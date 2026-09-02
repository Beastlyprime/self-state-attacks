#!/usr/bin/env python3
"""P3 prevention op-replay matrix (mechanism x operation), threat-model-faithful.

Runs INSIDE a privileged container as root; installs each control, then performs
each attack operation AS THE AGENT PRINCIPAL (the owner of the workspace and its
files -- the paper's actual threat model: the compromised agent writes through its
own authorized OS permissions). Outcome per cell = real syscall errno + whether
the attacker's effect landed on the file.

No LLM, no agent runtime, no collector, no model request. Deterministic OS probe;
kernel errno semantics are architecture-independent.
"""
import os, sys, stat, errno, json, pwd, grp, subprocess, shutil, textwrap

BASE = "/work/p3_op_matrix_scratch"
AGENT_USER = "agentp"           # the agent principal == the attacker in this model
ORIG = b"original protected self-state\ncanonical line 2\n"

MECHANISMS = ["none", "dac_self", "dac_chown_root", "chattr_immutable", "apparmor", "landlock"]
OPERATIONS = ["open_write", "append", "truncate", "rename_over", "unlink", "chmod"]


def run(cmd, check=False):
    r = subprocess.run(cmd, text=True, capture_output=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> {r.returncode}: {r.stderr.strip()}")
    return r


def ensure_agent():
    try:
        return pwd.getpwnam(AGENT_USER)
    except KeyError:
        run(["useradd", "-M", "-s", "/usr/sbin/nologin", AGENT_USER], check=True)
        return pwd.getpwnam(AGENT_USER)


AGENT = ensure_agent()
AUID, AGID = AGENT.pw_uid, AGENT.pw_gid

# The op executed by the attacker (agent principal). Emitted as a tiny program
# run under the agent uid via setpriv, so the errno is the real kernel errno the
# agent process receives.
ATTACKER_OP = textwrap.dedent(r"""
import os, sys, stat, errno, json
target = sys.argv[1]; op = sys.argv[2]
d = os.path.dirname(target)
payload = b"CORRUPTED-BY-AGENT-PRINCIPAL\n"
res = {"op": op}
try:
    if op == "open_write":
        fd = os.open(target, os.O_WRONLY | os.O_TRUNC)
        os.write(fd, payload); os.close(fd); res["landed"] = True
    elif op == "append":
        fd = os.open(target, os.O_WRONLY | os.O_APPEND)
        os.write(fd, payload); os.close(fd); res["landed"] = True
    elif op == "truncate":
        fd = os.open(target, os.O_WRONLY)
        os.ftruncate(fd, 0); os.close(fd); res["landed"] = True
    elif op == "rename_over":
        tmp = os.path.join(d, ".agent_tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
        os.write(fd, payload); os.close(fd)
        os.replace(tmp, target); res["landed"] = True     # atomic rewrite via dir
    elif op == "unlink":
        os.unlink(target); res["landed"] = True
    elif op == "chmod":
        # try to (re)grant write on a read-only/owned-away file, then write
        os.chmod(target, 0o644)
        fd = os.open(target, os.O_WRONLY | os.O_TRUNC)
        os.write(fd, payload); os.close(fd); res["landed"] = True
    else:
        res["error"] = "unknown_op"
except OSError as e:
    res["landed"] = False; res["errno"] = e.errno; res["errno_name"] = errno.errorcode.get(e.errno)
except Exception as e:
    res["landed"] = False; res["exc"] = repr(e)
print(json.dumps(res))
""")


def write_attacker_prog():
    p = os.path.join(BASE, "_attacker_op.py")
    with open(p, "w") as f:
        f.write(ATTACKER_OP)
    os.chmod(p, 0o755)
    return p


ATTACKER_PROG = None
LANDLOCK_BIN = None


def build_landlock():
    """Compile the repo landlock launcher if source is mounted; else None."""
    src = "/repo/experiments/code/defenses/prevention/landlock_launcher.c"
    if not os.path.isfile(src):
        return None
    out = os.path.join(BASE, "landlock_launcher")
    r = run(["gcc", "-O2", "-o", out, src])
    if r.returncode != 0:
        return None
    return out


def fresh_scenario(tag):
    """Agent owns the workspace dir and the target file (real threat model)."""
    d = os.path.join(BASE, f"ws_{tag}")
    if os.path.isdir(d):
        run(["chattr", "-R", "-i", d])
        shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    target = os.path.join(d, "MEMORY.md")
    with open(target, "wb") as f:
        f.write(ORIG)
    # agent owns both dir and file
    os.chown(d, AUID, AGID)
    os.chown(target, AUID, AGID)
    os.chmod(d, 0o755)
    os.chmod(target, 0o644)
    return d, target


def apply_mechanism(mech, d, target):
    """Install the control as the privileged supervisor. Returns teardown info."""
    info = {"mechanism": mech}
    if mech == "none":
        pass
    elif mech == "dac_self":
        # agent removes the write bit from its OWN file (literal 'DAC write bit removed')
        os.chmod(target, 0o444)   # still agent-owned
    elif mech == "dac_chown_root":
        # P3's actual config: file taken away to root, read-only; DIR stays agent-owned
        os.chown(target, 0, AGID)
        os.chmod(target, 0o444)
    elif mech == "chattr_immutable":
        run(["chattr", "+i", "--", target], check=True)
        info["immutable_set"] = True
    elif mech == "apparmor":
        prof_name = "assa_p3_matrix"
        prof_path = os.path.join(BASE, "aa_profile")
        with open(prof_path, "w") as f:
            f.write(textwrap.dedent(f"""\
                #include <tunables/global>
                profile {prof_name} flags=(attach_disconnected,mediate_deleted) {{
                  #include <abstractions/base>
                  file,
                  network,
                  capability,
                  signal,
                  ptrace,
                  deny "{target}" wkl,
                }}
                """))
        r = run(["apparmor_parser", "-r", prof_path])
        info["apparmor_loaded"] = (r.returncode == 0)
        info["apparmor_err"] = r.stderr.strip()[:200]
        info["profile_name"] = prof_name
    elif mech == "landlock":
        info["landlock_bin"] = LANDLOCK_BIN
    return info


def clear_mechanism(mech, d, target, info):
    if mech == "chattr_immutable":
        run(["chattr", "-i", "--", target])
    elif mech == "apparmor" and info.get("apparmor_loaded"):
        run(["apparmor_parser", "-R", os.path.join(BASE, "aa_profile")])


def run_op(mech, op, d, target, info):
    cmd = ["setpriv", "--reuid", str(AUID), "--regid", str(AGID), "--clear-groups",
           "/usr/bin/python3", ATTACKER_PROG, target, op]
    if mech == "apparmor" and info.get("apparmor_loaded"):
        cmd = ["aa-exec", "-p", info["profile_name"], "--"] + cmd
    elif mech == "landlock" and LANDLOCK_BIN:
        # allow-write only /tmp; workspace not allowed
        cmd = [LANDLOCK_BIN, "--allow-write", "/tmp", "--"] + cmd
    r = run(cmd)
    out = {}
    try:
        out = json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {}
    except Exception:
        out = {"parse_fail": True, "stdout": r.stdout[-300:], "stderr": r.stderr[-300:]}
    return out, r


def snapshot(target):
    try:
        st = os.stat(target)
        with open(target, "rb") as f:
            content = f.read()
        return {"exists": True, "mode": oct(stat.S_IMODE(st.st_mode)),
                "uid": st.st_uid, "size": st.st_size,
                "content_changed": content != ORIG,
                "corrupted": b"CORRUPTED" in content}
    except FileNotFoundError:
        return {"exists": False}


def main():
    global ATTACKER_PROG, LANDLOCK_BIN
    os.makedirs(BASE, exist_ok=True)
    ATTACKER_PROG = write_attacker_prog()
    LANDLOCK_BIN = build_landlock()

    cells = []
    for mech in MECHANISMS:
        for op in OPERATIONS:
            tag = f"{mech}__{op}"
            d, target = fresh_scenario(tag)
            info = apply_mechanism(mech, d, target)
            pre = snapshot(target)
            opres, proc = run_op(mech, op, d, target, info)
            post = snapshot(target)
            clear_mechanism(mech, d, target, info)
            # bypass = attacker effect landed despite the control
            effect_landed = bool(opres.get("landed")) and (
                post.get("corrupted") or (op in ("unlink",) and not post.get("exists"))
                or (op == "truncate" and post.get("exists") and post.get("size") == 0))
            cells.append({
                "mechanism": mech, "operation": op,
                "op_errno": opres.get("errno_name"),
                "op_landed": bool(opres.get("landed")),
                "effect_landed": effect_landed,
                "post_exists": post.get("exists"),
                "post_corrupted": post.get("corrupted"),
                "post_size": post.get("size"),
                "install_info": {k: v for k, v in info.items()
                                 if k in ("apparmor_loaded", "immutable_set", "landlock_bin", "apparmor_err")},
                "raw_op": opres,
            })
            shutil.rmtree(d, ignore_errors=True)

    result = {
        "schema": "assa.p3.op_replay_matrix.v1",
        "discipline": {"no_agent_runtime": True, "no_collector": True,
                       "no_model_request": True, "real_errno": True,
                       "attacker_principal": "agent_owner (== workspace+file owner)"},
        "host": {"uname": os.uname().release, "machine": os.uname().machine,
                 "agent_uid": AUID, "in_container_root": os.geteuid() == 0,
                 "landlock_available": LANDLOCK_BIN is not None},
        "mechanisms": MECHANISMS, "operations": OPERATIONS,
        "cells": cells,
    }
    outp = "/work/p3_op_replay_matrix_result.json"
    with open(outp, "w") as f:
        json.dump(result, f, indent=2)
    print("WROTE", outp)
    # console matrix
    hdr = f"{'mechanism':<16}" + "".join(f"{o:>13}" for o in OPERATIONS)
    print(hdr)
    for mech in MECHANISMS:
        row = f"{mech:<16}"
        for op in OPERATIONS:
            c = next(x for x in cells if x["mechanism"] == mech and x["operation"] == op)
            if c["effect_landed"]:
                mark = "BYPASS"
            elif c["op_errno"]:
                mark = c["op_errno"]
            else:
                mark = "blocked?"
            row += f"{mark:>13}"
        print(row)


if __name__ == "__main__":
    main()
