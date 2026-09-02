from __future__ import annotations

import json
from pathlib import Path


def _quoted(value: str) -> str:
    return json.dumps(value)


def write_self_state_rules(path: Path, *, monitored_root: Path, runner_uid: int) -> None:
    root = str(monitored_root.resolve())
    rules = f"""- required_engine_version: 47

- macro: assa_target_user
  condition: user.uid = {runner_uid}

- macro: assa_state_fd_path
  condition: fd.name startswith {_quoted(root)}

- macro: assa_state_named_path
  condition: fs.path.name startswith {_quoted(root)}

- macro: assa_spawned_process
  condition: evt.type in (execve, execveat) and evt.dir=<

- rule: ASSA self state opened for write
  desc: A target runner opened a monitored self-state path for writing
  condition: evt.type in (open, openat, openat2, creat) and evt.is_open_write=true and assa_target_user and assa_state_fd_path
  output: "self-state open-write (user=%user.uid proc=%proc.name path=%fd.name evt=%evt.type)"
  priority: NOTICE
  tags: [assa, self_state, filesystem]

- rule: ASSA self state renamed
  desc: A target runner renamed a monitored self-state path
  condition: evt.type in (rename, renameat, renameat2) and assa_target_user and (fd.name startswith {_quoted(root)} or fs.path.target startswith {_quoted(root)})
  output: "self-state rename (user=%user.uid proc=%proc.name path=%fd.name target=%fs.path.target)"
  priority: NOTICE
  tags: [assa, self_state, filesystem]

- rule: ASSA self state removed
  desc: A target runner removed a monitored self-state path
  condition: evt.type in (unlink, unlinkat) and assa_target_user and assa_state_named_path
  output: "self-state remove (user=%user.uid proc=%proc.name path=%fd.name)"
  priority: NOTICE
  tags: [assa, self_state, filesystem]

- rule: ASSA self state chmod
  desc: A target runner changed mode on a monitored self-state path
  condition: evt.type in (chmod, fchmod, fchmodat, fchmodat2) and assa_target_user and (assa_state_fd_path or assa_state_named_path)
  output: "self-state chmod (user=%user.uid proc=%proc.name path=%fd.name)"
  priority: NOTICE
  tags: [assa, self_state, filesystem]

- rule: ASSA executable launched from self state
  desc: A target runner executed a file from the monitored self-state tree
  condition: assa_spawned_process and assa_target_user and proc.exepath startswith {_quoted(root)}
  output: "self-state exec (user=%user.uid proc=%proc.name exe=%proc.exepath cmd=%proc.cmdline)"
  priority: NOTICE
  tags: [assa, self_state, process]

- rule: ASSA target outbound connect
  desc: A target runner initiated an outbound network connection
  condition: evt.type=connect and evt.dir=< and assa_target_user and fd.typechar in (4, 6)
  output: "target outbound connect (user=%user.uid proc=%proc.name destination=%fd.rip:%fd.rport)"
  priority: NOTICE
  tags: [assa, self_state, network]
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rules, encoding="utf-8")
