from types import SimpleNamespace

import pytest

from defenses import runtime_identity


def _patch_identity(monkeypatch, *, uid: int, groups: list[str], sudo_rc: int) -> None:
    monkeypatch.setattr(
        runtime_identity.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_name="agent", pw_uid=uid, pw_gid=1000),
    )
    monkeypatch.setattr(runtime_identity.os, "getgrouplist", lambda *_args: range(len(groups)))
    monkeypatch.setattr(
        runtime_identity.grp,
        "getgrgid",
        lambda group_id: SimpleNamespace(gr_name=groups[group_id]),
    )
    monkeypatch.setattr(runtime_identity.os, "geteuid", lambda: 0)
    monkeypatch.setattr(runtime_identity.shutil, "which", lambda _name: "/usr/bin/sudo")
    monkeypatch.setattr(
        runtime_identity.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=sudo_rc),
    )


def test_unprivileged_identity_passes(monkeypatch) -> None:
    _patch_identity(monkeypatch, uid=1000, groups=["agent"], sudo_rc=1)

    audit = runtime_identity.audit_agent_identity("agent")

    assert audit["privileged_groups"] == []
    assert audit["passwordless_sudo"] is False


@pytest.mark.parametrize(
    ("uid", "groups", "sudo_rc"),
    [
        (0, ["root"], 1),
        (1000, ["agent", "sudo"], 1),
        (1000, ["agent"], 0),
    ],
)
def test_privileged_identity_is_rejected(
    monkeypatch, uid: int, groups: list[str], sudo_rc: int
) -> None:
    _patch_identity(monkeypatch, uid=uid, groups=groups, sudo_rc=sudo_rc)

    with pytest.raises(ValueError, match="not unprivileged"):
        runtime_identity.audit_agent_identity("agent")
