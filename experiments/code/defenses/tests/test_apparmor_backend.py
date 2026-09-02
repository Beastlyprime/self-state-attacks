import os
import pwd
from pathlib import Path
from types import SimpleNamespace

import defenses.prevention.backends as prevention_backends
from defenses.prevention.backends import AgentIdentity, AppArmorBackend, BackendContext


def test_directory_glob_is_quoted_as_one_apparmor_path(
    tmp_path: Path, monkeypatch
) -> None:
    directory = tmp_path / "agent" / "workspace" / "memory"
    directory.mkdir(parents=True)
    identity_entry = pwd.getpwuid(os.geteuid())
    context = BackendContext(
        agent_dir=tmp_path / "agent",
        identity=AgentIdentity(
            identity_entry.pw_name,
            identity_entry.pw_uid,
            identity_entry.pw_gid,
        ),
        level=5,
        run_id="test",
        artifact_dir=tmp_path / "artifacts",
    )
    backend = AppArmorBackend()
    original_exists = Path.exists
    monkeypatch.setattr(
        Path,
        "exists",
        lambda path: False
        if path == Path("/sys/kernel/security/apparmor/profiles")
        else original_exists(path),
    )
    monkeypatch.setattr(backend, "preflight", lambda _context: {"ok": True})
    monkeypatch.setattr(
        prevention_backends,
        "_expand_existing",
        lambda _agent_dir, _relpaths: [directory],
    )
    monkeypatch.setattr(
        prevention_backends,
        "_run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    result = backend.setup(context)
    profile = Path(result["profile_path"]).read_text(encoding="utf-8")
    assert f'"{directory}/**" wkl,' in profile
    assert f'"{directory}"/**' not in profile
