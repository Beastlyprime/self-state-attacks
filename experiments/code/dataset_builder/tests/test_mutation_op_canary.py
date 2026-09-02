from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[4]
CODE_ROOT = PROJECT_ROOT / "experiments" / "code"
AGENT_ROOT = PROJECT_ROOT / "experiments" / "agent"
for path in (CODE_ROOT, AGENT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from dataset_builder.mutation_op_canary import _normalized_audit_fields  # noqa: E402


def test_normalized_audit_fields_preserve_write_syscall_contract() -> None:
    raw = (
        "type=SYSCALL msg=audit(1786500000.1:42): "
        "arch=c000003e syscall=1 success=yes exit=23 "
        "a0=3 a1=7fff0000 a2=17 a3=0 ppid=701 pid=702"
    )

    fields = _normalized_audit_fields(raw, "write")

    assert fields["syscall_number"] == 1
    assert fields["syscall_name"] == "write"
    assert fields["syscall_pid"] == 702
    assert fields["syscall_ppid"] == 701
    assert fields["syscall_fd"] == 3
    assert fields["syscall_requested_count"] == 23
    assert fields["syscall_exit"] == 23
    assert fields["syscall_byte_count"] == 23


def test_normalized_audit_fields_do_not_report_failed_bytes() -> None:
    raw = "type=SYSCALL syscall=1 exit=-13 a0=4 a1=0 a2=20 a3=0 ppid=8 pid=9"
