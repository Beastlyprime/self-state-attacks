"""Minimal OpenClaw-faithful harness for self-state trace collection.

This package mirrors the trace-relevant core of OpenClaw (github.com/openclaw/openclaw)
so that file-system traces collected from this harness are distributionally comparable
to traces from real OpenClaw under the same workload.

Design fidelity: see SPEC.md §1-12. Out of scope: gateway, channels, plugins,
onboarding, doctor, UI, telemetry — any component that doesn't contribute to
file-system trace signatures.
"""

__version__ = "0.1.0"
