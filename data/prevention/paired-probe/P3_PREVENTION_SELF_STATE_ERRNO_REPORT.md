# P3 Prevention Self-State Errno Measurement

Generated: `2026-08-21T21:59:16.400112+00:00`

Scope: DAC chmod removal, chattr +i immutable, AppArmor, and Landlock only. IMA is intentionally retained as a separate mechanism and is not included in the collateral aggregate.

The probe performs two real writes as the agent user against the same self-state file: a legal marker update and an ordinary legitimate self-state update. Both outcomes are taken from the writer process errno, not inferred from post-state.

| Mechanism | Marker errno | Marker blocked | Legitimate errno | Collateral blocked | Admissible |
|---|---:|---|---:|---|---|
| dac | EACCES (13) | True | EACCES (13) | True | True |
| chattr_immutable | EPERM (1) | True | EPERM (1) | True | True |
| apparmor | EACCES (13) | True | EACCES (13) | True | True |
| landlock | EACCES (13) | True | EACCES (13) | True | True |

Failure discipline: if setup, policy activation, real errno capture, or teardown cannot be proven, the mechanism is marked inadmissible rather than repaired by interpretation.
