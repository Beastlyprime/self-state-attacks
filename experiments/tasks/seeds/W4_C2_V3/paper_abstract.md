# Abstract

We present a method for detecting self-state corruption in long-running language-model agents. Our approach monitors file-level I/O signatures against per-workload baselines and flags divergences that are characteristic of memory-file overwrite attacks. We evaluate on four workload profiles totaling 80 tasks and achieve 94% detection rate at a 2% false-positive rate. The approach is workload-aware: a coding workload has a different baseline than a knowledge-retrieval workload, and using the wrong baseline causes the detector to fail.

# Keywords

AI safety, agent security, workload fingerprinting, anomaly detection
