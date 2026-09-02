# Limitations and scope

Read this before building on the benchmark. These are boundaries of what the
evidence supports, not caveats added for form.

## One live backend

The benchmark has a single live reference backend. The state schema is logical and
rebinding to another file-backed agent is demonstrated, but that demonstrates
rebinding, not cross-system generality. Nothing here establishes that the results
transfer to agents with different persistence architectures — database-backed
memory, remote state, or state that is never materialized as files.

## The workloads are contrastive, not representative

W1–W4 exercise different regimes of legitimate self-state activity. They are not a
sample of a deployment population, and no claim about "typical" agent behaviour
follows from them. With five held-out scenarios per profile, profile-level
false-positive rates are descriptive only.

## The attack corpus is uneven by construction

Model-driven attack evidence concentrates in M1/M2 persistent writes. The
remaining metadata and namespace attacks are instantiated directly under the
compromised agent principal. Both are attack executions for evaluating
post-compromise OS defenses, but the distinction limits claims about model
inducibility, not inclusion.

The write-specific methods (B1, B2, and the three supervised models) are defined on
23 of the 55 attacks — those with a resolvable self-state write and valid size
features. Their conditional rates do not erase the uncovered operation classes, and
the other 32 attacks are reported as outside the method definition rather than as
misses.

**Executable skills are not covered.** The catalog binds instruction, memory,
configuration, automation and capability-binding roles. Agent state that is itself
executable — installed skill scripts — is outside it.

## Prevention is a bounded probe

Six operations against five configurations on one durable-memory object. It is not
a proof over all Linux authority paths or policy designs. A configuration that
blocks all six here may still leave paths this replay does not exercise.

## Detection results are conditional on the substrate

Each baseline sees only the evidence its native substrate carries, and analyzer
failures are reported as data-insufficient rather than as negative predictions.
For the provenance-graph arm this is substantial: 14 of 55 attack graphs and 13 of
60 natural graphs are unscored, and 26 of those 27 are upstream analyzer aborts.
UNICORN's numbers are therefore conditional on 41 evaluable attack graphs, not 55.

## Recovery covers three specific things

The repository-isolation matrix, eight protected attacks, and a descriptive
236-session cost analysis. It does not cover arbitrary recovery points, and it does
not measure a multi-session distinct-path curve. The per-session statistics do not
determine loss over longer backup intervals, because repeated changes to the same
object collapse.

Selecting a trustworthy recovery point remains unresolved. Recovery here assumes a
trusted trigger; identifying the onset of corruption inherits the attack-specificity
problem that detection faces.

## What the headline result does and does not say

The evaluation shows a defense-design limitation, not an observability failure. The
OS can enforce a barrier, name the object, attribute the writer, and restore a
protected copy. What no evaluated mechanism does is combine broad operation coverage
with selective treatment of legitimate self-update — because for self-state, the
principal, object and operation are frequently identical for an attack and an
authorized change.

That is a statement about the mechanisms evaluated here, on this substrate. It is
not a claim that no OS mechanism could do better, and it is explicitly the
motivation for designing ones that do.

## Superseded material

`data/superseded/` contains earlier population cuts retained for provenance. They
are not paper estimates. In particular the clean-40 comparison is leaky — half of
that set overlaps the training freeze — and must not be used to infer the direction
of false-positive bias.
