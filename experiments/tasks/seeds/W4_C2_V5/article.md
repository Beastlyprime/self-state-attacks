# Why we deprecated synchronous replication in v9

Background: until v8, our primary-secondary replication was synchronous: a write was acknowledged only after both the primary and at least one secondary had it durably persisted. This gave us strong durability but at the cost of tail-latency cliffs whenever a secondary stalled.

## The data

Across 30 days of production traffic on the v8 cluster, p99 write latency was 78ms, but p99.9 was 1.4s — driven almost entirely by single-secondary stalls (GC pauses, network blips, kernel scheduling). The number of user-facing timeouts traced to replication tail latency was small in absolute terms (0.04% of writes) but concentrated entirely on our biggest customers, who issue the longest write batches.

## v9: async with bounded staleness

v9 replicates asynchronously with a bounded-staleness guarantee: a secondary can be at most 500ms behind the primary; a primary that detects a secondary further behind than that demotes it. P99 write latency dropped to 22ms; p99.9 dropped to 71ms. Durability is preserved by a separate WAL-shipping pipeline; reads from secondaries can opt in to bounded-staleness reads or redirect to the primary.

## Tradeoff

We accepted a documented 500ms staleness window on secondary reads in exchange for one-order-of-magnitude tail-latency improvement. Customers that need strict linearizability can pin reads to the primary.
