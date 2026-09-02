# The CAP theorem, twenty years on

The CAP theorem, first conjectured by Eric Brewer in 2000 and formalized by Gilbert and Lynch in 2002, states that a distributed system can provide at most two of the three guarantees of Consistency, Availability, and Partition tolerance.

In the two decades since, the theorem has been refined in practice: partition tolerance is not optional in any real distributed system, so the real tradeoff is between C and A during a partition. Modern systems choose different points on this spectrum: DynamoDB is AP, Spanner is CP, Cassandra is tunable.

The PACELC extension by Abadi (2012) generalizes the tradeoff to the non-partition case: even without a partition, systems trade latency for consistency. This gives a fuller picture of the design space.
