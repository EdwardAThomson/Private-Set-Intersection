# Multi-level mesh PSI cascade

`src/mesh_psi.{h,cpp}` ports the multi-level grid idea from the React frontend
(`reference_cpp_only/src/PSIVisualization.js`, `runMultiLevelPSI`) into the C++
protocol library as a coarse-to-fine cascade of tag-mode PSI runs.

## The problem

Flat grid PSI hashes every occupied fine cell into the protocol. On a large
map that is wasteful: most of the map is empty, and most occupied cells belong
to only one party. Every unmatched cell still costs a hash-to-group, a scalar
multiplication, a blinding, and 32 to 64 bytes on the wire.

## The cascade

`runCascadePSI(bobUnits, aliceUnits, config)` takes a `MeshConfig` with an
ordered list of cell sizes, coarse to fine (for example `{400.0, 50.0}`).
Validation requires the list to be strictly decreasing and each finer size to
exactly divide the coarser one, so every fine cell nests inside exactly one
coarse cell.

1. At the coarsest level, both parties map their units to occupied coarse
   cells (deduplicated) and run a full tag-mode PSI exchange over them.
2. At each finer level, both parties keep only the cells whose parent coarse
   cell survived the previous level's intersection, then run tag-mode PSI over
   that restricted set.
3. The finest level's intersection is the result, along with per-level stats:
   set sizes before and after restriction, per-phase timings, and wire bytes.

On clustered maps (the realistic game case) the coarse level prunes most fine
cells before any expensive work happens, so the fine-level PSI only runs over
the co-occupied portion of the map.

## Security rules

Two rules are load-bearing and encoded as comments in `mesh_psi.cpp`:

- **Fresh keys per level.** Every level is a completely independent protocol
  exchange: a fresh Bob private scalar and fresh Alice blinding scalars.
  Keys, tags, and blinded points are never reused across levels. Reusing
  Bob's scalar would let Alice correlate tags between levels and test
  coarse-level guesses against fine-level tags.
- **Domain separation per level.** The string hashed to the group is
  `L<cellSize>:<cx> <cy>` (for example `L400:3 5`), never the bare cell
  string, so a coarse cell element can never collide with a fine cell element
  or a raw `flooredPosition` string, even when the integer coordinates
  coincide.

One reveal is deliberate: the coarse level tells Alice which coarse cells both
parties occupy. That is the designed hierarchical reveal, the same trade-off
the OpenConflict paper's multi-level scheme makes, and it is exactly what
bounds the fine-level work. Callers who cannot accept coarse co-occupancy
leakage should run flat PSI (a single-level config) instead.

## Benchmark results

`tools/psi_mesh_bench.cpp` compares flat fine-grid PSI (cell 50) against the
two-level cascade (400 then 50) on clustered placements: 10 clusters on a
100,000 x 100,000 map, clusters 4 to 6 shared between the parties, fixed seed.
Machine timings will vary; representative run:

| mode    | units | total ms | wire bytes | fine matches |
|---------|-------|----------|------------|--------------|
| flat    |   500 |    93.71 |     63,774 |           13 |
| cascade |   500 |    75.61 |     49,932 |           13 |
| flat    |  2000 |   321.12 |    231,857 |          156 |
| cascade |  2000 |   191.56 |    139,736 |          156 |
| flat    |  5000 |   683.00 |    499,641 |          652 |
| cascade |  5000 |   370.01 |    268,483 |          652 |

At 5,000 units per side the cascade is ~1.8x faster and sends ~46% fewer
bytes: the coarse level (336 vs 318 cells) prunes the fine level from 3,847
and 3,754 occupied cells down to 1,601 and 1,764. The win grows with map
sparsity: the less the parties' clusters overlap, the more the coarse level
prunes.

## Tests

`tests/mesh_psi_test.cpp` checks that the cascade returns exactly the same
fine-level intersection as flat PSI (including empty-intersection and
full-overlap cases and a three-level config), that no raw position, bare cell
string, or level-prefixed element ever appears in any level's serialized
transcript, and that invalid configs (empty, non-positive, non-decreasing,
non-dividing) are rejected.
