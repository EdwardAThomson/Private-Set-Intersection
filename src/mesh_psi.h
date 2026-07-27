#ifndef MESH_PSI_H
#define MESH_PSI_H

// Multi-level mesh PSI: a coarse-to-fine cascade of tag-mode PSI runs over
// grid cells, ported from the multi-level grid idea in the React frontend
// (reference_cpp_only/src/PSIVisualization.js, runMultiLevelPSI).
//
// Instead of running one PSI over every occupied fine cell of a large map,
// the cascade first intersects the parties' occupied COARSE cells, then at
// each finer level restricts both inputs to cells whose parent coarse cell
// survived the previous level. On clustered maps this bounds the fine-level
// work by the coarse co-occupancy instead of the whole map.
//
// SECURITY MODEL (see also docs/mesh_cascade.md):
//  * Every level is a completely independent protocol exchange: a fresh Bob
//    private scalar and fresh Alice blinding scalars per level. Keys, tags,
//    and blinded points are never reused across levels.
//  * Levels are domain-separated: the string that is hashed to the group is
//    "L<cellSize>:<cx> <cy>", so a coarse cell string can never collide with
//    a fine cell string even if the integer coordinates coincide.
//  * The coarse level intentionally reveals coarse-cell co-occupancy. That is
//    the designed hierarchical reveal, the same trade-off the OpenConflict
//    paper's multi-level scheme makes, and it is exactly what bounds the
//    fine-level work.

#include <cstddef>
#include <string>
#include <vector>

#include "psi_types.h"

struct MeshConfig {
    // Cell sizes ordered coarse to fine, e.g. {400.0, 50.0}. Each finer size
    // must exactly divide the coarser one so that every fine cell nests inside
    // exactly one coarse cell.
    std::vector<double> cellSizes;
};

// Throws std::invalid_argument if the config is empty, contains a
// non-positive size, is not strictly decreasing, or a finer size does not
// divide the next coarser size.
void validateMeshConfig(const MeshConfig& config);

// Maps a raw position to its cell string "<cx> <cy>" at the given cell size,
// using the same floor convention as flooredPosition (position_utils.h):
// cx = floor(x / cellSize), cy = floor(y / cellSize).
std::string cellForPosition(double x, double y, double cellSize);

// Given a fine cell string produced by cellForPosition at fineCellSize,
// returns the coarse cell string it is contained in at coarseCellSize.
// Requires fineCellSize to divide coarseCellSize.
std::string parentCell(const std::string& fineCell,
                       double fineCellSize,
                       double coarseCellSize);

// Domain separation: the element actually hashed into the protocol at a
// level, "L<cellSize>:<cell>". Never feed bare cell strings to the protocol.
std::string levelDomainElement(const std::string& cell, double cellSize);

struct MeshLevelStats {
    double cellSize{0.0};

    // Occupied cells at this level before / after restriction to the previous
    // level's surviving coarse cells (in == total at the coarsest level).
    std::size_t bobCellsTotal{0};
    std::size_t aliceCellsTotal{0};
    std::size_t bobCellsIn{0};
    std::size_t aliceCellsIn{0};
    std::size_t intersectionSize{0};

    // Per-phase timings for this level's exchange, in milliseconds.
    double bobSetupMs{0.0};
    double aliceSetupMs{0.0};
    double bobResponseMs{0.0};
    double aliceFinalizeMs{0.0};

    // Total serialized bytes of the three wire messages of this level.
    std::size_t wireBytes{0};

    // Concatenation of the three serialized wire messages, kept so tests can
    // scan the transcript for plaintext leakage.
    std::string transcript;

    double totalMs() const {
        return bobSetupMs + aliceSetupMs + bobResponseMs + aliceFinalizeMs;
    }
};

struct CascadeResult {
    // Intersection at the finest level, as bare cell strings "<cx> <cy>"
    // (level prefix stripped), sorted ascending.
    std::vector<std::string> intersection;
    std::vector<MeshLevelStats> levels;

    double totalMs() const;
    std::size_t totalWireBytes() const;
};

// Runs the full coarse-to-fine cascade described above. A single-level config
// degenerates to flat tag-mode PSI over that level's cells.
CascadeResult runCascadePSI(const std::vector<Unit>& bobUnits,
                            const std::vector<Unit>& aliceUnits,
                            const MeshConfig& config);

#endif // MESH_PSI_H
