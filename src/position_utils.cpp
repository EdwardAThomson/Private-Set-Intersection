#include "position_utils.h"

#include <cmath>

#include "psi_types.h"

std::string flooredPosition(double x, double y) {
    return std::to_string(static_cast<long long>(std::floor(x))) + " " +
           std::to_string(static_cast<long long>(std::floor(y)));
}

std::vector<std::string> convertToFlooredStrings(const std::vector<Unit>& units) {
    std::vector<std::string> result;
    result.reserve(units.size());
    for (const auto& unit : units) {
        result.push_back(flooredPosition(unit.x, unit.y));
    }
    return result;
}
