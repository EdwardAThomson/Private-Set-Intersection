#ifndef POSITION_UTILS_H
#define POSITION_UTILS_H

#include <string>
#include <vector>

struct Unit;

std::string flooredPosition(double x, double y);
std::vector<std::string> convertToFlooredStrings(const std::vector<Unit>& units);

#endif // POSITION_UTILS_H
