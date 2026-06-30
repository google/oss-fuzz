#pragma once
#include <array>
#include <string_view>

#define ERASE_MAX_GEOMETRY 100000000000ULL
#define ERASE_MIN_GEOMETRY 1000000ULL

static constexpr auto highSpeedMMC =
    std::to_array<std::string_view>({ "TestPart" });
