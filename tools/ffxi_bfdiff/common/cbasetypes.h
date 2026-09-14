// Verbatim copy of lines 40-47 of LandSandBoat's src/common/cbasetypes.h
// (https://github.com/LandSandBoat/server), which is licensed under the GNU
// General Public License v3.0; this file is distributed under GPL-3.0 as well
// (see LICENSE and NOTICE at the repository root).
//
// Minimal stand-in for the real header, carrying ONLY the integer typedefs
// blowfish.cpp/md52.cpp need; the real one drags in fmt/ and tracy/ which are
// irrelevant to the cipher and would only be a build problem. blowfish.cpp and
// blowfish.h themselves are compiled UNMODIFIED -- that is the point of this
// harness.
#pragma once
#include <cstdint>
#include <cstring>

using int8  = std::int8_t;
using int16 = std::int16_t;
using int32 = std::int32_t;

using uint8  = std::uint8_t;
using uint16 = std::uint16_t;
using uint32 = std::uint32_t;
