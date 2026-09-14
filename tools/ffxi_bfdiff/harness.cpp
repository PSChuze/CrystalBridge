// Differential oracle for a port of LandSandBoat's world-packet cipher.
//
// Links LandSandBoat's REAL blowfish.cpp and md52.cpp (unmodified) and exposes
// the exact composition map_networking.cpp performs, so a port can be compared
// against the C++ it claims to reproduce -- rather than against itself, which
// is all an encipher/decipher round trip proves.
//
// LandSandBoat (https://github.com/LandSandBoat/server) is licensed under the
// GNU General Public License v3.0, and so is this file (see LICENSE and NOTICE
// at the repository root). The LandSandBoat sources are NOT in this
// repository. To build, copy these four files from a LandSandBoat checkout at
// the revision the pinned image was built from into ./common/ next to the
// cbasetypes.h stand-in that is already there:
//
//   src/common/blowfish.h   src/common/blowfish.cpp
//   src/common/md52.h       src/common/md52.cpp
//
// then, from this directory:
//
//   g++ -std=c++17 -O2 -I. harness.cpp common/blowfish.cpp common/md52.cpp -o harness
//
//   schedule <key40hex>            -> P[18] and S[1024] as hex, from the real
//                                     initBlowfish + blowfish_init
//   decipher <key40hex> <datahex>  -> map_decipher_packet's transform
//   encipher <key40hex> <datahex>  -> finalizePacket's transform
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "common/blowfish.h"

void md5(uint8* text, uint8* hash, int32 size);

static std::vector<uint8> unhex(const char* s)
{
    std::vector<uint8> out;
    for (size_t i = 0; s[i] && s[i + 1]; i += 2)
    {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        out.push_back(static_cast<uint8>((nib(s[i]) << 4) | nib(s[i + 1])));
    }
    return out;
}

static void puthex(const uint8* p, size_t n)
{
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
    printf("\n");
}

// MapSession::initBlowfish, src/map/map_session.cpp -- md5 the 20-byte key,
// truncate the hash at its first zero byte, schedule on that.
static void init_session(const std::vector<uint8>& key20, uint32* P, uint32* S)
{
    uint32 key[5] = {};
    memcpy(key, key20.data(), 20);

    uint8 hash[16] = {};
    md5(reinterpret_cast<uint8*>(key), hash, 20);
    for (uint32 i = 0; i < 16; ++i)
    {
        if (hash[i] == 0)
        {
            memset(hash + i, 0, 16 - i);
            break;
        }
    }
    blowfish_init(reinterpret_cast<int8*>(hash), 16, P, S);
}

int main(int argc, char** argv)
{
    if (argc < 3) { fprintf(stderr, "usage: harness <cmd> <key40hex> [datahex]\n"); return 2; }
    const std::string cmd = argv[1];
    const auto key = unhex(argv[2]);
    if (key.size() != 20) { fprintf(stderr, "key must be 20 bytes\n"); return 2; }

    static uint32 P[18];
    static uint32 S[4][256];
    init_session(key, P, S[0]);

    if (cmd == "schedule")
    {
        puthex(reinterpret_cast<uint8*>(P), sizeof(P));
        puthex(reinterpret_cast<uint8*>(S), sizeof(S));
        return 0;
    }

    if (argc < 4) { fprintf(stderr, "need datahex\n"); return 2; }
    auto buf = unhex(argv[3]);
    const size_t buffsize = buf.size();
    if (buffsize <= 0x1C) { fprintf(stderr, "datagram too short\n"); return 2; }

    // map_decipher_packet / finalizePacket both cipher from byte 28 for an even
    // count of 4-byte words.
    uint16 tmp = static_cast<uint16>((buffsize - 0x1C) / 4);
    tmp -= tmp % 2;

    if (cmd == "decipher")
    {
        blowfish_decipher_blocks(reinterpret_cast<uint32*>(buf.data()) + 7, tmp / 2, P, S[0]);
    }
    else if (cmd == "encipher")
    {
        blowfish_encipher_blocks(reinterpret_cast<uint32*>(buf.data()) + 7, tmp / 2, P, S[0]);
    }
    else
    {
        fprintf(stderr, "unknown cmd\n");
        return 2;
    }
    puthex(buf.data(), buf.size());
    return 0;
}
