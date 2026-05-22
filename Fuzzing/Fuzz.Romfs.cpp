// Fuzz.Romfs.cpp - libFuzzer entry for the ROMFS handler.
//
// ROMFS binary format (Linux romfs):
//   bytes [0..7]:  magic "-rom1fs-"
//   bytes [8..11]: FullSize (BE u32) — total filesystem size
//   bytes [12..15]: Checksum (BE u32) — not verified by NanaZip
//   bytes [16..]: volume name (null-terminated, 16-byte aligned) then file headers
//
// Each file header has a Size field (BE u32) that flows into
// std::vector<uint8_t> Buffer(Size) during Extract — unchecked, causing OOM.
// The custom mutator fixes the magic and caps FullSize to input length.
#include "NanaZip.Codecs.Fuzz.h"
#include <cstring>
#include <cstdint>

extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

static constexpr size_t kRomfsMinSize = 16;  // magic(8) + fullsize(4) + checksum(4)

static void WriteBE32(std::uint8_t* p, std::uint32_t v)
{
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

static std::uint32_t ReadBE32(const std::uint8_t* p)
{
    return (static_cast<std::uint32_t>(p[0]) << 24)
         | (static_cast<std::uint32_t>(p[1]) << 16)
         | (static_cast<std::uint32_t>(p[2]) << 8)
         |  static_cast<std::uint32_t>(p[3]);
}

extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /*Seed*/)
{
    size_t NewSize = LLVMFuzzerMutate(Data, Size, MaxSize);

    if (NewSize < kRomfsMinSize)
    {
        if (MaxSize < kRomfsMinSize)
            return NewSize;
        std::memset(Data + NewSize, 0, kRomfsMinSize - NewSize);
        NewSize = kRomfsMinSize;
    }

    // Fix magic so every iteration reaches the parser
    static const std::uint8_t kMagic[8] = {'-','r','o','m','1','f','s','-'};
    std::memcpy(Data, kMagic, 8);

    // Cap FullSize (BE u32 at offset 8) to input length.
    // The parser uses FullSize to bound filename reads and as the overall
    // filesystem size. If FullSize > input length, ReadFileStream fails
    // on every file header read, wasting the iteration.
    std::uint32_t fullSize = ReadBE32(Data + 8);
    if (fullSize > static_cast<std::uint32_t>(NewSize))
    {
        fullSize = static_cast<std::uint32_t>(NewSize);
        WriteBE32(Data + 8, fullSize);
    }

    return NewSize;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    // Skip Extract: Romfs Extract is trivial (ReadFileStream+Write), but
    // 10,000 entries × per-file Buffer(Size) allocations accumulate ASan
    // shadow memory faster than it's reclaimed, causing OOM in non-fork mode.
    // All interesting parser logic (linked-list traversal, filename parsing,
    // type dispatch, directory recursion) runs during Open/GetProperty.
    NanaZip::Fuzz::RunFuzzCaseNoExtract(3, data, size);
    return 0;
}
