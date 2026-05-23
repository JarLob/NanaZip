// Fuzz.Lvm.cpp - libFuzzer entry for the upstream-7-Zip LvmHandler that
// NanaZip ships but 7-Zip's official 7z.dll does not.
//
// LVM PV label lives in sector 1 (bytes 512..1023). Open2 gates:
//   [512+0  .. 512+7 ]  memcmp "LABELONE"
//   [512+8  .. 512+15]  sector_xl (LE u64) == 1
//   [512+16 .. 512+19]  CRC32 == LvmCrcCalc(buf+20, 492)
//                        (CRC-32/IEEE poly 0xEDB88320, init 0xf597a6cf, no final XOR)
//   [512+20 .. 512+23]  offsetToCont (LE u32) == 32
//   [512+24 .. 512+31]  memcmp "LVM2 001"
//
// PV header layout (all within CRC region, starting at label+32):
//   +32..63 : pv_id (32 bytes, free)
//   +64..71 : device_size_xl (LE u64)
//   +72..87 : data area disk_locn[0] {offset:8, size:8}
//             … more data disk_locns until (0,0) terminator
//   next 16 : metadata disk_locn[0] {offset:8, size:8}
//             handler does meta.Alloc(size) → null-deref if huge
//
// The custom mutator (a) fixes the five label-gate fields, (b) terminates
// the data disk_locn list immediately so the metadata disk_locn position is
// known, (c) caps metadata size to 64 KiB to prevent the unchecked OOM,
// and (d) recomputes the CRC.
#include "NanaZip.Core.Fuzz.h"
#include <cstring>
#include <cstdint>
#include <algorithm>

extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

// ---- Inline CRC-32 (same polynomial / table as 7-Zip's C/7zCrc.c) --------
static std::uint32_t s_Crc32Table[256];
static bool s_Crc32Inited = false;

static void InitCrc32Table()
{
    for (std::uint32_t i = 0; i < 256; ++i)
    {
        std::uint32_t c = i;
        for (int j = 0; j < 8; ++j)
            c = (c >> 1) ^ (c & 1 ? 0xEDB88320u : 0u);
        s_Crc32Table[i] = c;
    }
    s_Crc32Inited = true;
}

static std::uint32_t CrcUpdate(std::uint32_t crc,
                                const std::uint8_t* data, std::size_t len)
{
    if (!s_Crc32Inited) InitCrc32Table();
    for (std::size_t i = 0; i < len; ++i)
        crc = (crc >> 8) ^ s_Crc32Table[(crc ^ data[i]) & 0xFF];
    return crc;
}

static void WriteLE32(std::uint8_t* p, std::uint32_t v)
{
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

static void WriteLE64(std::uint8_t* p, std::uint64_t v)
{
    WriteLE32(p, static_cast<std::uint32_t>(v));
    WriteLE32(p + 4, static_cast<std::uint32_t>(v >> 32));
}

static std::uint64_t ReadLE64(const std::uint8_t* p)
{
    return static_cast<std::uint64_t>(p[0])
        | (static_cast<std::uint64_t>(p[1]) << 8)
        | (static_cast<std::uint64_t>(p[2]) << 16)
        | (static_cast<std::uint64_t>(p[3]) << 24)
        | (static_cast<std::uint64_t>(p[4]) << 32)
        | (static_cast<std::uint64_t>(p[5]) << 40)
        | (static_cast<std::uint64_t>(p[6]) << 48)
        | (static_cast<std::uint64_t>(p[7]) << 56);
}

static constexpr std::size_t   kSectorSize     = 512;
static constexpr std::size_t   kMinLvm         = kSectorSize * 2;  // 1024
static constexpr std::uint32_t kLvmCrcInit     = 0xf597a6cfu;
static constexpr std::uint64_t kMaxMetaSize    = 65536;  // 64 KiB

extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /*Seed*/)
{
    size_t NewSize = LLVMFuzzerMutate(Data, Size, MaxSize);

    if (NewSize < kMinLvm)
    {
        if (MaxSize < kMinLvm)
            return NewSize;
        std::memset(Data + NewSize, 0, kMinLvm - NewSize);
        NewSize = kMinLvm;
    }

    std::uint8_t* label = Data + kSectorSize;   // sector 1

    // --- 1. Fix structural gate fields ---

    // [+0]  "LABELONE"
    static const std::uint8_t kLabel[8] = {
        'L','A','B','E','L','O','N','E'
    };
    std::memcpy(label, kLabel, 8);

    // [+8]  sector_xl = 1  (LE u64)
    WriteLE64(label + 8, 1);

    // [+20] offsetToCont = 32  (LE u32)
    WriteLE32(label + 20, 32);

    // [+24] "LVM2 001"
    static const std::uint8_t kLvm2[8] = {
        'L','V','M','2',' ','0','0','1'
    };
    std::memcpy(label + 24, kLvm2, 8);

    // --- 2. Terminate data disk_locn list immediately (label+72) ---
    //     so metadata disk_locn is at the known position label+88.
    //     PV header: +32 id(32) +64 device_size(8) +72 data_disk_locn[0]
    std::memset(label + 72, 0, 16);   // {offset=0, size=0} → break

    // --- 3. Cap metadata disk_locn size (label+96) to kMaxMetaSize ---
    //     The handler does meta.Alloc(size) with no bounds check; without
    //     this cap, every mutated input triggers a multi-TB OOM crash.
    {
        std::uint64_t metaSize = ReadLE64(label + 96);
        if (metaSize > kMaxMetaSize)
            WriteLE64(label + 96, metaSize % (kMaxMetaSize + 1));
    }

    // --- 4. Recompute CRC over bytes [+20 .. +511] ---
    std::uint32_t crc = CrcUpdate(kLvmCrcInit, label + 20, kSectorSize - 20);
    WriteLE32(label + 16, crc);

    return NewSize;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    NanaZip::Fuzz::Core::RunFuzzCaseByName(L"LVM", data, size);
    return 0;
}
