/*
 * PROJECT:    NanaZip
 * FILE:       Fuzz.Lvm.cpp
 * PURPOSE:    libFuzzer harness for the upstream-7-Zip LvmHandler that
 *             NanaZip ships but 7-Zip's official 7z.dll does not
 *
 * LICENSE:    The MIT License
 *
 * LVM PV label lives in sector 1 (bytes 512..1023). Open2 gates:
 *   [512+0  .. 512+7 ]  memcmp "LABELONE"
 *   [512+8  .. 512+15]  sector_xl (LE u64) == 1
 *   [512+16 .. 512+19]  CRC32 == LvmCrcCalc(buf+20, 492)
 *                        (CRC-32/IEEE poly 0xEDB88320, init 0xf597a6cf,
 *                        no final XOR)
 *   [512+20 .. 512+23]  offsetToCont (LE u32) == 32
 *   [512+24 .. 512+31]  memcmp "LVM2 001"
 *
 * PV header layout (all within CRC region, starting at label+32):
 *   +32..63 : pv_id (32 bytes, free)
 *   +64..71 : device_size_xl (LE u64)
 *   +72..87 : data area disk_locn[0] {offset:8, size:8}
 *             ... more data disk_locns until (0,0) terminator
 *   next 16 : metadata disk_locn[0] {offset:8, size:8}
 *             handler does meta.Alloc(size) -> null-deref if huge
 *
 * The custom mutator (a) fixes the five label-gate fields, (b) terminates
 * the data disk_locn list immediately so the metadata disk_locn position is
 * known, (c) caps metadata size to 64 KiB to prevent the unchecked OOM,
 * and (d) recomputes the CRC.
 */

#include "NanaZip.Core.Fuzz.h"
#include <cstring>
#include <cstdint>
#include <algorithm>

extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

// ---- Inline CRC-32 (same polynomial / table as 7-Zip's C/7zCrc.c) --------
static std::uint32_t Crc32Table[256];
static bool Crc32Initialized = false;

static void InitCrc32Table()
{
    for (std::uint32_t I = 0; I < 256; ++I)
    {
        std::uint32_t C = I;
        for (int J = 0; J < 8; ++J)
            C = (C >> 1) ^ (C & 1 ? 0xEDB88320u : 0u);
        Crc32Table[I] = C;
    }
    Crc32Initialized = true;
}

static std::uint32_t CrcUpdate(
    std::uint32_t Crc,
    const std::uint8_t* Data,
    std::size_t Length)
{
    if (!Crc32Initialized) InitCrc32Table();
    for (std::size_t I = 0; I < Length; ++I)
        Crc = (Crc >> 8) ^ Crc32Table[(Crc ^ Data[I]) & 0xFF];
    return Crc;
}

static void WriteLE32(std::uint8_t* P, std::uint32_t V)
{
    P[0] = static_cast<std::uint8_t>(V);
    P[1] = static_cast<std::uint8_t>(V >> 8);
    P[2] = static_cast<std::uint8_t>(V >> 16);
    P[3] = static_cast<std::uint8_t>(V >> 24);
}

static void WriteLE64(std::uint8_t* P, std::uint64_t V)
{
    WriteLE32(P, static_cast<std::uint32_t>(V));
    WriteLE32(P + 4, static_cast<std::uint32_t>(V >> 32));
}

static std::uint64_t ReadLE64(const std::uint8_t* P)
{
    return static_cast<std::uint64_t>(P[0])
        | (static_cast<std::uint64_t>(P[1]) << 8)
        | (static_cast<std::uint64_t>(P[2]) << 16)
        | (static_cast<std::uint64_t>(P[3]) << 24)
        | (static_cast<std::uint64_t>(P[4]) << 32)
        | (static_cast<std::uint64_t>(P[5]) << 40)
        | (static_cast<std::uint64_t>(P[6]) << 48)
        | (static_cast<std::uint64_t>(P[7]) << 56);
}

static constexpr std::size_t   SectorSize     = 512;
static constexpr std::size_t   MinLvm         = SectorSize * 2;  // 1024
static constexpr std::uint32_t LvmCrcInit     = 0xf597a6cfu;
static constexpr std::uint64_t MaxMetaSize    = 65536;  // 64 KiB

extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /*Seed*/)
{
    size_t NewSize = LLVMFuzzerMutate(Data, Size, MaxSize);

    if (NewSize < MinLvm)
    {
        if (MaxSize < MinLvm)
            return NewSize;
        std::memset(Data + NewSize, 0, MinLvm - NewSize);
        NewSize = MinLvm;
    }

    std::uint8_t* Label = Data + SectorSize;   // sector 1

    // --- 1. Fix structural gate fields ---

    // [+0]  "LABELONE"
    static const std::uint8_t LabelMagic[8] = {
        'L','A','B','E','L','O','N','E'
    };
    std::memcpy(Label, LabelMagic, 8);

    // [+8]  sector_xl = 1  (LE u64)
    WriteLE64(Label + 8, 1);

    // [+20] offsetToCont = 32  (LE u32)
    WriteLE32(Label + 20, 32);

    // [+24] "LVM2 001"
    static const std::uint8_t Lvm2Magic[8] = {
        'L','V','M','2',' ','0','0','1'
    };
    std::memcpy(Label + 24, Lvm2Magic, 8);

    // --- 2. Terminate data disk_locn list immediately (label+72) ---
    //     so metadata disk_locn is at the known position label+88.
    //     PV header: +32 id(32) +64 device_size(8) +72 data_disk_locn[0]
    std::memset(Label + 72, 0, 16);   // {offset=0, size=0} -> break

    // --- 3. Cap metadata disk_locn size (label+96) to MaxMetaSize ---
    //     The handler does meta.Alloc(size) with no bounds check; without
    //     this cap, every mutated input triggers a multi-TB OOM crash.
    {
        std::uint64_t MetaSize = ReadLE64(Label + 96);
        if (MetaSize > MaxMetaSize)
            WriteLE64(Label + 96, MetaSize % (MaxMetaSize + 1));
    }

    // --- 4. Recompute CRC over bytes [+20 .. +511] ---
    std::uint32_t Crc = CrcUpdate(LvmCrcInit, Label + 20, SectorSize - 20);
    WriteLE32(Label + 16, Crc);

    return NewSize;
}

extern "C" int LLVMFuzzerTestOneInput(
    const std::uint8_t* Data,
    std::size_t Size)
{
    NanaZip::Fuzz::Core::RunFuzzCaseByName(L"LVM", Data, Size);
    return 0;
}