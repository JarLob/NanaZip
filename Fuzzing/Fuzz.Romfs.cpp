/*
 * PROJECT:    NanaZip
 * FILE:       Fuzz.Romfs.cpp
 * PURPOSE:    libFuzzer harness for the ROMFS handler
 *
 * LICENSE:    The MIT License
 *
 * ROMFS binary format (Linux romfs):
 *   bytes [0..7]:  magic "-rom1fs-"
 *   bytes [8..11]: FullSize (BE u32) - total filesystem size
 *   bytes [12..15]: Checksum (BE u32) - not verified by NanaZip
 *   bytes [16..]: volume name (null-terminated, 16-byte aligned) then file headers
 *
 * Each file header has a Size field (BE u32) that flows into
 * std::vector<uint8_t> Buffer(Size) during Extract - unchecked, causing OOM.
 * The custom mutator fixes the magic and caps FullSize to input length.
 */

#include "NanaZip.Codecs.Fuzz.h"
#include <cstring>
#include <cstdint>

extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

static constexpr std::size_t RomfsMinSize = 16;  // magic(8) + fullsize(4) + checksum(4)

static void WriteBE32(std::uint8_t* P, std::uint32_t V)
{
    P[0] = static_cast<std::uint8_t>(V >> 24);
    P[1] = static_cast<std::uint8_t>(V >> 16);
    P[2] = static_cast<std::uint8_t>(V >> 8);
    P[3] = static_cast<std::uint8_t>(V);
}

static std::uint32_t ReadBE32(const std::uint8_t* P)
{
    return (static_cast<std::uint32_t>(P[0]) << 24)
         | (static_cast<std::uint32_t>(P[1]) << 16)
         | (static_cast<std::uint32_t>(P[2]) << 8)
         |  static_cast<std::uint32_t>(P[3]);
}

extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /*Seed*/)
{
    size_t NewSize = LLVMFuzzerMutate(Data, Size, MaxSize);

    if (NewSize < RomfsMinSize)
    {
        if (MaxSize < RomfsMinSize)
            return NewSize;
        std::memset(Data + NewSize, 0, RomfsMinSize - NewSize);
        NewSize = RomfsMinSize;
    }

    // Fix magic so every iteration reaches the parser
    static const std::uint8_t Magic[8] = {'-','r','o','m','1','f','s','-'};
    std::memcpy(Data, Magic, 8);

    // Cap FullSize (BE u32 at offset 8) to input length.
    // The parser uses FullSize to bound filename reads and as the overall
    // filesystem size. If FullSize > input length, ReadFileStream fails
    // on every file header read, wasting the iteration.
    std::uint32_t FullSize = ReadBE32(Data + 8);
    if (FullSize > static_cast<std::uint32_t>(NewSize))
    {
        FullSize = static_cast<std::uint32_t>(NewSize);
        WriteBE32(Data + 8, FullSize);
    }

    return NewSize;
}

extern "C" int LLVMFuzzerTestOneInput(
    const std::uint8_t* Data,
    std::size_t Size)
{
    // Like RunFuzzCaseNoExtract but WITHOUT querying SevenZipArchiveSymbolicLink.
    // The Romfs handler allocates std::string(Information.Size, '\0') for symlinks
    // where Size is an uncapped attacker-controlled BE u32 - every symlink entry
    // with a large Size triggers a multi-GB OOM that drowns the campaign.
    IInArchive* Archive = NanaZip::Fuzz::CreateHandler(3);
    if (!Archive) return 0;

    auto* Stream = new NanaZip::Fuzz::InMemoryInStream(Data, Size);
    UINT64 MaxCheck = 1ULL << 24;
    if (Archive->Open(Stream, &MaxCheck, nullptr) == S_OK)
    {
        UINT32 Num = 0;
        Archive->GetNumberOfItems(&Num);
        if (Num > 4096) Num = 4096;

        static const PROPID Props[] = {
            SevenZipArchivePath,
            SevenZipArchiveSize,
            SevenZipArchivePackSize,
            SevenZipArchiveIsDirectory,
            SevenZipArchiveModifiedTime,
            SevenZipArchiveAttributes,
            // SevenZipArchiveSymbolicLink omitted: uncapped Size -> OOM
        };
        for (UINT32 I = 0; I < Num; ++I)
        {
            for (PROPID P : Props)
            {
                PROPVARIANT V{};
                Archive->GetProperty(I, P, &V);
                ::PropVariantClear(&V);
            }
        }
        Archive->Close();
    }
    Stream->Release();
    Archive->Release();
    return 0;
}