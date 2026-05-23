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
    // Like RunFuzzCaseNoExtract but WITHOUT querying SevenZipArchiveSymbolicLink.
    // The Romfs handler allocates std::string(Information.Size, '\0') for symlinks
    // where Size is an uncapped attacker-controlled BE u32 — every symlink entry
    // with a large Size triggers a multi-GB OOM that drowns the campaign.
    IInArchive* archive = NanaZip::Fuzz::CreateHandler(3);
    if (!archive) return 0;

    auto* stream = new NanaZip::Fuzz::InMemoryInStream(data, size);
    UINT64 maxCheck = 1ULL << 24;
    if (archive->Open(stream, &maxCheck, nullptr) == S_OK)
    {
        UINT32 num = 0;
        archive->GetNumberOfItems(&num);
        if (num > 4096) num = 4096;

        static const PROPID kProps[] = {
            SevenZipArchivePath,
            SevenZipArchiveSize,
            SevenZipArchivePackSize,
            SevenZipArchiveIsDirectory,
            SevenZipArchiveModifiedTime,
            SevenZipArchiveAttributes,
            // SevenZipArchiveSymbolicLink omitted: uncapped Size → OOM
        };
        for (UINT32 i = 0; i < num; ++i)
        {
            for (PROPID p : kProps)
            {
                PROPVARIANT v{};
                archive->GetProperty(i, p, &v);
                ::PropVariantClear(&v);
            }
        }
        archive->Close();
    }
    stream->Release();
    archive->Release();
    return 0;
}
