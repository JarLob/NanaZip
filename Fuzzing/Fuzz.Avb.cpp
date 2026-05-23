// Fuzz.Avb.cpp - libFuzzer entry for the upstream-7-Zip AvbHandler that
// NanaZip ships but 7-Zip's official 7z.dll does not.
//
// AVB layout (AvbHandler.cpp):
//   bytes [0 .. vbmeta_size-1] : vbmeta block (header + auth + aux/descriptors)
//   bytes [vbmeta_size .. fileSize-65] : partition data (ext image etc.)
//   bytes [fileSize-64 .. fileSize-1] : footer
//
// Footer gates (Open2):
//   [0..7]   memcmp "AVBf\0\0\0\1"
//   [28..35] vbmeta_size in [256, 65536]
//   [36..63] all zeros (reserved)
//
// Vbmeta header gates (AvbVBMetaImageHeader::Parse):
//   [0..3]   BE u32 == 0x41564230 ("AVB0")
//   [4..7]   required_libavb_version_major (BE u32) == 1
//
// Without a custom mutator, random byte changes to the 64-byte footer (whose
// POSITION shifts whenever libFuzzer changes the input length) almost never
// satisfy all constraints at once. We fix the footer + vbmeta-header after
// every mutation so the fuzzer always reaches the descriptor-walk code.
#include "NanaZip.Core.Fuzz.h"
#include <cstring>
#include <algorithm>

extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

static void WriteBE32(std::uint8_t* p, std::uint32_t v)
{
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

static void WriteBE64(std::uint8_t* p, std::uint64_t v)
{
    WriteBE32(p, static_cast<std::uint32_t>(v >> 32));
    WriteBE32(p + 4, static_cast<std::uint32_t>(v));
}

// Minimum useful size: 256 (vbmeta header) + 64 (footer) = 320
static constexpr size_t kMinAvb = 320;
static constexpr size_t kFooterSize = 64;
static constexpr size_t kVbmetaHeaderSize = 256;

extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /*Seed*/)
{
    size_t NewSize = LLVMFuzzerMutate(Data, Size, MaxSize);

    // Ensure minimum size for a parseable AVB image.
    if (NewSize < kMinAvb)
    {
        if (MaxSize < kMinAvb)
            return NewSize;          // can't fix, let it fail fast
        // Zero-extend
        std::memset(Data + NewSize, 0, kMinAvb - NewSize);
        NewSize = kMinAvb;
    }

    // --- Fix vbmeta header (always at offset 0) ---
    WriteBE32(Data + 0, 0x41564230);   // "AVB0"
    WriteBE32(Data + 4, 1);            // required_libavb_version_major

    // --- Fix footer (last 64 bytes) ---
    std::uint8_t* footer = Data + NewSize - kFooterSize;

    // Magic "AVBf\0\0\0\1"
    static const std::uint8_t kSig[8] = {
        'A','V','B','f', 0, 0, 0, 1
    };
    std::memcpy(footer, kSig, 8);

    // version_minor = 0
    std::memset(footer + 8, 0, 4);

    // original_image_size: keep whatever the mutator put in bytes 12..19
    // (the handler reads it but only uses it for the sub-stream size)

    // vbmeta_offset = 0  (BE u64)
    WriteBE64(footer + 20, 0);

    // vbmeta_size = min(NewSize - 64, 65536), clamped to >= 256
    std::uint64_t vbmetaSize = NewSize - kFooterSize;
    if (vbmetaSize > 65536) vbmetaSize = 65536;
    if (vbmetaSize < kVbmetaHeaderSize) vbmetaSize = kVbmetaHeaderSize;
    WriteBE64(footer + 28, vbmetaSize);

    // Reserved bytes 36..63 must be zero.
    std::memset(footer + 36, 0, 28);

    return NewSize;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    NanaZip::Fuzz::Core::RunFuzzCaseByName(L"AVB", data, size);
    return 0;
}
