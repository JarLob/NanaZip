// Fuzz.DotNetSingleFile.cpp - libFuzzer entry for the .NET single-file handler.
//
// .NET SingleFile bundle layout:
//   [0..1]   : "MZ" (PE signature check)
//   [2..9]   : int64_t BundleHeaderOffset
//   [10..41] : 32-byte SHA-256 signature (g_BundleSignature)
//   [42+]    : bundle header (version, file count, entries...)
//
// The handler scans up to 20 MiB looking for the signature byte-by-byte.
// Without a mutator, most iterations waste time on inputs where the signature
// is never found. We place the MZ + offset + signature at fixed positions so
// every iteration reaches the bundle header parser immediately.
#include "NanaZip.Codecs.Fuzz.h"
#include <cstring>
#include <cstdint>

extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

// Bundle signature: SHA-256 of ".net core bundle"
static const uint8_t kBundleSig[32] = {
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
    0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
    0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
};

// Fixed layout:
//   [0]  'M'
//   [1]  'Z'
//   [2]  int64_t LE = 42  (BundleHeaderOffset, points right after signature)
//   [10] signature (32 bytes)
//   [42] start of bundle header (mutator leaves this to libFuzzer)
static constexpr size_t kSigOffset = 10;
static constexpr size_t kHeaderStart = kSigOffset + 32;  // 42
static constexpr size_t kMinDotNet = kHeaderStart + 13;   // version(8) + count(4) + idlen(1)

static void WriteLE64(uint8_t* p, int64_t v)
{
    auto u = static_cast<uint64_t>(v);
    for (int i = 0; i < 8; ++i) { p[i] = static_cast<uint8_t>(u >> (i*8)); }
}

extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /*Seed*/)
{
    size_t NewSize = LLVMFuzzerMutate(Data, Size, MaxSize);

    if (NewSize < kMinDotNet)
    {
        if (MaxSize < kMinDotNet)
            return NewSize;
        std::memset(Data + NewSize, 0, kMinDotNet - NewSize);
        NewSize = kMinDotNet;
    }

    // Fix the header stub so the signature scan succeeds instantly
    Data[0] = 'M';
    Data[1] = 'Z';
    WriteLE64(Data + 2, static_cast<int64_t>(kHeaderStart));
    std::memcpy(Data + kSigOffset, kBundleSig, 32);

    return NewSize;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    NanaZip::Fuzz::RunFuzzCaseNoExtract(1, data, size);
    return 0;
}
