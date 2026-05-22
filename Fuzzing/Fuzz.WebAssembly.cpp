// Fuzz.WebAssembly.cpp - libFuzzer entry for the WebAssembly (wasm) handler.
//
// WebAssembly binary format (MVP):
//   bytes [0..3]: magic   \0asm  (0x00 0x61 0x73 0x6D)
//   bytes [4..7]: version 1      (0x01 0x00 0x00 0x00)
//   bytes [8.. ]: sections (type:1 + ULEB128 size + payload)
//
// Without a custom mutator, random byte changes break the 8-byte header
// and the handler bails at the memcmp check, wasting the iteration.
// We rewrite the magic+version after each mutation.
#include "NanaZip.Codecs.Fuzz.h"
#include <cstring>
#include <cstdint>

extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

static constexpr size_t kWasmHeaderSize = 8;
static const uint8_t kWasmHeader[kWasmHeaderSize] = {
    0x00, 0x61, 0x73, 0x6D,   // \0asm
    0x01, 0x00, 0x00, 0x00    // version 1
};

extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* Data, size_t Size, size_t MaxSize, unsigned int /*Seed*/)
{
    size_t NewSize = LLVMFuzzerMutate(Data, Size, MaxSize);

    if (NewSize < kWasmHeaderSize)
    {
        if (MaxSize < kWasmHeaderSize)
            return NewSize;
        std::memset(Data + NewSize, 0, kWasmHeaderSize - NewSize);
        NewSize = kWasmHeaderSize;
    }

    // Fix magic + version so every iteration reaches the section parser
    std::memcpy(Data, kWasmHeader, kWasmHeaderSize);

    // Clamp ULEB128 runs to prevent multi-GB allocations from tiny inputs.
    // ULEB128 uses bit 7 as a continuation flag. A run of N continuation
    // bytes encodes a value up to 2^(7*N)-1. We allow at most 2 continuation
    // bytes (max decoded value = 16383 = 16 KiB), which is generous for any
    // section size within a 64 KiB input. Clearing bit 7 on the 3rd+
    // consecutive high-bit byte terminates the ULEB128 without changing
    // the byte count or shifting subsequent positions.
    int run = 0;
    for (size_t i = kWasmHeaderSize; i < NewSize; ++i)
    {
        if (Data[i] & 0x80)
        {
            ++run;
            if (run >= 2)
                Data[i] &= 0x7F;  // clear continuation → cap value
        }
        else
        {
            run = 0;
        }
    }

    return NewSize;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    NanaZip::Fuzz::RunFuzzCase(5, data, size);
    return 0;
}
