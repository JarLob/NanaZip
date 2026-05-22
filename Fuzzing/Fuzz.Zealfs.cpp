// Fuzz.Zealfs.cpp - libFuzzer entry for the ZealFS handler.
#include "NanaZip.Codecs.Fuzz.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    NanaZip::Fuzz::RunFuzzCase(4, data, size);
    return 0;
}
