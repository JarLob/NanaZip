// Fuzz.Littlefs.cpp - libFuzzer entry for the littlefs handler.
#include "NanaZip.Codecs.Fuzz.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    NanaZip::Fuzz::RunFuzzCase(6, data, size);
    return 0;
}
