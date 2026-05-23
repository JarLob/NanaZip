/*
 * PROJECT:    NanaZip
 * FILE:       NanaZip.Codecs.Fuzz.h
 * PURPOSE:    Shared libFuzzer harness scaffolding for NanaZip-specific
 *             archive handlers (formats not provided by upstream 7-Zip).
 *
 * LICENSE:    The MIT License
 *
 * Each per-format Fuzz.<Format>.cpp defines LLVMFuzzerTestOneInput and calls
 * RunFuzzCase(kFormatIndex, data, size). The harness loads the already-built
 * NanaZip.Codecs.dll (link with the ASan build under Output\Binaries\...) and
 * uses its exported 7-Zip-style CreateObject to instantiate the handler, so
 * no NanaZip object files need to be compiled into the fuzz binary.
 *
 * Fuzzed handlers (g_Archivers indices in NanaZip.Codecs.cpp):
 *   0 UFS / UFS2
 *   1 .NET single-file application
 *   2 Electron asar
 *   3 ROMFS
 *   4 ZealFS
 *   5 WebAssembly (wasm)
 *   6 littlefs
 *
 * Build (MSVC cl.exe, x64, ASan + libFuzzer; VS 2022 17.0+):
 *   cl /MD /Zi /O1 /EHsc /fsanitize=address /fsanitize=fuzzer ^
 *     /I"%cd%\..\NanaZip.Specification" ^
 *     Fuzz.Ufs.cpp /Fe:Fuzz.Ufs.exe /link /SUBSYSTEM:CONSOLE
 * (MSVC rejects the comma-joined /fsanitize=address,fuzzer form; pass each
 * sanitizer as a separate flag.)
 *
 * Run:
 *   set ASAN_OPTIONS=abort_on_error=1:allocator_may_return_null=1:detect_leaks=0
 *   Fuzz.Ufs.exe -timeout=30 -rss_limit_mb=4096 .\corpus\ufs
 *
 * The fuzz binary must live next to NanaZip.Codecs.dll (and
 * clang_rt.asan_dynamic-x86_64.dll). Easiest is to drop it into
 * Output\Binaries\Release\x64\ and run it from there.
 */

#ifndef NANAZIP_CODECS_FUZZ
#define NANAZIP_CODECS_FUZZ

#include <Windows.h>

#include <NanaZip.Specification.SevenZip.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace NanaZip::Fuzz
{
    using CreateObjectFn = HRESULT(WINAPI*)(const GUID*, const GUID*, void**);

    inline CreateObjectFn LoadCreateObject()
    {
        // The DLL is expected to live next to the fuzz binary (same directory
        // we are launched from in the typical case).
        HMODULE module = ::LoadLibraryW(L"NanaZip.Codecs.dll");
        if (!module)
        {
            std::abort();
        }
        auto fn = reinterpret_cast<CreateObjectFn>(
            ::GetProcAddress(module, "CreateObject"));
        if (!fn)
        {
            std::abort();
        }
        return fn;
    }

    inline GUID MakeArchiveClsid(std::uint32_t ProviderIndex)
    {
        // Mirrors the decoding in NanaZip.Codecs.cpp::CreateObject:
        //   Data4 reinterpreted as u64 LE = ArchiverProviderIdBase | Index
        //   ArchiverProviderIdBase = 0x4123374B00000000
        const std::uint64_t Id =
            0x4123374B00000000ULL | std::uint64_t(ProviderIndex);
        GUID g;
        g.Data1 = SevenZipGuidData1;
        g.Data2 = SevenZipGuidData2;
        g.Data3 = SevenZipGuidData3Common;
        for (int i = 0; i < 8; ++i)
        {
            g.Data4[i] = static_cast<std::uint8_t>(Id >> (i * 8));
        }
        return g;
    }

    template <typename Interface>
    class FuzzComBase : public Interface
    {
    public:
        ULONG STDMETHODCALLTYPE AddRef() override
        {
            return ++m_ref;
        }
        ULONG STDMETHODCALLTYPE Release() override
        {
            ULONG v = --m_ref;
            if (v == 0) delete this;
            return v;
        }
    protected:
        virtual ~FuzzComBase() = default;
    private:
        std::atomic<ULONG> m_ref{ 1 };
    };

    class InMemoryInStream final : public FuzzComBase<IInStream>
    {
    public:
        InMemoryInStream(const std::uint8_t* data, std::size_t size) noexcept
            : m_data(data), m_size(size), m_pos(0) {}

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) override
        {
            if (!out) return E_POINTER;
            if (riid == IID_IUnknown ||
                riid == __uuidof(ISequentialInStream) ||
                riid == __uuidof(IInStream))
            {
                *out = static_cast<IInStream*>(this);
                this->AddRef();
                return S_OK;
            }
            *out = nullptr;
            return E_NOINTERFACE;
        }

        HRESULT STDMETHODCALLTYPE Read(
            void* data, UINT32 size, UINT32* processed) override
        {
            std::uint64_t remaining = (m_pos < m_size) ? (m_size - m_pos) : 0;
            UINT32 toRead = (size < remaining)
                ? size
                : static_cast<UINT32>(remaining);
            if (toRead && data)
            {
                std::memcpy(data, m_data + m_pos, toRead);
            }
            m_pos += toRead;
            if (processed) *processed = toRead;
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE Seek(
            INT64 offset, UINT32 origin, UINT64* newPos) override
        {
            std::int64_t base = 0;
            switch (origin)
            {
            case STREAM_SEEK_SET: base = 0; break;
            case STREAM_SEEK_CUR: base = static_cast<std::int64_t>(m_pos); break;
            case STREAM_SEEK_END: base = static_cast<std::int64_t>(m_size); break;
            default: return E_INVALIDARG;
            }
            std::int64_t target = base + offset;
            if (target < 0)
            {
                return HRESULT_FROM_WIN32(ERROR_NEGATIVE_SEEK);
            }
            // Seeking past EOF is allowed; subsequent reads return zero bytes.
            m_pos = static_cast<std::uint64_t>(target);
            if (newPos) *newPos = m_pos;
            return S_OK;
        }

    private:
        const std::uint8_t* m_data;
        std::size_t m_size;
        std::uint64_t m_pos;
    };

    class NullOutStream final : public FuzzComBase<ISequentialOutStream>
    {
    public:
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) override
        {
            if (!out) return E_POINTER;
            if (riid == IID_IUnknown ||
                riid == __uuidof(ISequentialOutStream))
            {
                *out = static_cast<ISequentialOutStream*>(this);
                this->AddRef();
                return S_OK;
            }
            *out = nullptr;
            return E_NOINTERFACE;
        }

        HRESULT STDMETHODCALLTYPE Write(
            const void* /*data*/, UINT32 size, UINT32* processed) override
        {
            // Discard. We only care that the decode path executes under ASan.
            if (processed) *processed = size;
            return S_OK;
        }
    };

    class NullExtractCallback final : public FuzzComBase<IArchiveExtractCallback>
    {
    public:
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) override
        {
            if (!out) return E_POINTER;
            if (riid == IID_IUnknown ||
                riid == __uuidof(IProgress) ||
                riid == __uuidof(IArchiveExtractCallback))
            {
                *out = static_cast<IArchiveExtractCallback*>(this);
                this->AddRef();
                return S_OK;
            }
            *out = nullptr;
            return E_NOINTERFACE;
        }

        HRESULT STDMETHODCALLTYPE SetTotal(UINT64) override { return S_OK; }
        HRESULT STDMETHODCALLTYPE SetCompleted(const PUINT64) override { return S_OK; }

        HRESULT STDMETHODCALLTYPE GetStream(
            UINT32, ISequentialOutStream** stream, INT32 askMode) override
        {
            if (!stream) return E_POINTER;
            if (askMode == SevenZipExtractAskModeSkip)
            {
                *stream = nullptr;
                return S_OK;
            }
            *stream = new NullOutStream();
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE PrepareOperation(INT32) override { return S_OK; }
        HRESULT STDMETHODCALLTYPE SetOperationResult(INT32) override { return S_OK; }
    };

    inline IInArchive* CreateHandler(std::uint32_t formatIndex)
    {
        static CreateObjectFn s_create = LoadCreateObject();
        GUID clsid = MakeArchiveClsid(formatIndex);
        GUID iid = __uuidof(IInArchive);
        void* obj = nullptr;
        if (FAILED(s_create(&clsid, &iid, &obj)) || !obj)
        {
            return nullptr;
        }
        return static_cast<IInArchive*>(obj);
    }

    inline void RunFuzzCase(
        std::uint32_t formatIndex,
        const std::uint8_t* data,
        std::size_t size)
    {
        IInArchive* archive = CreateHandler(formatIndex);
        if (!archive) return;

        // The InMemoryInStream and NullExtractCallback start at refcount 1; the
        // handler will AddRef/Release as needed. Match that by holding our own
        // ref via stack ownership and Release() at the end.
        InMemoryInStream* stream = new InMemoryInStream(data, size);
        UINT64 maxCheck = 1ULL << 24; // 16 MiB header search window cap
        if (archive->Open(stream, &maxCheck, nullptr) == S_OK)
        {
            UINT32 num = 0;
            archive->GetNumberOfItems(&num);
            // Cap iterations so adversarial inputs claiming billions of entries
            // don't waste fuzzing budget.
            if (num > 4096) num = 4096;

            static const PROPID kProps[] = {
                SevenZipArchivePath,
                SevenZipArchiveSize,
                SevenZipArchivePackSize,
                SevenZipArchiveIsDirectory,
                SevenZipArchiveModifiedTime,
                SevenZipArchiveAttributes,
                SevenZipArchiveSymbolicLink,
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

            // Build an explicit index array instead of passing
            // (nullptr, 0xFFFFFFFF) which triggers a null-deref bug in
            // the NanaZip handlers (Indices[i] instead of ActualFileIndex
            // at the GetStream call).
            std::vector<UINT32> indices(num);
            for (UINT32 i = 0; i < num; ++i)
                indices[i] = i;

            NullExtractCallback* cb = new NullExtractCallback();
            archive->Extract(indices.data(), num, TRUE, cb);
            cb->Release();

            archive->Close();
        }
        stream->Release();
        archive->Release();
    }

    // Same as RunFuzzCase but skips the Extract call. Use for handlers where
    // Extract is a trivial read+write with no parsing, but has unchecked
    // attacker-controlled allocation sizes that cause OOMs on most iterations.
    inline void RunFuzzCaseNoExtract(
        std::uint32_t formatIndex,
        const std::uint8_t* data,
        std::size_t size)
    {
        IInArchive* archive = CreateHandler(formatIndex);
        if (!archive) return;

        InMemoryInStream* stream = new InMemoryInStream(data, size);
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
                SevenZipArchiveSymbolicLink,
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
    }
}

#endif // !NANAZIP_CODECS_FUZZ
