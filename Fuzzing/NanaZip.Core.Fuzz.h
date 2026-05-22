/*
 * PROJECT:    NanaZip
 * FILE:       NanaZip.Core.Fuzz.h
 * PURPOSE:    libFuzzer scaffolding for upstream-7-Zip handlers shipped by
 *             NanaZip but NOT bundled into 7-Zip's official 7z.dll. Currently
 *             AvbHandler (Android Verified Boot vbmeta) and LvmHandler (Linux
 *             LVM2 physical volume metadata).
 *
 * LICENSE:    The MIT License
 *
 * Loads NanaZip.Core.dll (the 7-Zip-fork DLL inside the NanaZip install) and
 * uses its exported 7-Zip codec ABI (CreateObject + GetNumberOfFormats +
 * GetHandlerProperty2) to look up a handler by its registered "Name" string
 * (e.g. "AVB", "LVM"). Reuses the COM stream/callback stubs from the sibling
 * header NanaZip.Codecs.Fuzz.h.
 */

#ifndef NANAZIP_CORE_FUZZ
#define NANAZIP_CORE_FUZZ

#include "NanaZip.Codecs.Fuzz.h"

#include <atomic>
#include <cstring>
#include <string>

namespace NanaZip::Fuzz::Core
{
    using GetNumberOfFormatsFn = HRESULT(WINAPI*)(UINT32*);
    using GetHandlerProperty2Fn = HRESULT(WINAPI*)(UINT32, PROPID, PROPVARIANT*);

    // 7-Zip NHandlerPropID enum values from IArchive.h.
    constexpr PROPID kHandlerPropName    = 0;
    constexpr PROPID kHandlerPropClassID = 1;

    struct CoreApi
    {
        HMODULE Module;
        CreateObjectFn CreateObject;
        GetNumberOfFormatsFn GetNumberOfFormats;
        GetHandlerProperty2Fn GetHandlerProperty2;
    };

    inline CoreApi const& LoadCoreApi()
    {
        static CoreApi api = []() -> CoreApi {
            CoreApi a{};
            a.Module = ::LoadLibraryW(L"NanaZip.Core.dll");
            if (!a.Module) std::abort();
            a.CreateObject = reinterpret_cast<CreateObjectFn>(
                ::GetProcAddress(a.Module, "CreateObject"));
            a.GetNumberOfFormats = reinterpret_cast<GetNumberOfFormatsFn>(
                ::GetProcAddress(a.Module, "GetNumberOfFormats"));
            a.GetHandlerProperty2 = reinterpret_cast<GetHandlerProperty2Fn>(
                ::GetProcAddress(a.Module, "GetHandlerProperty2"));
            if (!a.CreateObject || !a.GetNumberOfFormats || !a.GetHandlerProperty2)
            {
                std::abort();
            }
            return a;
        }();
        return api;
    }

    // Returns true and fills outClsid if a handler whose registered name
    // matches `name` (case-sensitive) is found. The CLSID lives in a static
    // cache so subsequent calls are free.
    inline bool ResolveHandlerClsid(const wchar_t* name, GUID& outClsid)
    {
        CoreApi const& api = LoadCoreApi();
        UINT32 count = 0;
        if (FAILED(api.GetNumberOfFormats(&count))) return false;

        for (UINT32 i = 0; i < count; ++i)
        {
            PROPVARIANT vName{};
            if (FAILED(api.GetHandlerProperty2(i, kHandlerPropName, &vName)))
            {
                continue;
            }
            bool match = (vName.vt == VT_BSTR && vName.bstrVal &&
                std::wcscmp(vName.bstrVal, name) == 0);
            ::PropVariantClear(&vName);
            if (!match) continue;

            PROPVARIANT vClsid{};
            if (FAILED(api.GetHandlerProperty2(i, kHandlerPropClassID, &vClsid)))
            {
                return false;
            }
            // ClassID is delivered as a 16-byte binary blob in a BSTR.
            bool ok = false;
            if (vClsid.vt == VT_BSTR && vClsid.bstrVal &&
                ::SysStringByteLen(vClsid.bstrVal) >= sizeof(GUID))
            {
                std::memcpy(&outClsid, vClsid.bstrVal, sizeof(GUID));
                ok = true;
            }
            ::PropVariantClear(&vClsid);
            return ok;
        }
        return false;
    }

    inline IInArchive* CreateHandlerByName(const wchar_t* name)
    {
        // Cache the resolved CLSID per name across iterations.
        static std::atomic<bool> s_resolved{ false };
        static GUID s_clsid{};
        static const wchar_t* s_name = nullptr;

        if (!s_resolved.load(std::memory_order_acquire) || s_name != name)
        {
            GUID g{};
            if (!ResolveHandlerClsid(name, g)) return nullptr;
            s_clsid = g;
            s_name = name;
            s_resolved.store(true, std::memory_order_release);
        }

        CoreApi const& api = LoadCoreApi();
        GUID iid = __uuidof(IInArchive);
        void* obj = nullptr;
        if (FAILED(api.CreateObject(&s_clsid, &iid, &obj)) || !obj)
        {
            return nullptr;
        }
        return static_cast<IInArchive*>(obj);
    }

    inline void RunFuzzCaseByName(
        const wchar_t* handlerName,
        const std::uint8_t* data,
        std::size_t size)
    {
        IInArchive* archive = CreateHandlerByName(handlerName);
        if (!archive) return;

        InMemoryInStream* stream = new InMemoryInStream(data, size);
        UINT64 maxCheck = 1ULL << 24; // 16 MiB header search window cap
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
}

#endif // !NANAZIP_CORE_FUZZ
