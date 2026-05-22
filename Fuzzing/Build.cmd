@echo off
rem Build all per-format libFuzzer harnesses for NanaZip-specific archive
rem handlers using MSVC (cl.exe). Requires Visual Studio 2022 17.0 or newer
rem with the C++ AddressSanitizer component installed (it ships both the ASan
rem and libFuzzer runtimes). Run from an "x64 Native Tools Command Prompt".
rem
rem Output goes next to the existing ASan-built NanaZip.Codecs.dll so
rem LoadLibrary picks it up and a single ASAN_OPTIONS applies to both the
rem harness and the codec DLL.

setlocal
set "ROOT=%~dp0"
set "OUT=%ROOT%..\Output\Binaries\Release\x64"
set "INC=/I""%ROOT%..\NanaZip.Specification"""

if not exist "%OUT%\NanaZip.Codecs.dll" (
    echo ERROR: %OUT%\NanaZip.Codecs.dll not found. Build the Release^|x64
    echo configuration with EnableASAN=true first.
    exit /b 1
)

if not exist "%ROOT%obj" mkdir "%ROOT%obj"

rem MSVC rejects the comma-joined form /fsanitize=address,fuzzer; pass each
rem sanitizer as a separate flag.
set "FLAGS=/nologo /MD /Zi /O1 /EHsc /std:c++17 /fsanitize=address /fsanitize=fuzzer"

for %%F in (Ufs DotNetSingleFile ElectronAsar Romfs Zealfs WebAssembly Littlefs Avb Lvm) do (
    echo === Building Fuzz.%%F.exe ===
    cl %FLAGS% %INC% "%ROOT%Fuzz.%%F.cpp" /Fo"%ROOT%obj\\" /Fe:"%OUT%\Fuzz.%%F.exe" /link /SUBSYSTEM:CONSOLE ole32.lib oleaut32.lib
    if errorlevel 1 (
        echo Build failed for %%F.
        exit /b 1
    )
)

echo.
echo Built harnesses:
dir /b "%OUT%\Fuzz.*.exe"
echo.
echo Drop seed inputs into per-format corpus directories, e.g.:
echo   mkdir "%OUT%\corpus\Ufs"
echo   copy poc\vuln001_oob.img "%OUT%\corpus\Ufs\"
echo Then run from %OUT%:
echo   set ASAN_OPTIONS=abort_on_error=1:allocator_may_return_null=1:detect_leaks=0
echo   Fuzz.Ufs.exe -timeout=30 -rss_limit_mb=4096 corpus\Ufs
endlocal
