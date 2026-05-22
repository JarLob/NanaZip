@rem Fuzz.cmd - run a NanaZip codec harness forever, never stop on crash.
@rem Usage:  Fuzz.cmd <Format> [corpus_dir]
@rem   e.g.  Fuzz.cmd Zealfs
@rem         Fuzz.cmd WebAssembly corpus\Wasm
@rem
@rem Artifacts are deduplicated by content SHA-1 and written to
@rem   crashes\<Format>\crash-<sha1>          - crashing inputs
@rem   crashes\<Format>\oom-<sha1>            - out-of-memory inputs
@rem   crashes\<Format>\timeout-<sha1>        - >timeout-second inputs
@rem
@rem libFuzzer fork-mode worker logs go to fuzz-<i>.log in CWD with NO option
@rem to rename them. To allow concurrent Fuzz.cmd invocations for different
@rem harnesses out of the same install dir, we cd into a per-harness work\
@rem subdirectory before launching, and reference exe / corpus / artifacts by
@rem absolute path.
@rem
@rem Triage tip (PowerShell):
@rem   gci crashes\Zealfs -Filter 'crash-*' ^| group {
@rem       (Get-FileHash $_.FullName -Algorithm SHA1).Hash.Substring(0,8) } ^|
@rem       sort Count -desc ^| select Count,Name
@echo off
setlocal EnableDelayedExpansion

if "%~1"=="" (
    echo Usage: %~nx0 ^<Format^> [corpus_dir]
    echo   Format: Ufs ^| DotNetSingleFile ^| ElectronAsar ^| Romfs ^| Zealfs ^| WebAssembly ^| Littlefs
    exit /b 2
)

set "HARNESS=%~1"
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

if "%~2"=="" (
    set "CORPUS=%ROOT%\corpus\%HARNESS%"
) else (
    rem Resolve user-supplied corpus path (relative paths bind to original cwd).
    for %%I in ("%~2") do set "CORPUS=%%~fI"
)

set "EXE=%ROOT%\Fuzz.%HARNESS%.exe"
if not exist "%EXE%" (
    echo [Fuzz.cmd] ERROR: %EXE% not found
    exit /b 3
)
if not exist "%CORPUS%" (
    echo [Fuzz.cmd] ERROR: corpus dir not found: %CORPUS%
    exit /b 3
)

set "OUT=%ROOT%\crashes\%HARNESS%"
if not exist "%OUT%" mkdir "%OUT%"

rem Per-harness working dir so concurrent invocations don't fight over
rem fuzz-0.log / fuzz-1.log (libFuzzer fork-mode worker logs, name hardcoded).
set "WORK=%ROOT%\work\%HARNESS%"
if not exist "%WORK%" mkdir "%WORK%"

rem Per-format dictionary of magic numbers / type tags. Massive exec/coverage
rem boost on formats with multi-byte signatures (WebAssembly, Romfs, Littlefs,
rem .NET single-file, ElectronAsar). Optional - skipped silently if missing.
set "DICTARG="
if exist "%ROOT%\dict\%HARNESS%.dict" (
    set "DICTARG=-dict=%ROOT%\dict\%HARNESS%.dict"
)

rem Per-format extra libFuzzer flags. Currently only used to keep UFS seeds
rem from being shrunk below the on-disk superblock offset (UFS2 @ 65536, UFS1
rem @ 8192) -- libFuzzer's default mutator otherwise truncates inputs and the
rem parser then fails the very first Seek/Read at offset 65536, wasting the
rem entire campaign. -max_len=1048576 keeps growth headroom for cylinder
rem groups; -len_control=0 disables the input-shrinking heuristic that would
rem otherwise erase the superblock entirely.
set "EXTRA_ARGS="
if /I "%HARNESS%"=="Ufs" (
    set "EXTRA_ARGS=-max_len=131072"
)
if /I "%HARNESS%"=="DotNetSingleFile" (
    rem Custom mutator places MZ+signature at fixed offsets so the 20 MiB scan
    rem finds the header instantly. 256 KiB is enough for the bundle header +
    rem file entries. NoExtract avoids the unchecked vector(Size) OOMs.
    set "EXTRA_ARGS=-max_len=262144 -malloc_limit_mb=16"
)
if /I "%HARNESS%"=="WebAssembly" (
    rem Largest real-world .wasm seed is ~19 KiB; cap at 64 KiB. ULEB128-decoded
    rem section sizes can still trigger multi-GB allocations from tiny inputs,
    rem so also lower malloc_limit_mb to reject them instantly.
    set "EXTRA_ARGS=-max_len=65536 -malloc_limit_mb=16"
)
if /I "%HARNESS%"=="Romfs" (
    rem Per-file Size field (BE u32) in file headers is attacker-controlled and
    rem flows into std::vector during Extract. Cap allocations.
    set "EXTRA_ARGS=-malloc_limit_mb=16"
)
if /I "%HARNESS%"=="Lvm" (
    rem LVM2 text metadata area size and string-table lengths are parsed from
    rem attacker-controlled input and flow into unchecked allocations. Without
    rem a cap every mutated input triggers multi-TB alloc attempts.
    set "EXTRA_ARGS=-malloc_limit_mb=16"
)
if /I "%HARNESS%"=="Avb" (
    rem AVB vbmeta descriptor sizes are attacker-controlled.
    set "EXTRA_ARGS=-malloc_limit_mb=16"
)

rem ASan: don't abort on huge single allocations (MSVC ASan will still print
rem the report, but libFuzzer's -ignore_ooms / -ignore_crashes will swallow
rem the exit). detect_leaks=0 is a no-op on Windows but harmless;
rem abort_on_error=0 is the Windows default but set explicitly in case of
rem inherited env.
set "ASAN_OPTIONS=allocator_may_return_null=1:detect_leaks=0:abort_on_error=0"

echo [Fuzz.cmd] harness=%HARNESS%
echo [Fuzz.cmd] corpus =%CORPUS%
echo [Fuzz.cmd] crashes=%OUT%\
echo [Fuzz.cmd] cwd    =%WORK%  ^(fuzz-N.log lives here^)

cd /d "%WORK%"

rem -fork=2 -> two parallel worker processes; the parent restarts them after
rem every crash/OOM/timeout, writes artifacts, continues. Do NOT add -jobs/
rem -workers on top of -fork: that spawns N parent processes, each redirecting
rem its own logs to fuzz-N.log (you stop seeing ASan reports live).
rem -ignore_crashes/-ignore_ooms/-ignore_timeouts=1 -> never exit on findings.
rem -reload=30 -> re-scan corpus for files added by other workers.
rem -malloc_limit_mb=256 -> reject any single alloc >256 MB before MSVC's ASan
rem allocator gets involved. Without this, formats with attacker-controlled
rem size fields (DotNetSingleFile, WebAssembly) drown the campaign in
rem multi-TB OOM aborts that each take 10-30s to wind down.
rem
rem Restart loop: libFuzzer's -fork mode on Windows has a known race condition
rem where a child's temp directory is deleted before the parent reads it,
rem causing a spurious "No such file or directory" exit. The loop below
rem automatically restarts the fuzzer when this happens. A 2-second pause
rem avoids tight-looping if something else is wrong. Ctrl-C still exits.
rem
rem Time-limited mode (CI): set FUZZ_TOTAL_SECONDS=N before calling this
rem script. The fuzzer will stop after N seconds total. Without this env var
rem the loop runs forever (interactive use).
if defined FUZZ_TOTAL_SECONDS (
    for /f %%T in ('powershell -NoProfile -c "[int](Get-Date).ToUniversalTime().Subtract([datetime]::UnixEpoch).TotalSeconds"') do set "FUZZ_START=%%T"
    set /a "FUZZ_END=FUZZ_START + FUZZ_TOTAL_SECONDS"
)
set "TIME_ARG="

:fuzz_loop
if defined FUZZ_TOTAL_SECONDS (
    for /f %%T in ('powershell -NoProfile -c "[int](Get-Date).ToUniversalTime().Subtract([datetime]::UnixEpoch).TotalSeconds"') do set "NOW=%%T"
    if !NOW! GEQ !FUZZ_END! goto fuzz_done
    set /a "REMAINING=FUZZ_END - NOW"
    set "TIME_ARG=-max_total_time=!REMAINING!"
    echo [Fuzz.cmd] !REMAINING!s remaining...
)

echo [Fuzz.cmd] Starting fuzzer (Ctrl-C to stop)...
"%EXE%" ^
    -fork=2 ^
    -ignore_crashes=1 ^
    -ignore_ooms=1 ^
    -ignore_timeouts=1 ^
    -timeout=30 ^
    -rss_limit_mb=4096 ^
    -malloc_limit_mb=256 ^
    -reload=30 ^
    -print_final_stats=1 ^
    -artifact_prefix=%OUT%\ ^
    %DICTARG% ^
    %EXTRA_ARGS% ^
    %TIME_ARG% ^
    "%CORPUS%"

if defined FUZZ_TOTAL_SECONDS (
    for /f %%T in ('powershell -NoProfile -c "[int](Get-Date).ToUniversalTime().Subtract([datetime]::UnixEpoch).TotalSeconds"') do set "NOW=%%T"
    if !NOW! GEQ !FUZZ_END! goto fuzz_done
)

set "FUZZ_EXIT=%ERRORLEVEL%"
echo [Fuzz.cmd] Fuzzer exited with code %FUZZ_EXIT%, restarting in 2s...
timeout /t 2 /nobreak >nul
goto fuzz_loop

:fuzz_done
echo [Fuzz.cmd] Time limit reached, stopping.
