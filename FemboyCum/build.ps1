param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot 'work\build-x86'),
    [string]$Generator = 'Visual Studio 18 2026',
    [ValidateSet('Release','Debug')][string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$taskCmakeCommand = Get-Command cmake.exe -ErrorAction SilentlyContinue
if ($taskCmakeCommand) {
    $taskCmake = $taskCmakeCommand.Source
} else {
    $taskCandidates = @(Get-ChildItem -Path "$env:ProgramFiles\Microsoft Visual Studio\*\*\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" -File -ErrorAction SilentlyContinue)
    if (-not $taskCandidates.Count) { throw 'CMake not found. Install CMake and the MSVC C++ desktop workload.' }
    $taskCmake = ($taskCandidates | Sort-Object FullName -Descending | Select-Object -First 1).FullName
}
$taskCtest = Join-Path (Split-Path -Parent $taskCmake) 'ctest.exe'
& $taskCmake -S $PSScriptRoot -B $BuildDirectory -G $Generator -A Win32 -DBUILD_TESTING=ON
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
& $taskCmake --build $BuildDirectory --config $Configuration --parallel 3
if ($LASTEXITCODE -ne 0) { throw 'Source build failed' }
& $taskCtest --test-dir $BuildDirectory -C $Configuration --output-on-failure --output-junit (Join-Path $BuildDirectory 'tests.xml')
if ($LASTEXITCODE -ne 0) { throw 'CTest failed' }
