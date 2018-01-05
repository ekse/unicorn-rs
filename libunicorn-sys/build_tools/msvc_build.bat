@echo off

set curdir=%cd%

call "%~1"
if %errorlevel% neq 0 (
    exit /b 1
)

cd %curdir%

set LIB=%LIB%;"%~2"

if %3 == "" (
    set toolset_parameter=
) else (
    set toolset_parameter=PlatformToolset=%3;
)

msbuild msvc/unicorn.sln /m /t:unicorn_static /p:OutDir="%~2/";%toolset_parameter%useenv=true;Configuration=Release;Platform=%4
