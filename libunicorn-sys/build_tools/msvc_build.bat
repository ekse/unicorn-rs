@echo off

set curdir=%cd%

call "%~1" -arch=x64 -host_arch=x86 -no_logo
if %errorlevel% neq 0 (
    exit /b 1
)

cd %curdir%

set LIB=%LIB%;"%~2"

msbuild msvc/unicorn.sln /m /t:unicorn_static /p:OutDir="%~2/";%3useenv=true;Configuration=Release
