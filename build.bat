@echo off
echo ================================================================================
echo BUILDING GO WEB SERVER
echo ================================================================================
echo.

echo [1/2] Building optimized binary...
go build -ldflags="-s -w" -o server.exe main.go

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [2/2] Build successful!
    echo.
    echo ================================================================================
    echo BINARY INFO:
    echo ================================================================================
    dir server.exe | findstr server.exe
    echo.
    echo ================================================================================
    echo TO RUN:
    echo ================================================================================
    echo   server.exe
    echo.
    echo OR double-click server.exe
    echo ================================================================================
) else (
    echo.
    echo [ERROR] Build failed!
    echo.
)

pause
