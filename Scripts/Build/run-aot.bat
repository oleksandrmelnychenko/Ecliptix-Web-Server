@echo off
setlocal enabledelayedexpansion

:: Ecliptix AOT Server Runner for Windows
:: This script builds and runs the Ecliptix server with AOT compilation for optimal performance

:: Configuration
set "PROJECT_DIR=%~dp0.."
set "PROJECT_FILE=%PROJECT_DIR%\Ecliptix.Core\Ecliptix.Core.csproj"
set "RUNTIME_ID=win-x64"
set "CONFIGURATION=Release"
set "OUTPUT_DIR=%PROJECT_DIR%\Ecliptix.Core\bin\%CONFIGURATION%\net9.0\%RUNTIME_ID%\publish"
set "AOT_BINARY=%OUTPUT_DIR%\Ecliptix.Core.exe"

:: Default options
set "CLEAN=false"
set "SKIP_BUILD=false"
set "VERBOSE=false"
set "HELP=false"

:: Parse command line arguments
:parse_args
if "%~1"=="" goto end_parse
if /i "%~1"=="--clean" (
    set "CLEAN=true"
    shift
    goto parse_args
)
if /i "%~1"=="-c" (
    set "CLEAN=true"
    shift
    goto parse_args
)
if /i "%~1"=="--skip-build" (
    set "SKIP_BUILD=true"
    shift
    goto parse_args
)
if /i "%~1"=="-s" (
    set "SKIP_BUILD=true"
    shift
    goto parse_args
)
if /i "%~1"=="--verbose" (
    set "VERBOSE=true"
    shift
    goto parse_args
)
if /i "%~1"=="-v" (
    set "VERBOSE=true"
    shift
    goto parse_args
)
if /i "%~1"=="--help" (
    set "HELP=true"
    shift
    goto parse_args
)
if /i "%~1"=="-h" (
    set "HELP=true"
    shift
    goto parse_args
)
if /i "%~1"=="--runtime" (
    set "RUNTIME_ID=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="-r" (
    set "RUNTIME_ID=%~2"
    shift
    shift
    goto parse_args
)
echo Unknown option: %~1
set "HELP=true"
shift
goto parse_args

:end_parse

:: Show help
if "%HELP%"=="true" (
    echo.
    echo Ecliptix AOT Server Runner for Windows
    echo.
    echo Usage: %~nx0 [options]
    echo.
    echo Options:
    echo   -c, --clean        Clean build artifacts before building
    echo   -s, --skip-build   Skip build and run existing AOT binary
    echo   -v, --verbose      Enable verbose output
    echo   -r, --runtime      Specify runtime identifier ^(default: win-x64^)
    echo   -h, --help         Show this help message
    echo.
    echo Examples:
    echo   %~nx0                    # Build and run with default settings
    echo   %~nx0 --clean            # Clean build and run
    echo   %~nx0 --skip-build       # Run existing AOT binary without rebuilding
    echo   %~nx0 --runtime win-arm64 --verbose  # Build for ARM64 with verbose output
    echo.
    exit /b 0
)

:: Header
echo.
echo ╔══════════════════════════════════════╗
echo ║        Ecliptix AOT Server           ║
echo ║     High-Performance Cryptographic   ║
echo ║          Protocol Server             ║
echo ╚══════════════════════════════════════╝
echo.

:: Check prerequisites
echo [%date% %time%] Checking prerequisites...

:: Check if dotnet is installed
dotnet --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] .NET SDK is not installed or not in PATH
    exit /b 1
)

:: Get dotnet version
for /f "tokens=*" %%i in ('dotnet --version 2^>nul') do set "DOTNET_VERSION=%%i"
echo Found .NET SDK version: !DOTNET_VERSION!

:: Check if project file exists
if not exist "%PROJECT_FILE%" (
    echo [ERROR] Project file not found: %PROJECT_FILE%
    exit /b 1
)

echo [SUCCESS] Prerequisites check passed

:: Clean build artifacts
if "%CLEAN%"=="true" (
    echo [%date% %time%] Cleaning build artifacts...
    cd /d "%PROJECT_DIR%"
    
    if "%VERBOSE%"=="true" (
        dotnet clean --configuration "%CONFIGURATION%" --verbosity detailed
    ) else (
        dotnet clean --configuration "%CONFIGURATION%" >nul 2>&1
    )
    
    :: Remove publish directory
    if exist "%OUTPUT_DIR%" (
        rmdir /s /q "%OUTPUT_DIR%"
        echo Removed publish directory
    )
    
    echo [SUCCESS] Clean completed
)

:: Build AOT binary
if "%SKIP_BUILD%"=="false" (
    echo [%date% %time%] Starting AOT compilation...
    echo Configuration: %CONFIGURATION%
    echo Runtime: %RUNTIME_ID%
    echo Output: %OUTPUT_DIR%
    
    cd /d "%PROJECT_DIR%"
    
    :: Build command with appropriate verbosity
    if "%VERBOSE%"=="true" (
        set "PUBLISH_CMD=dotnet publish "%PROJECT_FILE%" --configuration %CONFIGURATION% --runtime %RUNTIME_ID% --verbosity detailed"
    ) else (
        set "PUBLISH_CMD=dotnet publish "%PROJECT_FILE%" --configuration %CONFIGURATION% --runtime %RUNTIME_ID%"
    )
    
    echo Executing: !PUBLISH_CMD!
    
    :: Execute build command
    !PUBLISH_CMD!
    if errorlevel 1 (
        echo [ERROR] AOT compilation failed
        exit /b 1
    )
    
    echo [SUCCESS] AOT compilation completed
) else (
    echo [%date% %time%] Skipping build as requested
)

:: Check if AOT binary exists
if not exist "%AOT_BINARY%" (
    echo [ERROR] AOT binary not found: %AOT_BINARY%
    echo [ERROR] Try running without --skip-build to build the binary first
    exit /b 1
)

:: Get binary size
for %%i in ("%AOT_BINARY%") do set "BINARY_SIZE=%%~zi"
set /a "BINARY_SIZE_MB=!BINARY_SIZE!/1024/1024"
echo [SUCCESS] AOT binary ready: %AOT_BINARY% ^(!BINARY_SIZE_MB! MB^)

:: Display system information
echo [%date% %time%] System Information:
echo   OS: Windows
echo   Architecture: %PROCESSOR_ARCHITECTURE%
echo   Binary: %AOT_BINARY%
echo   Working Directory: %PROJECT_DIR%Ecliptix.Core

:: Run the AOT server
echo [%date% %time%] Starting Ecliptix AOT server...

:: Change to the project directory for proper config file resolution
cd /d "%PROJECT_DIR%Ecliptix.Core"

:: Set environment variables for optimal AOT performance
set "DOTNET_ReadyToRun=0"
set "DOTNET_TieredCompilation=0"
set "DOTNET_TC_QuickJit=0"

echo Environment configured for AOT execution
echo Server starting with native AOT binary...
echo.
echo ========================================
echo   🚀 Ecliptix AOT Server Starting...
echo ========================================
echo.

:: Execute the AOT binary
"%AOT_BINARY%"