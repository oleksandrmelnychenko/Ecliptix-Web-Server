#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Ecliptix AOT Server Runner - Cross-platform PowerShell script
    
.DESCRIPTION
    This script builds and runs the Ecliptix server with AOT compilation for optimal performance.
    Works on Windows, Linux, and macOS.
    
.PARAMETER Clean
    Clean build artifacts before building
    
.PARAMETER SkipBuild
    Skip build and run existing AOT binary
    
.PARAMETER Verbose
    Enable verbose output
    
.PARAMETER Runtime
    Specify runtime identifier (e.g., win-x64, linux-x64, osx-x64)
    
.PARAMETER Help
    Show help information
    
.EXAMPLE
    ./run-aot.ps1
    Build and run with default settings
    
.EXAMPLE
    ./run-aot.ps1 -Clean -Verbose
    Clean build and run with verbose output
    
.EXAMPLE
    ./run-aot.ps1 -SkipBuild
    Run existing AOT binary without rebuilding
#>

param(
    [switch]$Clean,
    [switch]$SkipBuild,
    [switch]$Verbose,
    [string]$Runtime,
    [switch]$Help
)

# Configuration
$ProjectDir = Split-Path $PSScriptRoot -Parent
$ProjectFile = Join-Path $ProjectDir "Ecliptix.Core" "Ecliptix.Core.csproj"
$Configuration = "Release"

# Determine default runtime based on platform
if (-not $Runtime) {
    if ($IsWindows -or $env:OS -eq "Windows_NT") {
        $Runtime = "win-x64"
        $BinaryExtension = ".exe"
    } elseif ($IsLinux) {
        $Runtime = "linux-x64"
        $BinaryExtension = ""
    } elseif ($IsMacOS) {
        $Runtime = "osx-x64"
        $BinaryExtension = ""
    } else {
        $Runtime = "linux-x64"  # Default fallback
        $BinaryExtension = ""
    }
} else {
    $BinaryExtension = if ($Runtime.StartsWith("win-")) { ".exe" } else { "" }
}

$OutputDir = Join-Path $ProjectDir "Ecliptix.Core" "bin" $Configuration "net9.0" $Runtime "publish"
$AotBinary = Join-Path $OutputDir "Ecliptix.Core$BinaryExtension"

# Colors for output (if terminal supports it)
$Colors = @{
    Red = "`e[31m"
    Green = "`e[32m" 
    Yellow = "`e[33m"
    Blue = "`e[34m"
    Reset = "`e[0m"
}

# Fallback for terminals that don't support ANSI colors
if (-not $Host.UI.SupportsVirtualTerminal) {
    $Colors = @{
        Red = ""
        Green = ""
        Yellow = ""
        Blue = ""
        Reset = ""
    }
}

# Logging functions
function Write-Log {
    param([string]$Message)
    Write-Host "$($Colors.Blue)[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')]$($Colors.Reset) $Message"
}

function Write-Success {
    param([string]$Message)
    Write-Host "$($Colors.Green)[SUCCESS]$($Colors.Reset) $Message"
}

function Write-Warning {
    param([string]$Message)
    Write-Host "$($Colors.Yellow)[WARNING]$($Colors.Reset) $Message"
}

function Write-Error {
    param([string]$Message)
    Write-Host "$($Colors.Red)[ERROR]$($Colors.Reset) $Message"
}

# Show help
if ($Help) {
    Write-Host ""
    Write-Host "$($Colors.Blue)Ecliptix AOT Server Runner$($Colors.Reset)"
    Write-Host ""
    Write-Host "Usage: ./run-aot.ps1 [parameters]"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -Clean         Clean build artifacts before building"
    Write-Host "  -SkipBuild     Skip build and run existing AOT binary" 
    Write-Host "  -Verbose       Enable verbose output"
    Write-Host "  -Runtime       Specify runtime identifier (auto-detected by default)"
    Write-Host "  -Help          Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  ./run-aot.ps1                    # Build and run with default settings"
    Write-Host "  ./run-aot.ps1 -Clean -Verbose    # Clean build and run with verbose output"
    Write-Host "  ./run-aot.ps1 -SkipBuild         # Run existing AOT binary"
    Write-Host "  ./run-aot.ps1 -Runtime linux-arm64  # Build for ARM64 Linux"
    Write-Host ""
    exit 0
}

# Header
Write-Host ""
Write-Host "╔══════════════════════════════════════╗"
Write-Host "║        Ecliptix AOT Server           ║"
Write-Host "║     High-Performance Cryptographic   ║"
Write-Host "║          Protocol Server             ║"
Write-Host "╚══════════════════════════════════════╝"
Write-Host ""

# Check prerequisites
Write-Log "Checking prerequisites..."

# Check if dotnet is installed
try {
    $dotnetVersion = & dotnet --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet command failed"
    }
    Write-Log "Found .NET SDK version: $dotnetVersion"
} catch {
    Write-Error ".NET SDK is not installed or not in PATH"
    exit 1
}

# Check if project file exists
if (-not (Test-Path $ProjectFile)) {
    Write-Error "Project file not found: $ProjectFile"
    exit 1
}

Write-Success "Prerequisites check passed"

# Clean build artifacts
if ($Clean) {
    Write-Log "Cleaning build artifacts..."
    Push-Location $ProjectDir
    
    try {
        if ($Verbose) {
            & dotnet clean --configuration $Configuration --verbosity detailed
        } else {
            & dotnet clean --configuration $Configuration | Out-Null
        }
        
        # Remove publish directory
        if (Test-Path $OutputDir) {
            Remove-Item $OutputDir -Recurse -Force
            Write-Log "Removed publish directory"
        }
        
        Write-Success "Clean completed"
    } finally {
        Pop-Location
    }
}

# Build AOT binary
if (-not $SkipBuild) {
    Write-Log "Starting AOT compilation..."
    Write-Log "Configuration: $Configuration"
    Write-Log "Runtime: $Runtime"
    Write-Log "Output: $OutputDir"
    
    Push-Location $ProjectDir
    
    try {
        $publishArgs = @(
            "publish"
            $ProjectFile
            "--configuration", $Configuration
            "--runtime", $Runtime
        )
        
        if ($Verbose) {
            $publishArgs += "--verbosity", "detailed"
        }
        
        Write-Log "Executing: dotnet $($publishArgs -join ' ')"
        
        # Capture build time
        $buildStart = Get-Date
        
        & dotnet @publishArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Publish command failed"
        }
        
        $buildEnd = Get-Date
        $buildTime = [math]::Round(($buildEnd - $buildStart).TotalSeconds, 1)
        Write-Success "AOT compilation completed in ${buildTime}s"
    } catch {
        Write-Error "AOT compilation failed"
        exit 1
    } finally {
        Pop-Location
    }
} else {
    Write-Log "Skipping build as requested"
}

# Check if AOT binary exists
if (-not (Test-Path $AotBinary)) {
    Write-Error "AOT binary not found: $AotBinary"
    Write-Error "Try running without -SkipBuild to build the binary first"
    exit 1
}

# Make binary executable on Unix systems
if ($BinaryExtension -eq "" -and (Test-Path $AotBinary)) {
    try {
        & chmod +x $AotBinary 2>$null
    } catch {
        # Ignore errors, might not be needed
    }
}

# Get binary size
$binarySize = (Get-Item $AotBinary).Length
$binarySizeMB = [math]::Round($binarySize / 1MB, 2)
Write-Success "AOT binary ready: $AotBinary ($binarySizeMB MB)"

# Display system information
Write-Log "System Information:"
Write-Host "  OS: $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)"
Write-Host "  Architecture: $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
Write-Host "  Runtime: $Runtime"
Write-Host "  Binary: $AotBinary"
Write-Host "  Working Directory: $(Join-Path $ProjectDir 'Ecliptix.Core')"

# Run the AOT server
Write-Log "Starting Ecliptix AOT server..."

# Change to the project directory for proper config file resolution
$workingDir = Join-Path $ProjectDir "Ecliptix.Core"
Push-Location $workingDir

try {
    # Set environment variables for optimal AOT performance
    $env:DOTNET_ReadyToRun = "0"
    $env:DOTNET_TieredCompilation = "0" 
    $env:DOTNET_TC_QuickJit = "0"
    
    Write-Log "Environment configured for AOT execution"
    Write-Log "Server starting with native AOT binary..."
    Write-Host ""
    Write-Host "$($Colors.Green)========================================$($Colors.Reset)"
    Write-Host "$($Colors.Green)  🚀 Ecliptix AOT Server Starting...$($Colors.Reset)"
    Write-Host "$($Colors.Green)========================================$($Colors.Reset)"
    Write-Host ""
    
    # Execute the AOT binary
    & $AotBinary
} finally {
    Pop-Location
}