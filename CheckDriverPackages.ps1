<#
.SYNOPSIS
    Audits ConfigMgr Driver Packages for source path existence and content validation.

.DESCRIPTION
    Examines all ConfigMgr Driver Packages and validates that:
    - Source path is configured
    - Source directory exists and is accessible
    - Source directory contains files (not empty)
    
    This script is particularly useful during ConfigMgr cleanup operations to identify
    driver packages with missing or empty source directories, which can cause deployment errors.
    
    The script generates a detailed CSV report with validation results for each driver package.

.PARAMETER SiteCode
    ConfigMgr site code (e.g., 'P01', 'PS1').
    If not specified, the script attempts to auto-detect from available PSDrives.

.PARAMETER CsvOutputPath
    Full path where the CSV audit report will be saved.
    Default: C:\Temp\DriverPackageAudit.csv

.PARAMETER VerboseOutput
    Enables detailed console output during execution.

.EXAMPLE
    .\CheckDriverPackages.ps1 -SiteCode 'P01'
    
    Runs the audit using site code P01 with default CSV output path.

.EXAMPLE
    .\CheckDriverPackages.ps1 -SiteCode 'PS1' -CsvOutputPath 'D:\Reports\DriverAudit.csv'
    
    Runs the audit with custom site code and output path.

.EXAMPLE
    .\CheckDriverPackages.ps1 -VerboseOutput
    
    Auto-detects site code and shows detailed progress information.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
    
    Creates a CSV file containing driver package audit results with columns:
    - PackageID: Driver package identifier
    - Name: Driver package name
    - SourcePath: Configured source path
    - PathExists: Boolean indicating if path is accessible
    - IsFolderEmpty: Boolean indicating if folder is empty (null if path doesn't exist)
    - Status: Summary status message

.NOTES
    Author: Configuration Manager Administrator
    Requires: PowerShell 5.1 or higher
    Requires: ConfigMgr Console installed
    Requires: ConfigMgr PowerShell module (ConfigurationManager)
    Requires: Read permissions on SMS Provider
    Requires: Network access to all driver package source paths
    
    The account running this script must have:
    - ConfigMgr read permissions
    - Access to driver package source locations (UNC paths or local drives)
    - Write permissions to the CSV output directory

.LINK
    https://docs.microsoft.com/en-us/mem/configmgr/

#>

[CmdletBinding()]
[OutputType([System.IO.FileInfo])]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$SiteCode,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$CsvOutputPath = 'C:\Temp\DriverPackageAudit.csv',

    [Parameter(Mandatory = $false)]
    [switch]$VerboseOutput
)

#region Initialization

# Set strict mode for better error detection
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Enable verbose output if requested
if ($VerboseOutput) {
    $VerbosePreference = 'Continue'
}

Write-Verbose -Message '========================================='
Write-Verbose -Message 'ConfigMgr Driver Package Audit'
Write-Verbose -Message '========================================='

#endregion Initialization

#region ConfigMgr Module and Connection

try {
    Write-Verbose -Message 'Loading ConfigMgr module...'
    
    # Check if module is already loaded
    if (-not (Get-Module -Name ConfigurationManager)) {
        # Locate ConfigMgr module using SMS_ADMIN_UI_PATH environment variable
        if (-not $env:SMS_ADMIN_UI_PATH) {
            throw 'SMS_ADMIN_UI_PATH environment variable not found. Ensure ConfigMgr Console is installed.'
        }
        
        $adminConsolePath = Split-Path -Path $env:SMS_ADMIN_UI_PATH -Parent
        $moduleManifest = Join-Path -Path $adminConsolePath -ChildPath 'ConfigurationManager.psd1'
        
        if (-not (Test-Path -Path $moduleManifest)) {
            throw "ConfigMgr module manifest not found at: $moduleManifest"
        }
        
        Import-Module -Name $moduleManifest -ErrorAction Stop
        Write-Verbose -Message 'ConfigMgr module loaded successfully'
    }
    else {
        Write-Verbose -Message 'ConfigMgr module already loaded'
    }
    
    # Determine site code if not provided
    if (-not $SiteCode) {
        Write-Verbose -Message 'Site code not specified, attempting auto-detection...'
        
        $cmPSDrive = Get-PSDrive -PSProvider CMSite -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if ($cmPSDrive) {
            $SiteCode = "$($cmPSDrive.Name):"
            Write-Verbose -Message "Auto-detected site code: $SiteCode"
        }
        else {
            throw 'No site code specified and auto-detection failed. No CMSite PSDrive found.'
        }
    }
    else {
        # Ensure site code has colon suffix
        if ($SiteCode -notmatch ':$') {
            $SiteCode = "${SiteCode}:"
        }
    }
    
    # Connect to ConfigMgr site
    $currentLocation = Get-Location
    Set-Location -Path $SiteCode -ErrorAction Stop
    Write-Host "Connected to ConfigMgr site: $SiteCode" -ForegroundColor Green
    
}
catch {
    Write-Error -Message "Failed to load ConfigMgr module or connect to site: $_"
    exit 1
}

#endregion ConfigMgr Module and Connection

#region Driver Package Retrieval

try {
    Write-Verbose -Message 'Retrieving driver packages...'
    
    $driverPackages = Get-CMDriverPackage -ErrorAction Stop
    $packageCount = @($driverPackages).Count
    
    Write-Host "Found $packageCount driver package(s) to audit" -ForegroundColor Cyan
    Write-Verbose -Message "Retrieved $packageCount driver packages"
    
    if ($packageCount -eq 0) {
        Write-Warning -Message 'No driver packages found in the site. Exiting.'
        Set-Location -Path $currentLocation
        exit 0
    }
}
catch {
    Write-Error -Message "Failed to retrieve driver packages: $_"
    Set-Location -Path $currentLocation
    exit 1
}

#endregion Driver Package Retrieval

#region Driver Package Validation

Write-Verbose -Message 'Beginning driver package validation...'

$auditResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($package in $driverPackages) {
    $sourcePath = $package.PkgSourcePath
    $packageId = $package.PackageID
    $packageName = $package.Name
    
    Write-Verbose -Message "Processing package: $packageName ($packageId)"
    
    # Initialize validation variables
    $pathExists = $false
    $isFolderEmpty = $null
    $statusInfo = 'OK'
    
    # Validate source path
    if ([string]::IsNullOrWhiteSpace($sourcePath)) {
        $statusInfo = 'ERROR: Source path is empty in ConfigMgr'
        Write-Warning -Message "  $packageName - Source path not configured"
    }
    else {
        # Construct testable path with FileSystem provider prefix
        $testablePath = if ($sourcePath -match '^\\\\') {
            # UNC path
            "FileSystem::$sourcePath"
        }
        elseif ($sourcePath -match '^[a-zA-Z]:') {
            # Local drive path
            "FileSystem::$sourcePath"
        }
        else {
            # Unknown format, try as-is
            $sourcePath
        }
        
        Write-Verbose -Message "  Testing path: $testablePath"
        
        # Test path existence
        if (Test-Path -LiteralPath $testablePath -PathType Container) {
            $pathExists = $true
            
            # Check if folder is empty
            try {
                $folderContent = Get-ChildItem -LiteralPath $testablePath -Force -ErrorAction Stop |
                    Select-Object -First 1
                
                if ($folderContent) {
                    $isFolderEmpty = $false
                    Write-Verbose -Message "  Path exists and contains files"
                }
                else {
                    $isFolderEmpty = $true
                    $statusInfo = 'WARNING: Directory is empty'
                    Write-Warning -Message "  $packageName - Directory is empty"
                }
            }
            catch {
                $isFolderEmpty = $null
                $statusInfo = "WARNING: Cannot enumerate directory contents: $_"
                Write-Warning -Message "  $packageName - Cannot read directory: $_"
            }
        }
        else {
            $pathExists = $false
            $statusInfo = 'ERROR: Directory not found or access denied'
            Write-Warning -Message "  $packageName - Path does not exist or access denied"
        }
    }
    
    # Create audit result object
    $auditResult = [PSCustomObject]@{
        PackageID     = $packageId
        Name          = $packageName
        SourcePath    = $sourcePath
        PathExists    = $pathExists
        IsFolderEmpty = $isFolderEmpty
        Status        = $statusInfo
    }
    
    $auditResults.Add($auditResult)
}

#endregion Driver Package Validation

#region CSV Export

try {
    Write-Verbose -Message "Exporting results to CSV: $CsvOutputPath"
    
    # Ensure output directory exists
    $outputDirectory = Split-Path -Path $CsvOutputPath -Parent
    
    if ($outputDirectory -and -not (Test-Path -Path $outputDirectory)) {
        $null = New-Item -Path $outputDirectory -ItemType Directory -Force
        Write-Verbose -Message "Created output directory: $outputDirectory"
    }
    
    # Export to CSV
    $auditResults | Export-Csv -Path $CsvOutputPath -NoTypeInformation -Encoding UTF8 -Delimiter ';' -Force
    
    Write-Host "`nAudit complete!" -ForegroundColor Green
    Write-Host "Results exported to: $CsvOutputPath" -ForegroundColor Cyan
    
    # Display summary statistics
    $totalPackages = $auditResults.Count
    $packagesWithIssues = $auditResults | Where-Object { $_.Status -ne 'OK' }
    $missingPaths = $auditResults | Where-Object { -not $_.PathExists }
    $emptyFolders = $auditResults | Where-Object { $_.IsFolderEmpty -eq $true }
    
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "  Total packages:        $totalPackages"
    Write-Host "  Packages with issues:  $($packagesWithIssues.Count)" -ForegroundColor $(if ($packagesWithIssues.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Missing paths:         $($missingPaths.Count)" -ForegroundColor $(if ($missingPaths.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Empty directories:     $($emptyFolders.Count)" -ForegroundColor $(if ($emptyFolders.Count -gt 0) { 'Yellow' } else { 'Green' })
    
}
catch {
    Write-Error -Message "Failed to export CSV: $_"
    Set-Location -Path $currentLocation
    exit 1
}

#endregion CSV Export

#region Cleanup

# Return to original location
Set-Location -Path $currentLocation
Write-Verbose -Message 'Returned to original location'

#endregion Cleanup
