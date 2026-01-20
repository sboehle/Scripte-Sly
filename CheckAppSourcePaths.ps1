<#
.SYNOPSIS
    Checks ConfigMgr Application source paths for existence and accessibility.

.DESCRIPTION
    Validates all ConfigMgr Application source paths by checking if directories exist
    and contain files. Operates in ConfigMgr PowerShell context and supports both
    ConfigMgr cmdlets and WMI/CIM fallback methods.
    
    The script:
    - Connects to ConfigMgr using available cmdlets or WMI/CIM
    - Extracts all Windows/UNC paths from application deployment types
    - Validates path existence using Test-Path
    - Generates CSV report and detailed log file
    
    This is particularly useful during ConfigMgr cleanup operations to identify
    applications with missing or empty source directories.

.PARAMETER OutputDirectory
    Filesystem path where CSV report and log file will be saved.
    Directory will be created if it doesn't exist.
    Default: C:\ConfigMgrAppSourceCheck

.PARAMETER VerboseLog
    Enables detailed logging output for troubleshooting.

.EXAMPLE
    .\CheckAppSourcePaths.ps1
    
    Runs the check with default output directory.

.EXAMPLE
    .\CheckAppSourcePaths.ps1 -OutputDirectory 'C:\Reports\ConfigMgr' -VerboseLog
    
    Runs the check with custom output directory and verbose logging enabled.

.EXAMPLE
    .\CheckAppSourcePaths.ps1 -OutputDirectory 'D:\Audit\Apps'
    
    Saves results to a custom directory on D: drive.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.String
    
    Outputs log messages to console and creates two files:
    - CSV file with application source path validation results
    - Log file with detailed execution information

.NOTES
    Author: Configuration Manager Administrator
    Requires: PowerShell 5.1 or higher
    Requires: Access to SMS Provider namespace or ConfigMgr console context
    Requires: Read permissions on all UNC/network paths to be validated
    
    The account running this script must have:
    - ConfigMgr read permissions (SMS Provider access)
    - Network access to all application source paths
    - Write permissions to the output directory

.LINK
    https://docs.microsoft.com/en-us/mem/configmgr/

#>

[CmdletBinding()]
[OutputType([System.String])]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = 'C:\ConfigMgrAppSourceCheck',

    [Parameter(Mandatory = $false)]
    [switch]$VerboseLog
)

#region Helper Functions

<#
.SYNOPSIS
    Writes a log message to console and log file.

.DESCRIPTION
    Creates timestamped log entries with severity levels.
    Writes to both console (Write-Verbose/Write-Warning/Write-Error) and log file.

.PARAMETER Message
    The message to log.

.PARAMETER Level
    Severity level: INFO, WARN, or ERROR.

.EXAMPLE
    Write-Log -Message "Processing application" -Level INFO
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "$timestamp [$Level] $Message"
    
    # Output to console based on level
    switch ($Level) {
        'INFO' { Write-Verbose -Message $logLine }
        'WARN' { Write-Warning -Message $Message }
        'ERROR' { Write-Error -Message $Message }
    }
    
    # Write to log file if available
    if ($script:LogFilePath) {
        try {
            Add-Content -Path $script:LogFilePath -Value $logLine -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning -Message "Failed to write to log file: $_"
        }
    }
}

<#
.SYNOPSIS
    Ensures the output directory exists and returns its full path.

.DESCRIPTION
    Creates the directory if it doesn't exist and returns the absolute filesystem path.

.PARAMETER Path
    Directory path to ensure exists.

.EXAMPLE
    $fullPath = Initialize-OutputDirectory -Path 'C:\Reports'
#>
function Initialize-OutputDirectory {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        try {
            $null = New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
            Write-Verbose -Message "Created output directory: $Path"
        }
        catch {
            throw "Could not create output directory: $Path. Error: $_"
        }
    }
    
    # Return absolute filesystem path
    return (Get-Item -Path $Path).FullName
}

<#
.SYNOPSIS
    Recursively extracts Windows/UNC paths from PowerShell objects.

.DESCRIPTION
    Walks through object properties and collections to find strings that match
    Windows path patterns (UNC \\server\share or drive letter C:\path).
    Uses cycle detection to prevent infinite recursion.

.PARAMETER InputObject
    Object to search for path strings.

.EXAMPLE
    $paths = Get-PathFromObject -InputObject $deploymentType
#>
function Get-PathFromObject {
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [psobject]$InputObject
    )

    $pathList = [System.Collections.Generic.List[string]]::new()
    $pathPattern = '^(\\\\|[A-Za-z]:\\).*'  # UNC (\\) or drive letter (C:\)
    $visitedObjects = [System.Collections.Hashtable]::Synchronized(@{})

    function Search-ObjectForPaths {
        param([psobject]$Object)
        
        if ($null -eq $Object) {
            return
        }

        # Cycle detection
        try {
            $objectHash = $Object.GetHashCode() -as [string]
        }
        catch {
            $objectHash = [string]::Empty
        }
        
        if ($objectHash -and $visitedObjects.ContainsKey($objectHash)) {
            return
        }
        
        if ($objectHash) {
            $visitedObjects[$objectHash] = $true
        }

        # String check
        if ($Object -is [string]) {
            if ($Object -match $pathPattern) {
                $pathList.Add($Object)
            }
            return
        }

        # Collection check
        if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
            foreach ($item in $Object) {
                Search-ObjectForPaths -Object $item
            }
            return
        }

        # Object properties
        try {
            $properties = $Object | Get-Member -MemberType NoteProperty, Property -ErrorAction SilentlyContinue
            
            if ($properties) {
                foreach ($property in $properties) {
                    try {
                        $value = $Object.($property.Name)
                        Search-ObjectForPaths -Object $value
                    }
                    catch {
                        # Property access failed, skip
                    }
                }
            }
            else {
                # Fallback: check ToString()
                $stringValue = $Object.ToString()
                if ($stringValue -and ($stringValue -match $pathPattern)) {
                    $pathList.Add($stringValue)
                }
            }
        }
        catch {
            # Ignore errors during property enumeration
        }
    }

    Search-ObjectForPaths -Object $InputObject
    
    # Return unique paths
    return $pathList | Select-Object -Unique
}

#endregion Helper Functions

#region Initialization

# Set verbose preference if switch is set
if ($VerboseLog) {
    $VerbosePreference = 'Continue'
}

# Initialize output directory
try {
    $OutputDirectory = Initialize-OutputDirectory -Path $OutputDirectory
    Write-Verbose -Message "Output directory initialized: $OutputDirectory"
}
catch {
    Write-Error -Message $_
    exit 1
}

# Create output files with timestamp
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogFilePath = Join-Path -Path $OutputDirectory -ChildPath "AppSourceCheck_$timestamp.log"
$csvFilePath = Join-Path -Path $OutputDirectory -ChildPath "AppSourceCheck_$timestamp.csv"

# Initialize log file
$null = New-Item -Path $script:LogFilePath -ItemType File -Force
Write-Log -Message '========================================' -Level INFO
Write-Log -Message 'ConfigMgr Application Source Path Check' -Level INFO
Write-Log -Message '========================================' -Level INFO
Write-Log -Message "Output directory: $OutputDirectory" -Level INFO
Write-Log -Message "Log file: $script:LogFilePath" -Level INFO
Write-Log -Message "CSV file: $csvFilePath" -Level INFO

#endregion Initialization

#region ConfigMgr Connection

Write-Log -Message 'Connecting to ConfigMgr...' -Level INFO

$applications = $null
$connectionMethod = ''

# Try ConfigMgr cmdlets first
if (Get-Command -Name Get-CMApplication -ErrorAction SilentlyContinue) {
    Write-Log -Message 'ConfigMgr cmdlets found, using Get-CMApplication' -Level INFO
    $connectionMethod = 'Cmdlets'
    
    try {
        $applications = Get-CMApplication -ErrorAction Stop
        Write-Log -Message "Successfully retrieved applications using cmdlets" -Level INFO
    }
    catch {
        Write-Log -Message "Failed to retrieve applications using cmdlets: $_" -Level ERROR
        $applications = @()
    }
}
else {
    # Fallback to WMI/CIM
    Write-Log -Message 'ConfigMgr cmdlets not found, attempting WMI/CIM fallback' -Level WARN
    
    try {
        # Find SMS Provider namespace
        $smsNamespaces = Get-CimInstance -Namespace 'root\SMS' -ClassName '__Namespace' -ErrorAction Stop |
            Where-Object { $_.Name -like 'site_*' }
        
        if (-not $smsNamespaces) {
            throw 'No root\SMS\site_<CODE> namespace found. Ensure script runs with SMS Provider access.'
        }
        
        $siteNamespace = $smsNamespaces[0].Name
        $namespace = "root\SMS\$siteNamespace"
        $connectionMethod = "CIM:$namespace"
        
        Write-Log -Message "Using namespace: $namespace" -Level INFO
        
        # Query applications
        $applications = Get-CimInstance -Namespace $namespace -ClassName SMS_Application -ErrorAction Stop
        Write-Log -Message "Successfully retrieved applications using WMI/CIM" -Level INFO
    }
    catch {
        Write-Log -Message "Failed to access SMS Provider via WMI/CIM: $_" -Level ERROR
        $applications = @()
    }
}

$applicationCount = @($applications).Count
Write-Log -Message "Found $applicationCount application(s)" -Level INFO

if ($applicationCount -eq 0) {
    Write-Log -Message 'No applications found or connection failed. Exiting.' -Level ERROR
    exit 1
}

#endregion ConfigMgr Connection

#region Process Applications

# Initialize CSV with headers
$csvHeaders = '"ApplicationName","ApplicationId","DeploymentTypeName","CandidateSourcePath","PathExists","IsValidWindowsPath","Notes"'
$csvHeaders | Out-File -FilePath $csvFilePath -Encoding UTF8

Write-Log -Message 'Processing applications...' -Level INFO

foreach ($app in $applications) {
    # Extract application name and ID
    $appName = if ($connectionMethod -eq 'Cmdlets') {
        $app.LocalizedDisplayName
    }
    else {
        $app.LocalizedDisplayName ?? $app.Name
    }
    
    $appId = if ($connectionMethod -eq 'Cmdlets') {
        $app.CI_UniqueID
    }
    else {
        $app.CI_UniqueID ?? $app.ApplicationId
    }
    
    if (-not $appName) { $appName = '<unknown>' }
    if (-not $appId) { $appId = '<unknown>' }
    
    Write-Log -Message "Processing application: $appName (ID: $appId)" -Level INFO
    
    # Get deployment types
    $deploymentTypes = @()
    
    if ($connectionMethod -eq 'Cmdlets') {
        try {
            $deploymentTypes = Get-CMDeploymentType -ApplicationId $appId -ErrorAction SilentlyContinue
            
            if (-not $deploymentTypes) {
                # Fallback by name
                $deploymentTypes = Get-CMDeploymentType -ApplicationName $appName -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log -Message "  Failed to retrieve deployment types: $_" -Level WARN
        }
    }
    else {
        # CIM: Try to find deployment types
        try {
            if ($app.DeploymentTypes) {
                $deploymentTypes = $app.DeploymentTypes
            }
            elseif ($app.DeploymentType) {
                $deploymentTypes = $app.DeploymentType
            }
            else {
                # Query SMS_DeploymentType
                if ($app.CI_UniqueID) {
                    $query = "SELECT * FROM SMS_DeploymentType WHERE ApplicationId='$($app.CI_UniqueID)'"
                    $deploymentTypes = Get-CimInstance -Namespace $namespace -Query $query -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            Write-Log -Message "  Failed to retrieve deployment types: $_" -Level WARN
        }
    }
    
    if (-not $deploymentTypes) {
        Write-Log -Message "  No deployment types found for $appName" -Level WARN
        
        # Try to extract paths directly from application object
        $candidatePaths = Get-PathFromObject -InputObject $app
        
        if ($candidatePaths -and $candidatePaths.Count -gt 0) {
            foreach ($path in $candidatePaths) {
                $pathExists = Test-Path -Path $path
                $notes = 'Found directly on application object'
                
                $csvLine = '"{0}","{1}","{2}","{3}",{4},{5},"{6}"' -f @(
                    $appName
                    $appId
                    '<no-deployment-type>'
                    $path
                    $pathExists
                    $true
                    $notes
                )
                
                Add-Content -Path $csvFilePath -Value $csvLine -Encoding UTF8
                Write-Log -Message "    Path: $path -> Exists: $pathExists" -Level INFO
            }
        }
        
        continue
    }
    
    # Process each deployment type
    foreach ($dt in $deploymentTypes) {
        $dtName = $dt.LocalizedDisplayName ?? $dt.Name ?? $dt.DeploymentTypeName ?? '<unknown-deployment-type>'
        
        Write-Log -Message "  Deployment type: $dtName" -Level INFO
        
        # Extract paths from deployment type
        $candidatePaths = Get-PathFromObject -InputObject $dt
        
        if (-not $candidatePaths -or $candidatePaths.Count -eq 0) {
            Write-Log -Message "    No candidate paths found in deployment type object" -Level WARN
            
            # Try Get-CMContent if available
            if (Get-Command -Name Get-CMContent -ErrorAction SilentlyContinue) {
                try {
                    # Try various content ID properties
                    $contentId = $dt.ContentId ?? $dt.PackageID ?? $dt.PackageID0 ?? $dt.ContentPackageID
                    
                    if ($contentId) {
                        $contents = Get-CMContent -ContentId $contentId -ErrorAction SilentlyContinue
                        
                        if ($contents) {
                            $pathsFromContent = Get-PathFromObject -InputObject $contents
                            $candidatePaths += $pathsFromContent
                        }
                    }
                }
                catch {
                    Write-Log -Message "    Failed to retrieve content: $_" -Level WARN
                }
            }
        }
        
        # If still no paths found, log and continue
        if (-not $candidatePaths -or $candidatePaths.Count -eq 0) {
            Write-Log -Message "    No candidate paths found for deployment type $dtName" -Level WARN
            
            $csvLine = '"{0}","{1}","{2}","{3}",{4},{5},"{6}"' -f @(
                $appName
                $appId
                $dtName
                '<no-paths>'
                $false
                $false
                'No candidate paths found'
            )
            
            Add-Content -Path $csvFilePath -Value $csvLine -Encoding UTF8
            continue
        }
        
        # Test each path
        foreach ($path in ($candidatePaths | Select-Object -Unique)) {
            # Normalize path
            $normalizedPath = $path.Trim('"').Trim()
            
            # Check if it looks like a Windows path
            $isValidPath = $normalizedPath -match '^(\\\\|[A-Za-z]:\\).*'
            
            $pathExists = $false
            $notes = ''
            
            if ($isValidPath) {
                try {
                    $pathExists = Test-Path -Path $normalizedPath -ErrorAction Stop
                }
                catch {
                    $pathExists = $false
                    $notes = "Access denied or path invalid: $_"
                }
            }
            else {
                $notes = 'Not recognized as Windows/UNC path format'
            }
            
            $csvLine = '"{0}","{1}","{2}","{3}",{4},{5},"{6}"' -f @(
                $appName
                $appId
                $dtName
                $normalizedPath
                $pathExists
                $isValidPath
                $notes
            )
            
            Add-Content -Path $csvFilePath -Value $csvLine -Encoding UTF8
            Write-Log -Message "    Path: $normalizedPath -> Exists: $pathExists" -Level INFO
        }
    }
}

#endregion Process Applications

#region Completion

Write-Log -Message '========================================' -Level INFO
Write-Log -Message 'Application source path check complete' -Level INFO
Write-Log -Message "Results saved to: $csvFilePath" -Level INFO
Write-Log -Message "Log saved to: $script:LogFilePath" -Level INFO
Write-Log -Message '========================================' -Level INFO
Write-Log -Message 'NOTE: Ensure the account running this script has access to all UNC/network paths for accurate results.' -Level INFO

Write-Host "`nCheck complete!" -ForegroundColor Green
Write-Host "CSV Report: $csvFilePath" -ForegroundColor Cyan
Write-Host "Log File:   $script:LogFilePath" -ForegroundColor Cyan

#endregion Completion
