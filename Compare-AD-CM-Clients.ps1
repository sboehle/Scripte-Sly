<#
.SYNOPSIS
    Compares active ConfigMgr clients with Active Directory computer objects.

.DESCRIPTION
    Validates that ConfigMgr clients have corresponding Active Directory computer accounts.
    Identifies clients that are:
    - Missing from Active Directory
    - Present in AD but disabled
    - Present in AD and enabled
    
    Queries ConfigMgr via WMI (SMS Provider) and validates against Active Directory using
    either the ActiveDirectory PowerShell module or ADSI fallback for compatibility.
    
    Generates a detailed CSV report and optional CMTrace-compatible log file.

.PARAMETER SiteServer
    SMS Provider server name (typically the Primary Site Server).

.PARAMETER SiteCode
    ConfigMgr site code (e.g., 'P01', 'PS1').

.PARAMETER CollectionId
    Optional: Limit the check to clients in a specific collection.
    Example: 'SMS00001' for All Systems collection.

.PARAMETER ADSearchBase
    Optional: LDAP search base to limit AD search scope.
    Example: 'OU=Workstations,OU=HQ,DC=contoso,DC=com'
    If not specified, searches entire domain.

.PARAMETER IncludeDisabledAD
    When specified, disabled AD computer accounts are treated as 'FoundInAD' instead of 'ADDisabled'.
    Use this to focus only on missing computers, not disabled ones.

.PARAMETER OutputCsv
    Optional: Path where CSV report will be saved.
    If not specified, results are only displayed on console.

.PARAMETER LogPath
    Optional: Path for CMTrace-compatible log file.
    If not specified, minimal logging to console only.

.EXAMPLE
    .\Compare-AD-CM-Clients.ps1 -SiteServer 'CM01' -SiteCode 'P01' -OutputCsv '.\CM_vs_AD.csv'
    
    Compares all active clients against entire AD domain and exports to CSV.

.EXAMPLE
    .\Compare-AD-CM-Clients.ps1 -SiteServer 'CM01' -SiteCode 'P01' -CollectionId 'SMS00001' -ADSearchBase 'OU=Workstations,DC=contoso,DC=com' -LogPath '.\Compare.log'
    
    Compares clients in All Systems collection against specific OU with detailed logging.

.EXAMPLE
    .\Compare-AD-CM-Clients.ps1 -SiteServer 'CM01' -SiteCode 'P01' -IncludeDisabledAD -OutputCsv '.\Report.csv'
    
    Compares clients but treats disabled AD accounts as valid (focus on missing computers only).

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject[]
    
    Returns array of objects with properties:
    - CM_Name: Client name from ConfigMgr
    - CM_ResourceId: ConfigMgr resource ID
    - CM_Client: Client installed flag
    - CM_Active: Active status in ConfigMgr
    - CM_ClientVersion: ConfigMgr client version
    - AD_Status: FoundInAD, MissingInAD, or ADDisabled
    - AD_Enabled: AD account enabled status
    - AD_DNSHostName: DNS hostname from AD
    - AD_LastLogonTimestamp: Last logon timestamp from AD

.NOTES
    Author: Configuration Manager Administrator
    Requires: PowerShell 5.1 or higher
    Requires: Read access to SMS Provider (WMI)
    Requires: Read access to Active Directory
    Optional: ActiveDirectory PowerShell module (RSAT-AD-PowerShell feature)
    
    If ActiveDirectory module is not available, script uses ADSI fallback.
    
    The account running this script must have:
    - ConfigMgr read permissions (SMS Provider WMI access)
    - Active Directory read permissions
    - Network connectivity to SMS Provider and AD

.LINK
    https://docs.microsoft.com/en-us/mem/configmgr/

#>

[CmdletBinding()]
[OutputType([System.Management.Automation.PSCustomObject[]])]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SiteServer,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SiteCode,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$CollectionId,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ADSearchBase,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabledAD,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputCsv,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$LogPath
)

#region Helper Functions

<#
.SYNOPSIS
    Writes a CMTrace-compatible log entry.

.DESCRIPTION
    Creates log entries in CMTrace format with timestamp, severity, and component information.
    If no log file is specified, outputs to console.

.PARAMETER Message
    Log message content.

.PARAMETER Severity
    Log severity level: INFO, WARN, or ERROR.

.PARAMETER Component
    Component name for log entry identification.

.PARAMETER LogFile
    Path to log file (uses script-level variable if not specified).

.EXAMPLE
    Write-CMTraceLog -Message "Processing client" -Severity INFO
#>
function Write-CMTraceLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Severity = 'INFO',

        [Parameter(Mandatory = $false)]
        [string]$Component = 'Compare-AD-CM-Clients',

        [Parameter(Mandatory = $false)]
        [string]$LogFile = $script:CurrentLog
    )

    try {
        $timestamp = Get-Date -Format 'HH:mm:ss.fff'
        $date = Get-Date -Format 'MM-dd-yyyy'
        $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        
        # CMTrace severity codes: 1=INFO, 2=WARN, 3=ERROR
        $severityCode = switch ($Severity) {
            'INFO' { 1 }
            'WARN' { 2 }
            'ERROR' { 3 }
            default { 1 }
        }
        
        # CMTrace log format
        $logLine = "<![LOG[$Message]LOG]!><time=`"$timestamp`" date=`"$date`" component=`"$Component`" context=`"`" type=`"$severityCode`" thread=`"$threadId`" file=`"`">"
        
        if ($LogFile) {
            Add-Content -Path $LogFile -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        
        # Console output with color
        switch ($Severity) {
            'INFO' { Write-Verbose -Message $Message }
            'WARN' { Write-Warning -Message $Message }
            'ERROR' { Write-Error -Message $Message }
        }
    }
    catch {
        Write-Warning -Message "Logging failed: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Retrieves AD computer object by name with fallback methods.

.DESCRIPTION
    Attempts to find AD computer using:
    1. ActiveDirectory module (if available)
    2. ADSI DirectorySearcher fallback
    
    Searches by sAMAccountName, Name, and DNSHostName attributes.

.PARAMETER ComputerName
    Computer name to search for in Active Directory.

.PARAMETER SearchBase
    Optional LDAP search base to limit search scope.

.EXAMPLE
    $computer = Get-ADComputerSafe -ComputerName 'WS001' -SearchBase 'OU=Workstations,DC=contoso,DC=com'
#>
function Get-ADComputerSafe {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [string]$SearchBase
    )

    if ($script:UseADModule) {
        # Use ActiveDirectory module
        try {
            # Try sAMAccountName first (most reliable)
            $samAccountName = "${ComputerName}$"
            
            try {
                $computer = Get-ADComputer -Identity $samAccountName -Properties Enabled, DNSHostName, LastLogonTimestamp -ErrorAction Stop
                if ($computer) {
                    return $computer
                }
            }
            catch {
                # Identity lookup failed, try LDAP filter
            }
            
            # Fallback: LDAP filter search
            $filter = "(&(objectClass=computer)(|(name=$ComputerName)(dNSHostName=$ComputerName)(sAMAccountName=$samAccountName)))"
            $searchParams = @{
                LDAPFilter = $filter
                Properties = @('Enabled', 'DNSHostName', 'LastLogonTimestamp')
            }
            
            if ($SearchBase) {
                $searchParams['SearchBase'] = $SearchBase
            }
            
            $computer = Get-ADComputer @searchParams -ErrorAction Stop | Select-Object -First 1
            return $computer
        }
        catch {
            return $null
        }
    }
    else {
        # Use ADSI DirectorySearcher fallback
        try {
            # Determine LDAP root
            $ldapRoot = if ($SearchBase) {
                "LDAP://$SearchBase"
            }
            else {
                # Get default naming context from RootDSE
                $rootDSE = [ADSI]'LDAP://RootDSE'
                $defaultNamingContext = $rootDSE.defaultNamingContext
                "LDAP://$defaultNamingContext"
            }
            
            # Create directory entry and searcher
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapRoot)
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
            $searcher.PageSize = 1000
            $searcher.Filter = "(&(objectClass=computer)(|(name=$ComputerName)(dNSHostName=$ComputerName)))"
            $searcher.PropertiesToLoad.AddRange(@('name', 'dNSHostName', 'userAccountControl', 'lastLogonTimestamp')) | Out-Null
            
            $searchResult = $searcher.FindOne()
            
            if ($null -eq $searchResult) {
                return $null
            }
            
            # Build result object
            $computer = [PSCustomObject]@{
                Name                 = $searchResult.Properties['name'][0]
                DNSHostName          = if ($searchResult.Properties.Contains('dNSHostName')) { $searchResult.Properties['dNSHostName'][0] } else { $null }
                Enabled              = $true
                LastLogonTimestamp   = $null
            }
            
            # Parse userAccountControl for Enabled status
            if ($searchResult.Properties.Contains('useraccountcontrol')) {
                $uac = [int]$searchResult.Properties['useraccountcontrol'][0]
                # 0x0002 = ACCOUNTDISABLE flag
                $computer.Enabled = -not (($uac -band 0x0002) -eq 0x0002)
            }
            
            # Parse lastLogonTimestamp
            if ($searchResult.Properties.Contains('lastlogontimestamp')) {
                $llt = [long]$searchResult.Properties['lastlogontimestamp'][0]
                $computer.LastLogonTimestamp = $llt
            }
            
            return $computer
        }
        catch {
            Write-CMTraceLog -Message "ADSI search failed: $($_.Exception.Message)" -Severity WARN
            return $null
        }
    }
}

#endregion Helper Functions

#region Initialization

# Initialize script-level variables
$script:CurrentLog = $null
$script:UseADModule = $false

# Set verbose preference
$VerbosePreference = 'Continue'

# Initialize log file if specified
if ($LogPath) {
    try {
        $logDirectory = Split-Path -Path $LogPath -Parent
        
        if ($logDirectory -and -not (Test-Path -Path $logDirectory)) {
            $null = New-Item -Path $logDirectory -ItemType Directory -Force
        }
        
        $script:CurrentLog = $LogPath
        Write-CMTraceLog -Message '==========================================' -Severity INFO
        Write-CMTraceLog -Message 'ConfigMgr to AD Client Comparison' -Severity INFO
        Write-CMTraceLog -Message '==========================================' -Severity INFO
        Write-CMTraceLog -Message "Log initialized: $script:CurrentLog" -Severity INFO
    }
    catch {
        Write-Warning -Message "Failed to initialize log file: $_"
    }
}

Write-CMTraceLog -Message "Parameters: SiteServer=$SiteServer, SiteCode=$SiteCode, CollectionId=$CollectionId, ADSearchBase=$ADSearchBase, IncludeDisabledAD=$($IncludeDisabledAD.IsPresent)" -Severity INFO

#endregion Initialization

#region Active Directory Module Detection

try {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module -Name ActiveDirectory -ErrorAction Stop
        $script:UseADModule = $true
        Write-CMTraceLog -Message 'ActiveDirectory PowerShell module loaded successfully' -Severity INFO
    }
    else {
        Write-CMTraceLog -Message 'ActiveDirectory module not available. Using ADSI fallback for AD queries.' -Severity WARN
    }
}
catch {
    Write-CMTraceLog -Message "Failed to load ActiveDirectory module: $($_.Exception.Message). Using ADSI fallback." -Severity WARN
}

#endregion Active Directory Module Detection

#region ConfigMgr Connection and Client Query

$namespace = "root\SMS\site_$SiteCode"
Write-CMTraceLog -Message "Connecting to SMS Provider: \\$SiteServer\$namespace" -Severity INFO

try {
    # Create WMI connection scope
    $scope = New-Object System.Management.ManagementScope("\\$SiteServer\$namespace")
    $scope.Connect()
    Write-CMTraceLog -Message "Connected to SMS Provider successfully" -Severity INFO
}
catch {
    $errorMessage = "Failed to connect to SMS Provider: $($_.Exception.Message)"
    Write-CMTraceLog -Message $errorMessage -Severity ERROR
    throw $errorMessage
}

# Build WQL query for ConfigMgr clients
if ([string]::IsNullOrWhiteSpace($CollectionId)) {
    # Query all active clients
    $wqlQuery = @"
SELECT Name, ResourceId, SMSUniqueIdentifier, Client, Active, ClientType, ClientVersion, LastLogonTimestamp
FROM SMS_R_System
WHERE Client = 1 AND Active = 1
"@
    Write-CMTraceLog -Message "Query mode: All active clients" -Severity INFO
}
else {
    # Query clients in specific collection
    $wqlQuery = @"
SELECT s.Name, s.ResourceId, s.SMSUniqueIdentifier, s.Client, s.Active, s.ClientType, s.ClientVersion, s.LastLogonTimestamp
FROM SMS_R_System AS s
JOIN SMS_FullCollectionMembership AS f ON s.ResourceId = f.ResourceId
WHERE s.Client = 1 AND s.Active = 1 AND f.CollectionID = '$CollectionId'
"@
    Write-CMTraceLog -Message "Query mode: Collection $CollectionId" -Severity INFO
}

Write-CMTraceLog -Message "Executing WQL query..." -Severity INFO

try {
    $query = New-Object System.Management.ObjectQuery($wqlQuery)
    $searcher = New-Object System.Management.ManagementObjectSearcher($scope, $query)
    $configMgrClients = $searcher.Get()
    $clientCount = @($configMgrClients).Count
    
    Write-CMTraceLog -Message "Retrieved $clientCount ConfigMgr client(s)" -Severity INFO
    Write-Host "Found $clientCount ConfigMgr client(s) to validate" -ForegroundColor Cyan
}
catch {
    $errorMessage = "Failed to query ConfigMgr clients: $($_.Exception.Message)"
    Write-CMTraceLog -Message $errorMessage -Severity ERROR
    throw $errorMessage
}

if ($clientCount -eq 0) {
    Write-CMTraceLog -Message "No clients found. Exiting." -Severity WARN
    exit 0
}

#endregion ConfigMgr Connection and Client Query

#region Client Comparison Loop

Write-CMTraceLog -Message "Beginning Active Directory validation..." -Severity INFO

$comparisonResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$progressCounter = 0

foreach ($client in $configMgrClients) {
    $progressCounter++
    
    # Extract client properties
    $clientName = $client.Properties['Name'].Value
    $resourceId = $client.Properties['ResourceId'].Value
    $clientInstalled = $client.Properties['Client'].Value
    $clientActive = $client.Properties['Active'].Value
    $clientVersion = $client.Properties['ClientVersion'].Value
    
    # Progress indicator
    if ($progressCounter % 50 -eq 0) {
        Write-Host "Progress: $progressCounter / $clientCount clients processed..." -ForegroundColor Yellow
    }
    
    Write-CMTraceLog -Message "Checking client: $clientName (ResourceId: $resourceId)" -Severity INFO
    
    # Try to resolve DNS name from ConfigMgr data
    $dnsName = $null
    try {
        if ($client.Properties.Contains('FullDomainName')) {
            $dnsName = $client.Properties['FullDomainName'].Value
        }
    }
    catch {
        # Property not available
    }
    
    # Search Active Directory
    $adComputer = $null
    
    # Try DNS name first (more reliable in multi-domain environments)
    if ($dnsName) {
        $adComputer = Get-ADComputerSafe -ComputerName $dnsName -SearchBase $ADSearchBase
    }
    
    # Fallback to NetBIOS name
    if (-not $adComputer) {
        $adComputer = Get-ADComputerSafe -ComputerName $clientName -SearchBase $ADSearchBase
    }
    
    # Determine AD status
    $adStatus = 'MissingInAD'
    $adEnabled = $null
    $adDnsHostName = $null
    $adLastLogon = $null
    
    if ($adComputer) {
        # Extract AD properties
        $adEnabled = if ($adComputer.PSObject.Properties.Name -contains 'Enabled') {
            [bool]$adComputer.Enabled
        }
        else {
            $null
        }
        
        $adDnsHostName = if ($adComputer.PSObject.Properties.Name -contains 'DNSHostName') {
            [string]$adComputer.DNSHostName
        }
        else {
            $null
        }
        
        # Convert LastLogonTimestamp to DateTime
        if ($adComputer.PSObject.Properties.Name -contains 'LastLogonTimestamp' -and $adComputer.LastLogonTimestamp) {
            try {
                if ($adComputer.LastLogonTimestamp -is [long]) {
                    $adLastLogon = [DateTime]::FromFileTime($adComputer.LastLogonTimestamp)
                }
                else {
                    $adLastLogon = $adComputer.LastLogonTimestamp
                }
            }
            catch {
                $adLastLogon = $null
            }
        }
        
        # Determine status based on enabled flag
        if (-not $IncludeDisabledAD.IsPresent -and $adEnabled -eq $false) {
            $adStatus = 'ADDisabled'
            Write-CMTraceLog -Message "  $clientName => AD account is DISABLED" -Severity WARN
        }
        else {
            $adStatus = 'FoundInAD'
            Write-CMTraceLog -Message "  $clientName => Found in AD (Enabled: $adEnabled)" -Severity INFO
        }
    }
    else {
        Write-CMTraceLog -Message "  $clientName => NOT FOUND in Active Directory" -Severity WARN
    }
    
    # Create result object
    $resultObject = [PSCustomObject]@{
        CM_Name               = $clientName
        CM_ResourceId         = $resourceId
        CM_Client             = $clientInstalled
        CM_Active             = $clientActive
        CM_ClientVersion      = $clientVersion
        AD_Status             = $adStatus
        AD_Enabled            = $adEnabled
        AD_DNSHostName        = $adDnsHostName
        AD_LastLogonTimestamp = $adLastLogon
    }
    
    $comparisonResults.Add($resultObject)
}

#endregion Client Comparison Loop

#region Output Results

Write-CMTraceLog -Message '==========================================' -Severity INFO
Write-CMTraceLog -Message "Comparison complete. Total clients: $($comparisonResults.Count)" -Severity INFO

# Calculate summary statistics
$foundInAD = $comparisonResults | Where-Object { $_.AD_Status -eq 'FoundInAD' }
$missingInAD = $comparisonResults | Where-Object { $_.AD_Status -eq 'MissingInAD' }
$adDisabled = $comparisonResults | Where-Object { $_.AD_Status -eq 'ADDisabled' }

Write-Host "`nComparison Summary:" -ForegroundColor Yellow
Write-Host "  Total clients checked:  $($comparisonResults.Count)"
Write-Host "  Found in AD:            $($foundInAD.Count)" -ForegroundColor Green
Write-Host "  Missing in AD:          $($missingInAD.Count)" -ForegroundColor $(if ($missingInAD.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "  AD disabled:            $($adDisabled.Count)" -ForegroundColor $(if ($adDisabled.Count -gt 0) { 'Yellow' } else { 'Green' })

Write-CMTraceLog -Message "Summary - Found: $($foundInAD.Count), Missing: $($missingInAD.Count), Disabled: $($adDisabled.Count)" -Severity INFO

# Export to CSV if specified
if ($OutputCsv) {
    try {
        $csvDirectory = Split-Path -Path $OutputCsv -Parent
        
        if ($csvDirectory -and -not (Test-Path -Path $csvDirectory)) {
            $null = New-Item -Path $csvDirectory -ItemType Directory -Force
        }
        
        $comparisonResults | Sort-Object -Property CM_Name | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -Force
        
        Write-CMTraceLog -Message "CSV report exported to: $OutputCsv" -Severity INFO
        Write-Host "`nCSV report saved to: $OutputCsv" -ForegroundColor Cyan
    }
    catch {
        Write-CMTraceLog -Message "Failed to export CSV: $($_.Exception.Message)" -Severity ERROR
        Write-Warning -Message "Failed to export CSV: $_"
    }
}

# Display results to console
Write-Host "`nDetailed Results:" -ForegroundColor Yellow
$comparisonResults | Sort-Object -Property CM_Name | Format-Table -AutoSize

Write-CMTraceLog -Message '==========================================' -Severity INFO
Write-CMTraceLog -Message 'Comparison complete' -Severity INFO

# Return results
return $comparisonResults

#endregion Output Results
