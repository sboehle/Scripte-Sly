<#
.SYNOPSIS
Vergleicht aktive ConfigMgr-Clients mit AD-Computerobjekten.

.DESCRIPTION
Liest per WMI (SMS Provider) alle aktiven Clients aus SMS_R_System (optional in einer Collection)
und prüft, ob es entsprechende AD-Computerobjekte gibt. Meldet fehlende oder deaktivierte AD-Konten.
Schreibt optional CSV und CMTrace-kompatibles Log.

.PARAMETER SiteServer
SMS Provider Server (z. B. Primärserver).

.PARAMETER SiteCode
Standortcode (z. B. P01).

.PARAMETER CollectionId
Optional: Collection-ID, um die Clients einzugrenzen.

.PARAMETER ADSearchBase
Optional: LDAP-Suchbasis (z. B. "OU=Clients,DC=contoso,DC=com"). Wenn leer, gesamte Domäne.

.PARAMETER IncludeDisabledAD
Wenn gesetzt, werden deaktivierte AD-Computer als "FoundInAD" gewertet (kein ADDisabled-Status).

.PARAMETER OutputCsv
Optionaler Pfad für CSV-Export.

.PARAMETER LogPath
Optionaler Pfad für CMTrace-kompatibles Logfile.

.EXAMPLE
.\Compare-CMClientsToAD.ps1 -SiteServer CM01 -SiteCode P01 -OutputCsv .\CM_vs_AD.csv

.EXAMPLE
.\Compare-CMClientsToAD.ps1 -SiteServer CM01 -SiteCode P01 -CollectionId SMS00001 -ADSearchBase "OU=Workstations,DC=contoso,DC=com" -LogPath .\Compare.log
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SiteServer,

    [Parameter(Mandatory=$true)]
    [string]$SiteCode,

    [Parameter(Mandatory=$false)]
    [string]$CollectionId,

    [Parameter(Mandatory=$false)]
    [string]$ADSearchBase,

    [switch]$IncludeDisabledAD,

    [Parameter(Mandatory=$false)]
    [string]$OutputCsv,

    [Parameter(Mandatory=$false)]
    [string]$LogPath
)

#region Helpers: CMTrace logging
function Write-CMTraceLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR")][string]$Severity="INFO",
        [string]$Component = "Compare-CMClientsToAD",
        [string]$LogFile = $script:CurrentLog
    )
    try {
        $time = (Get-Date).ToString("HH:mm:ss.fff")
        $date = (Get-Date).ToString("MM-dd-yyyy")
        $thread = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        $sev = switch ($Severity) { "INFO" {1} "WARN" {2} "ERROR" {3} default {1} }
        $line = "<![LOG[$Message]LOG]!><time=""$time"" date=""$date"" component=""$Component"" context="""" type=""$sev"" thread=""$thread"" file="""">"
        if ($LogFile) { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } else { Write-Host "[$Severity] $Message" }
    } catch {
        Write-Host "[WARN] Logging failed: $($_.Exception.Message)"
    }
}
#endregion

# Init log
$script:CurrentLog = $null
if ($LogPath) {
    try {
        New-Item -Path (Split-Path -Parent $LogPath) -ItemType Directory -Force | Out-Null
    } catch {}
    $script:CurrentLog = $LogPath
    Write-CMTraceLog -Message "Logging initialized." -Severity INFO
}

Write-CMTraceLog -Message "Starting comparison: SiteServer=$SiteServer, SiteCode=$SiteCode, CollectionId=$CollectionId, ADSearchBase=$ADSearchBase, IncludeDisabledAD=$($IncludeDisabledAD.IsPresent)" -Severity INFO

#region Resolve SMS Provider and query clients
$namespace = "root\SMS\site_$SiteCode"
$cmScope = New-Object System.Management.ManagementScope("\\$SiteServer\$namespace")
try {
    $cmScope.Connect()
    Write-CMTraceLog -Message "Connected to SMS Provider \\$SiteServer\$namespace" -Severity INFO
} catch {
    Write-CMTraceLog -Message "Cannot connect to SMS Provider: $($_.Exception.Message)" -Severity ERROR
    throw
}

# Build WQL for clients
if ([string]::IsNullOrWhiteSpace($CollectionId)) {
    $wql = @"
SELECT Name, ResourceId, SMSUniqueIdentifier, Client, Active, ClientType, ClientVersion, LastLogonTimestamp
FROM SMS_R_System
WHERE Client = 1 AND Active = 1
"@
    Write-CMTraceLog -Message "WQL (all active clients): $wql" -Severity INFO
} else {
    $wql = @"
SELECT s.Name, s.ResourceId, s.SMSUniqueIdentifier, s.Client, s.Active, s.ClientType, s.ClientVersion, s.LastLogonTimestamp
FROM SMS_R_System as s
JOIN SMS_FullCollectionMembership as f on s.ResourceId = f.ResourceId
WHERE s.Client = 1 AND s.Active = 1 AND f.CollectionID = '$CollectionId'
"@
    Write-CMTraceLog -Message "WQL (by collection): $wql" -Severity INFO
}

$q = New-Object System.Management.ObjectQuery($wql)
$searcher = New-Object System.Management.ManagementObjectSearcher($cmScope, $q)

try {
    $cmDevices = $searcher.Get()
    $countCM = @($cmDevices).Count
    Write-CMTraceLog -Message "Retrieved $countCM ConfigMgr client(s) for comparison." -Severity INFO
} catch {
    Write-CMTraceLog -Message "Failed to query SMS_R_System: $($_.Exception.Message)" -Severity ERROR
    throw
}
#endregion

#region AD resolution (module or ADSI)
$useADModule = $false
try {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $useADModule = $true
        Write-CMTraceLog -Message "Using ActiveDirectory PowerShell module." -Severity INFO
    } else {
        Write-CMTraceLog -Message "ActiveDirectory module not available; falling back to ADSI/DirectorySearcher." -Severity WARN
    }
} catch {
    Write-CMTraceLog -Message "Failed to load ActiveDirectory module, using ADSI fallback. Error: $($_.Exception.Message)" -Severity WARN
}

function Get-ADComputerSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [string]$SearchBase
    )
    if ($useADModule) {
        try {
            # Prefer SAMAccountName (with $), fallback to Name
            $sam = "$ComputerName`$"
            $params = @{ Identity = $sam; ErrorAction = 'Stop' }
            if ($SearchBase) { $params['Server'] = $null } # Identity lookup ignores SearchBase; we’ll fallback to LDAP filter below if needed

            # First try exact sAMAccountName
            try {
                $c = Get-ADComputer @params -Properties Enabled, DNSHostName, LastLogonTimestamp
                if ($c) { return $c }
            } catch {}

            # Fallback: search by Name or DNSHostName within SearchBase
            $filter = "(&(objectClass=computer)(|(name=$ComputerName)(dNSHostName=$ComputerName)))"
            $sp = if ($SearchBase) { @{ LDAPFilter = $filter; SearchBase = $SearchBase } } else { @{ LDAPFilter = $filter } }
            $c2 = Get-ADComputer @sp -Properties Enabled, DNSHostName, LastLogonTimestamp | Select-Object -First 1
            return $c2
        } catch {
            return $null
        }
    } else {
        try {
            $root = if ($SearchBase) { "LDAP://$SearchBase" } else { "LDAP://RootDSE" }
            if ($root -eq "LDAP://RootDSE") {
                $dse = [ADSI]"LDAP://RootDSE"
                $defaultNamingContext = $dse.defaultNamingContext
                $root = "LDAP://$defaultNamingContext"
            }
            $entry = New-Object System.DirectoryServices.DirectoryEntry($root)
            $ds = New-Object System.DirectoryServices.DirectorySearcher($entry)
            $ds.PageSize = 1000
            $ds.Filter = "(&(objectClass=computer)(|(name=$ComputerName)(dNSHostName=$ComputerName)))"
            $ds.PropertiesToLoad.AddRange(@("name","dNSHostName","userAccountControl","lastLogonTimestamp")) | Out-Null
            $res = $ds.FindOne()
            if ($null -eq $res) { return $null }
            $obj = New-Object PSObject -Property @{
                Name = $res.Properties["name"][0]
                DNSHostName = $res.Properties["dNSHostName"][0]
                Enabled = $true
                LastLogonTimestamp = $null
            }
            # Enabled aus userAccountControl
            if ($res.Properties.Contains("useraccountcontrol")) {
                $uac = [int]$res.Properties["useraccountcontrol"][0]
                # 0x2 (ACCOUNTDISABLE)
                $obj.Enabled = (-not (($uac -band 0x2) -eq 0x2))
            }
            if ($res.Properties.Contains("lastlogontimestamp")) {
                $llt = [long]$res.Properties["lastlogontimestamp"][0]
                $obj | Add-Member -NotePropertyName LastLogonTimestamp -NotePropertyValue $llt -Force
            }
            return $obj
        } catch {
            return $null
        }
    }
}
#endregion

#region Compare loop
$result = New-Object System.Collections.Generic.List[object]

foreach ($dev in $cmDevices) {
    # SMS_R_System.Name is NetBIOS; try both NetBIOS and DNS
    $cmName = $dev.Properties["Name"].Value
    $dnsName = $null
    try {
        # Some environments extend SMS_R_System with FQDN; if not present ignore
        $dnsName = $dev.Properties["FullDomainName"].Value
    } catch {}

    $adObj = $null
    # First try DNS name (more reliable when multiple domains), then NetBIOS
    if ($dnsName) {
        $adObj = Get-ADComputerSafe -ComputerName $dnsName -SearchBase $ADSearchBase
    }
    if (-not $adObj) {
        $adObj = Get-ADComputerSafe -ComputerName $cmName -SearchBase $ADSearchBase
    }

    $status = "FoundInAD"
    $adEnabled = $null
    $adDns = $null
    $adLastLogon = $null

    if ($adObj) {
        # Normalize outputs
        $adEnabled = if ($adObj.PSObject.Properties.Name -contains 'Enabled') { [bool]$adObj.Enabled } else { $null }
        $adDns     = if ($adObj.PSObject.Properties.Name -contains 'DNSHostName') { [string]$adObj.DNSHostName } else { $null }

        # Convert lastLogonTimestamp (AD generalized time) to DateTime if available
        if ($adObj.PSObject.Properties.Name -contains 'LastLogonTimestamp' -and $adObj.LastLogonTimestamp) {
            try {
                if ($adObj.LastLogonTimestamp -is [string]) {
                    $adLastLogon = $adObj.LastLogonTimestamp
                } elseif ($adObj.LastLogonTimestamp -is [long]) {
                    $adLastLogon = [DateTime]::FromFileTime($adObj.LastLogonTimestamp)
                } else {
                    $adLastLogon = $adObj.LastLogonTimestamp
                }
            } catch {
                $adLastLogon = $null
            }
        }

        if (-not $IncludeDisabledAD.IsPresent -and $adEnabled -eq $false) {
            $status = "ADDisabled"
        }
    } else {
        $status = "MissingInAD"
    }

    $row = [PSCustomObject]@{
        CM_Name              = $cmName
        CM_ResourceId        = $dev.Properties["ResourceId"].Value
        CM_Client            = $dev.Properties["Client"].Value
        CM_Active            = $dev.Properties["Active"].Value
        CM_ClientVersion     = $dev.Properties["ClientVersion"].Value
        AD_Status            = $status
        AD_Enabled           = $adEnabled
        AD_DNSHostName       = $adDns
        AD_LastLogonTimestamp= $adLastLogon
    }
    $result.Add($row) | Out-Null

    Write-CMTraceLog -Message "Checked $cmName => $status (AD Enabled=$adEnabled, DNS=$adDns)" -Severity INFO
}
#endregion

#region Output
if ($OutputCsv) {
    try {
        $dir = Split-Path -Parent $OutputCsv
        if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        $result | Sort-Object CM_Name | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
        Write-CMTraceLog -Message "CSV written to $OutputCsv" -Severity INFO
    } catch {
        Write-CMTraceLog -Message "Failed to write CSV: $($_.Exception.Message)" -Severity ERROR
    }
}

# Default console output
$result | Sort-Object CM_Name | Format-Table -AutoSize
Write-CMTraceLog -Message "Completed comparison. Total: $($result.Count)" -Severity INFO
#endregion
