<#
.SYNOPSIS
  Prüft für alle ConfigMgr Applications, ob die Quell-Verzeichnisse noch im Dateisystem vorhanden sind.

.DESCRIPTION
  Läuft im Configuration Manager (ConfigMgr / SCCM) PowerShell-Kontext. 
  - Versucht zuerst die ConfigMgr-Cmdlets (Get-CMApplication / Get-CMDeploymentType / Get-CMContent).
  - Fallback: liest Anwendungen über SMS WMI/CIM (root\SMS\site_<Code>).
  Extrahiert alle Strings, die wie Windows-Pfade/UNC-Pfade aussehen, und prüft mit Test-Path.
  Schreibt ein CSV mit Ergebnissen sowie ein Logfile — beides als echte Dateisystempfade (keine CM-Provider-Pfade).

.PARAMETER OutputDirectory
  Expliziter Dateisystempfad, in dem CSV und Log abgelegt werden.
  Standard: C:\ConfigMgrAppSourceCheck

.PARAMETER VerboseLog
  Schaltet ausführliche Logging-Ausgaben ein.

.EXAMPLE
  .\Check-ConfigMgrAppSourcePaths.ps1 -OutputDirectory 'C:\Reports\ConfigMgr' -VerboseLog

.NOTES
  Kompatibilität: PowerShell 5.1
  Muss mit einem Account ausgeführt werden, der Zugriff auf das SMS-Provider-Namespace hat oder in der ConfigMgr-Console gestartet wird.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "C:\ConfigMgrAppSourceCheck",

    [Parameter(Mandatory=$false)]
    [switch]$VerboseLog
)

# -----------------------
# Hilfsfunktionen
# -----------------------
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$timestamp [$Level] $Message"
    Write-Output $line
    if ($global:LogFile) {
        Add-Content -Path $global:LogFile -Value $line -ErrorAction SilentlyContinue
    }
}

function Ensure-OutputDirectory {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) {
        try {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        } catch {
            throw "Konnte Ausgabeverzeichnis nicht erstellen: $Path. Fehler: $_"
        }
    }
    # Liefere immer den absoluten Dateisystempfad zurück
    return (Get-Item -Path $Path).FullName
}

# Rekursive Suche nach Strings, die wie Windows/UNC-Pfade aussehen
function Extract-PathsFromObject {
    param(
        [Parameter(Mandatory=$true)]
        [psobject]$Object
    )

    $results = [System.Collections.Generic.List[string]]::new()
    $pathRegex = '^(\\\\\\\\|[A-Za-z]:\\).*'  # UNC (\\) oder Laufwerksbuchstabe (C:\)
    $visited = [System.Collections.Hashtable]::Synchronized(@{})

    function _walk($obj) {
        if ($null -eq $obj) { return }

        $id = [Runtime.InteropServices.GCHandle]::Alloc($obj, [Runtime.InteropServices.GCHandleType]::Weak) 2>$null
        try {
            $hash = ($obj.GetHashCode() -as [string])  # Best Effort, dient nur zur Zyklusvermeidung
        } catch {
            $hash = [string]::Empty
        }
        if ($hash -and $visited.ContainsKey($hash)) { return }
        if ($hash) { $visited[$hash] = $true }

        if ($obj -is [string]) {
            if ($obj -match $pathRegex) {
                $results.Add($obj)
            }
            return
        }

        if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
            foreach ($item in $obj) {
                _walk $item
            }
            return
        }

        # Für PSObjects / Custom objects: iterate properties
        try {
            $members = $obj | Get-Member -MemberType NoteProperty, Property -ErrorAction SilentlyContinue
            if ($members) {
                foreach ($m in $members) {
                    try {
                        $val = $obj."$($m.Name)" 2>$null
                        _walk $val
                    } catch { }
                }
            } else {
                # primitive fallback: ToString prüfen
                $ts = $obj.ToString()
                if ($ts -and ($ts -match $pathRegex)) {
                    $results.Add($ts)
                }
            }
        } catch {
            # ignore
        }
    }

    _walk $Object
    # Deduplicate & return as array
    return $results | Select-Object -Unique
}

# -----------------------
# Start / Initialisierung
# -----------------------
try {
    $OutputDirectory = Ensure-OutputDirectory -Path $OutputDirectory
} catch {
    Write-Error $_
    exit 1
}

$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
$global:LogFile = Join-Path $OutputDirectory "AppSourceCheck_$ts.log"
$csvFile = Join-Path $OutputDirectory "AppSourceCheck_$ts.csv"

# CSV Kopfzeile vorbereiten
$csvHeaders = "ApplicationName,ApplicationId,DeploymentTypeName,CandidateSourcePath,PathExists,CheckedAsUNCOrDrive,Notes"

# Neues Log / CSV anlegen
"" | Out-File -FilePath $global:LogFile -Encoding UTF8
$csvHeaders | Out-File -FilePath $csvFile -Encoding UTF8

Write-Log "Starte ConfigMgr Application Source Check"
Write-Log "Ausgabeverzeichnis: $OutputDirectory"

# -----------------------
# ConfigMgr-Objekte lesen
# -----------------------
$apps = $null
$usedMethod = ""

# Wenn Get-CMApplication verfügbar ist -> Benutzen
if (Get-Command -Name Get-CMApplication -ErrorAction SilentlyContinue) {
    Write-Log "ConfigMgr-Cmdlets gefunden, verwende Get-CMApplication als Quelle."
    $usedMethod = "Cmdlets"
    try {
        $apps = Get-CMApplication -ErrorAction Stop
    } catch {
        Write-Log "Fehler beim Aufruf von Get-CMApplication: $_" "ERROR"
        $apps = @()
    }
} else {
    # Fallback: WMI/CIM
    Write-Log "ConfigMgr-Cmdlets nicht gefunden, versuche WMI/CIM-Fallback."
    # Namespace ermitteln: namespace root\SMS\site_*
    try {
        $namespaces = Get-CimInstance -Namespace root\SMS -ClassName __namespace -ErrorAction Stop | Where-Object { $_.Name -like "site_*" }
        if (-not $namespaces) {
            throw "Kein root\SMS\site_<CODE> Namespace gefunden. Stelle sicher, dass das Skript mit Berechtigungen ausgeführt wird, die Zugriff auf den SMS Provider erlauben."
        }
        $siteNsName = $namespaces[0].Name  # erster gefundener Site-Namespace (falls mehrere vorhanden)
        $namespace = "root\SMS\$siteNsName"
        Write-Log "Verwende Namespace: $namespace"
        # SMS_Application Klasse
        $apps = Get-CimInstance -Namespace $namespace -ClassName SMS_Application -ErrorAction Stop
        $usedMethod = "CIM:$namespace"
    } catch {
        Write-Log "Fehler beim Zugriff auf SMS WMI/CIM: $_" "ERROR"
        $apps = @()
    }
}

Write-Log ("Anzahl gefundener Applications: {0}" -f ($apps.Count))

# -----------------------
# Durch alle Applications iterieren
# -----------------------
foreach ($app in $apps) {
    # Versuche aussagekräftige Felder zu finden
    $appName = $null
    $appId = $null

    if ($usedMethod -eq "Cmdlets") {
        $appName = $app.LocalizedDisplayName
        $appId = $app.CI_UniqueID
    } else {
        # CIM-Objekt -> unterschiedliche Feldnamen
        $appName = $app.LocalizedDisplayName
        if (-not $appName) { $appName = $app.Name }
        $appId = $app.CI_UniqueID
        if (-not $appId) { $appId = $app.ApplicationId }
    }

    if (-not $appName) { $appName = "<unknown>" }
    if (-not $appId) { $appId = "<unknown>" }

    Write-Log "Untersuche Application: $appName (ID: $appId)"

    $deploymentTypes = @()
    if ($usedMethod -eq "Cmdlets") {
        try {
            $deploymentTypes = Get-CMDeploymentType -ApplicationId $appId -ErrorAction SilentlyContinue
            if (-not $deploymentTypes) {
                # alternative by name fallback
                $deploymentTypes = Get-CMDeploymentType -ApplicationName $appName -ErrorAction SilentlyContinue
            }
        } catch {
            $deploymentTypes = @()
        }
    } else {
        # CIM-Objekt: DeploymentTypes können als eingebettete Struktur vorhanden sein
        try {
            # Manche Umgebungen haben das Feld DeploymentTypes, andere DeploymentType
            if ($app.DeploymentTypes) {
                $deploymentTypes = $app.DeploymentTypes
            } elseif ($app.DeploymentType) {
                $deploymentTypes = $app.DeploymentType
            } else {
                # Versuche per Abfrage in SMS_DeploymentType Klasse (Parent = Application CI_UniqueID)
                try {
                    $namespace = $namespace # bereits definiert oben
                    if ($app.CI_UniqueID) {
                        $query = "SELECT * FROM SMS_DeploymentType WHERE ApplicationId='$($app.CI_UniqueID)'"
                        $deploymentTypes = Get-CimInstance -Namespace $namespace -Query $query -ErrorAction SilentlyContinue
                    }
                } catch {
                    $deploymentTypes = @()
                }
            }
        } catch {
            $deploymentTypes = @()
        }
    }

    if (-not $deploymentTypes) {
        Write-Log "  Keine DeploymentTypes gefunden für $appName" "WARN"
        # Trotzdem versuchen, aus dem $app-Objekt Pfade zu extrahieren (manche Apps haben Source-Pfade direkt)
        $candidatePaths = Extract-PathsFromObject -Object $app
        if ($candidatePaths -and $candidatePaths.Count -gt 0) {
            foreach ($p in $candidatePaths) {
                $exists = Test-Path -Path $p
                $notes = "gefunden direkt auf Application-Objekt"
                $line = '"{0}","{1}","{2}","{3}",{4},{5},"{6}"' -f ($appName,$appId,"<no-deploymenttype>",$p,$exists,($p -match '^(\\\\\\\\|[A-Za-z]:\\)'),$notes)
                Add-Content -Path $csvFile -Value $line -Encoding UTF8
                Write-Log ("    Kandidat: {0} -> Exists: {1}" -f $p, $exists)
            }
        }
        continue
    }

    # Für jeden DeploymentType alle möglichen Pfade extrahieren
    foreach ($dt in $deploymentTypes) {
        $dtName = $null
        try {
            if ($dt.LocalizedDisplayName) { $dtName = $dt.LocalizedDisplayName }
            elseif ($dt.Name) { $dtName = $dt.Name }
            elseif ($dt.DeploymentTypeName) { $dtName = $dt.DeploymentTypeName }
            else { $dtName = "<unknown-deploymenttype>" }
        } catch {
            $dtName = "<unknown-deploymenttype>"
        }

        Write-Log ("  DeploymentType: {0}" -f $dtName)

        # Extrahiere candidate paths aus dem DeploymentType-Objekt
        $candidatePaths = Extract-PathsFromObject -Object $dt

        if (-not $candidatePaths -or $candidatePaths.Count -eq 0) {
            Write-Log "    Keine eindeutigen Pfade im DeploymentType-Objekt gefunden. Versuche Get-CMContent (wenn verfügbar)."
            if (Get-Command -Name Get-CMContent -ErrorAction SilentlyContinue) {
                # Versuch: DeploymentType enthält wohl Content/ContentId - versuchen Content abzufragen
                try {
                    # Mögliche Properties prüfen
                    $contentId = $null
                    foreach ($prop in "ContentId","PackageID","PackageID0","ContentPackageID","ContentLibraryID","SourceId") {
                        if ($dt.PSObject.Properties.Name -contains $prop) {
                            $contentId = $dt.$prop
                            break
                        }
                    }
                    if ($contentId) {
                        $contents = Get-CMContent -ContentId $contentId -ErrorAction SilentlyContinue
                        if ($contents) {
                            $pathsFromContent = Extract-PathsFromObject -Object $contents
                            $candidatePaths += $pathsFromContent
                        }
                    }
                } catch {
                    # ignore
                }
            }
        }

        # Wenn noch keine Pfade, notieren
        if (-not $candidatePaths -or $candidatePaths.Count -eq 0) {
            Write-Log "    Keine Kandidat-Pfade für DeploymentType $dtName gefunden." "WARN"
            $line = '"{0}","{1}","{2}","{3}",{4},{5},"{6}"' -f ($appName,$appId,$dtName,"<no-paths>",$false,$false,"no candidate paths")
            Add-Content -Path $csvFile -Value $line -Encoding UTF8
            continue
        }

        # Pfade prüfen und in CSV schreiben
        foreach ($p in $candidatePaths | Select-Object -Unique) {
            # Normalize: trim, remove surrounding quotes
            $pTrim = $p.Trim('"').Trim()
            # Test-Path benötigt echte FileSystemPaths; wir behandeln nur Windows-Pfade / UNC
            $looksLikePath = ($pTrim -match '^(\\\\\\\\|[A-Za-z]:\\).*')
            $exists = $false
            if ($looksLikePath) {
                try {
                    $exists = Test-Path -Path $pTrim
                } catch {
                    $exists = $false
                }
            } else {
                # Nicht als Windows-Pfad erkennbar -> nicht prüfen
                $exists = $false
            }
            $notes = ""
            if (-not $looksLikePath) { $notes = "Nicht-windows-pfad-format" }

            $line = '"{0}","{1}","{2}","{3}",{4},{5},"{6}"' -f ($appName,$appId,$dtName,$pTrim,$exists,$looksLikePath,$notes)
            Add-Content -Path $csvFile -Value $line -Encoding UTF8
            Write-Log ("    Kandidat: {0} -> Exists: {1}" -f $pTrim, $exists)
        }
    }
}

Write-Log "Fertig. Ergebnisse gespeichert in:"
Write-Log "  CSV: $csvFile"
Write-Log "  Log: $global:LogFile"
Write-Log "Hinweis: Stellen Sie sicher, dass der Account, unter dem das Skript läuft, Zugriff auf alle UNC-Ziele hat (Domain-Zugriff)."

# Exit mit 0
exit 0
</powershell>