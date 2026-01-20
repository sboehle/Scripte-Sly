# Scripte-Sly

PowerShell scripts for Microsoft Configuration Manager (ConfigMgr/SCCM) administrative tasks.

## Overview

This repository contains PowerShell scripts developed during administrative activities for Configuration Manager environments. These scripts help automate common maintenance, auditing, and validation tasks.

**Disclaimer**: These scripts are provided as-is for testing purposes. No warranty or liability is assumed by the author. Test thoroughly in your environment before production use.

## Table of Contents

- [Scripts](#scripts)
  - [CheckAppSourcePaths.ps1](#checkappsourcepathsps1)
  - [CheckDriverPackages.ps1](#checkdriverpackagesps1)
  - [Compare-AD-CM-Clients.ps1](#compare-ad-cm-clientsps1)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
- [Contributing](#contributing)
- [License](#license)

## Scripts

### CheckAppSourcePaths.ps1

Validates ConfigMgr Application source paths for existence and accessibility.

**Purpose**: Identifies applications with missing or inaccessible source directories, which is particularly helpful during ConfigMgr cleanup operations.

**Features**:
- Automatically detects ConfigMgr cmdlets or falls back to WMI/CIM
- Recursively extracts all Windows/UNC paths from application deployment types
- Validates path existence using Test-Path
- Generates detailed CSV report and log file

**Parameters**:
- `OutputDirectory` - Directory for CSV and log output (default: `C:\ConfigMgrAppSourceCheck`)
- `VerboseLog` - Enable detailed logging output

**Example**:
```powershell
.\CheckAppSourcePaths.ps1 -OutputDirectory 'C:\Reports\ConfigMgr' -VerboseLog
```

**Output**:
- CSV file with columns: ApplicationName, ApplicationId, DeploymentTypeName, CandidateSourcePath, PathExists, IsValidWindowsPath, Notes
- Timestamped log file with execution details

**Requirements**:
- PowerShell 5.1 or higher
- ConfigMgr Console installed OR SMS Provider WMI access
- Read permissions on all source paths

---

### CheckDriverPackages.ps1

Audits ConfigMgr Driver Packages for source path existence and content validation.

**Purpose**: Identifies driver packages with missing or empty source directories. Empty directories can cause deployment errors in ConfigMgr.

**Features**:
- Auto-detects site code if not specified
- Validates source path configuration
- Checks directory existence and accessibility
- Verifies directories contain files (not empty)
- Provides summary statistics

**Parameters**:
- `SiteCode` - ConfigMgr site code (e.g., 'P01'), auto-detected if not specified
- `CsvOutputPath` - Path for CSV audit report (default: `C:\Temp\DriverPackageAudit.csv`)
- `VerboseOutput` - Enable detailed console output

**Example**:
```powershell
.\CheckDriverPackages.ps1 -SiteCode 'P01' -CsvOutputPath 'D:\Reports\DriverAudit.csv'
```

**Output**:
- CSV file with columns: PackageID, Name, SourcePath, PathExists, IsFolderEmpty, Status
- Console summary with statistics (total packages, packages with issues, missing paths, empty directories)

**Requirements**:
- PowerShell 5.1 or higher
- ConfigMgr Console installed (ConfigurationManager PowerShell module)
- Read permissions on SMS Provider
- Network access to driver package source paths

---

### Compare-AD-CM-Clients.ps1

Compares active ConfigMgr clients with Active Directory computer objects.

**Purpose**: Validates that ConfigMgr clients have corresponding Active Directory computer accounts. Identifies orphaned ConfigMgr clients or clients with disabled AD accounts.

**Features**:
- Queries ConfigMgr via WMI (SMS Provider)
- Validates against Active Directory using PowerShell module or ADSI fallback
- Supports collection-based filtering
- Supports OU-scoped AD searches
- Optional handling of disabled AD accounts
- CMTrace-compatible logging
- Progress indicators for large environments

**Parameters**:
- `SiteServer` - SMS Provider server name (required)
- `SiteCode` - ConfigMgr site code, e.g., 'P01' (required)
- `CollectionId` - Limit check to specific collection (optional)
- `ADSearchBase` - LDAP search base for AD queries (optional)
- `IncludeDisabledAD` - Treat disabled AD accounts as valid (optional)
- `OutputCsv` - Path for CSV report (optional)
- `LogPath` - Path for CMTrace log file (optional)

**Examples**:

1. **Check all active clients against entire domain**:
```powershell
.\Compare-AD-CM-Clients.ps1 -SiteServer 'CM01' -SiteCode 'P01' -OutputCsv '.\CM_vs_AD.csv' -LogPath '.\Compare.log'
```

2. **Restrict to specific collection and OU**:
```powershell
.\Compare-AD-CM-Clients.ps1 -SiteServer 'CM01' -SiteCode 'P01' -CollectionId 'SMS00001' -ADSearchBase 'OU=Workstations,OU=HQ,DC=contoso,DC=com' -OutputCsv '.\OU_Scope.csv'
```

3. **Ignore disabled AD accounts**:
```powershell
.\Compare-AD-CM-Clients.ps1 -SiteServer 'CM01' -SiteCode 'P01' -IncludeDisabledAD
```

**Output Fields**:
- `CM_Name` / `CM_ResourceId` / `CM_Client` / `CM_Active` / `CM_ClientVersion` - ConfigMgr data
- `AD_Status` - One of:
  - `FoundInAD` - Matching AD computer found
  - `ADDisabled` - AD computer found but disabled (only when `-IncludeDisabledAD` not set)
  - `MissingInAD` - No matching AD computer object found
- `AD_Enabled` / `AD_DNSHostName` / `AD_LastLogonTimestamp` - Selected AD details

**Requirements**:
- PowerShell 5.1 or higher
- Read access to SMS Provider (WMI)
- Read access to Active Directory
- Optional: ActiveDirectory PowerShell module (RSAT-AD-PowerShell)

**Notes**:
- Script tries FQDN first, then NetBIOS name for matching
- For multi-domain environments, use `-ADSearchBase` to target correct domain/OU
- For large environments, use `-CollectionId` or `-ADSearchBase` to limit scope
- Requires read permissions on SMS Provider and Active Directory

---

## Requirements

### Common Requirements

All scripts require:
- **PowerShell 5.1** or higher
- **Windows Operating System** (tested on Windows Server 2016/2019/2022 and Windows 10/11)
- **Execution Policy** allowing script execution (RemoteSigned or Unrestricted)

### Script-Specific Requirements

| Script | ConfigMgr Console | SMS Provider Access | AD Module | Network Access |
|--------|------------------|---------------------|-----------|----------------|
| CheckAppSourcePaths.ps1 | Optional | Yes (WMI/CIM) | No | Source paths |
| CheckDriverPackages.ps1 | Required | Yes | No | Source paths |
| Compare-AD-CM-Clients.ps1 | No | Yes (WMI) | Optional | AD Domain |

### Permissions

The account running these scripts must have:
- **ConfigMgr**: Read permissions on SMS Provider (WMI namespace `root\SMS\site_<CODE>`)
- **File System**: Read access to all UNC/network paths being validated
- **Active Directory** (Compare script only): Read permissions on computer objects

## Installation

1. **Clone the repository**:
```powershell
git clone https://github.com/raandree/Scripte-Sly.git
cd Scripte-Sly
```

2. **Set execution policy** (if needed):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

3. **Verify prerequisites**:
```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Check ConfigMgr module availability (for CheckDriverPackages)
Get-Module -ListAvailable -Name ConfigurationManager

# Check ActiveDirectory module availability (optional for Compare script)
Get-Module -ListAvailable -Name ActiveDirectory
```

## Usage Examples

### Scenario 1: ConfigMgr Application Cleanup

Identify applications with missing source paths before cleanup:

```powershell
# Run the application source check
.\CheckAppSourcePaths.ps1 -OutputDirectory 'C:\Reports' -VerboseLog

# Review the CSV report
Import-Csv 'C:\Reports\AppSourceCheck_*.csv' | 
    Where-Object { $_.PathExists -eq $false } |
    Format-Table -AutoSize
```

### Scenario 2: Driver Package Audit

Audit all driver packages and identify issues:

```powershell
# Run driver package audit
.\CheckDriverPackages.ps1 -SiteCode 'P01' -VerboseOutput

# Find empty driver packages
Import-Csv 'C:\Temp\DriverPackageAudit.csv' -Delimiter ';' |
    Where-Object { $_.IsFolderEmpty -eq 'True' } |
    Select-Object PackageID, Name, SourcePath
```

### Scenario 3: ConfigMgr-AD Reconciliation

Find ConfigMgr clients missing from Active Directory:

```powershell
# Compare all clients to AD
.\Compare-AD-CM-Clients.ps1 -SiteServer 'CM01' -SiteCode 'P01' -OutputCsv '.\CM_AD_Compare.csv' -LogPath '.\Compare.log'

# Analyze missing computers
Import-Csv '.\CM_AD_Compare.csv' |
    Where-Object { $_.AD_Status -eq 'MissingInAD' } |
    Select-Object CM_Name, CM_ResourceId, CM_ClientVersion |
    Export-Csv '.\MissingComputers.csv' -NoTypeInformation
```

### Scenario 4: Multi-Domain Environment

Compare clients in specific OU across different domains:

```powershell
# Target specific OU in domain
.\Compare-AD-CM-Clients.ps1 `
    -SiteServer 'CM01' `
    -SiteCode 'P01' `
    -ADSearchBase 'OU=Workstations,OU=Europe,DC=contoso,DC=com' `
    -CollectionId 'EUR00001' `
    -OutputCsv '.\Europe_Clients.csv'
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Follow PowerShell best practices**:
   - Use approved verbs (`Get-Verb`)
   - Include `[CmdletBinding()]` for advanced functions
   - Add comprehensive comment-based help
   - Use proper error handling
   - Follow consistent formatting (4-space indentation)
3. **Test thoroughly** in a lab environment before submitting
4. **Document changes** in commit messages and update README if needed
5. **Submit a pull request** with clear description of changes

### Code Style

- Use approved PowerShell verbs
- Include comprehensive comment-based help with examples
- Use parameter validation attributes
- Implement proper error handling with try-catch
- Use verbose logging for troubleshooting
- Follow naming conventions (PascalCase for functions, camelCase for variables)

## License

These scripts are provided "as-is" without any warranty. Use at your own risk.

The scripts are intended for administrative use in Configuration Manager environments and should be thoroughly tested before production deployment.

## Support

For issues, questions, or contributions:
- **GitHub Issues**: [Create an issue](https://github.com/raandree/Scripte-Sly/issues)
- **Pull Requests**: [Submit improvements](https://github.com/raandree/Scripte-Sly/pulls)

## Changelog

### 2026-01-20
- **Enhanced all scripts** with PowerShell best practices
- Added comprehensive comment-based help to all scripts
- Improved error handling and logging
- Added parameter validation
- Fixed syntax errors in CheckDriverPackages.ps1
- Enhanced README.md with detailed documentation

---

**Author**: Configuration Manager Administrators  
**Repository**: [https://github.com/raandree/Scripte-Sly](https://github.com/raandree/Scripte-Sly)  
**Last Updated**: January 20, 2026
