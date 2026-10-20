#Requires -Version 5.1
<#
Issue #75 local host facts only. No elevation requested, no system changes,
no secret/environment dump, no hostname/username/serial/IP/recovery keys.
Output is UNATTESTED local facts, NEVER a Writer credential authorization.
Usage: powershell.exe -NoProfile -File .\scripts\issue-75-windows-host-readonly.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
function Probe([scriptblock]$Block) {
    try { return (& $Block) }
    catch { return $null }
}
function Tri($x) {
    if ($null -eq $x) { return 'UNKNOWN' }
    if ($x -eq $true) { return 'YES' }
    if ($x -eq $false) { return 'NO' }
    return 'UNKNOWN'
}
$build = 0
$edition = 'UNKNOWN'
$os = Probe { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
if ($null -ne $os) {
    $n = 0
    if ([int]::TryParse([string]$os.BuildNumber,[ref]$n)) { $build=$n }
}
$v = Probe { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop }
if ($null -ne $v) {
    $raw = [string]$v.EditionID
    if ($raw -in @('Professional','ProfessionalN','Enterprise','EnterpriseS','Education','EducationN','Core','CoreSingleLanguage')) {
        $edition=$raw
    }
}
$cpu = Probe { Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1 }
$firmware = 'UNKNOWN'
$slat = 'UNKNOWN'
if ($null -ne $cpu) {
    $firmware=Tri $cpu.VirtualizationFirmwareEnabled
    $slat=Tri $cpu.SecondLevelAddressTranslationExtensions
}
$hyperv = 'UNKNOWN'
$feature = Probe { Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V-All' -ErrorAction Stop }
if ($null -ne $feature) {
    $state = [string]$feature.State
    if ($state -eq 'Enabled') { $hyperv='ENABLED' }
    elseif ($state -eq 'Disabled' -or $state -eq 'DisabledWithPayloadRemoved') { $hyperv='DISABLED' }
}
$memory='UNKNOWN'
if ($null -ne $os) {
    try {
        $kb=[decimal]$os.TotalVisibleMemorySize
        $memory=Tri ($kb -ge 8GB/1KB)
    } catch { $memory='UNKNOWN' }
}
$disk='UNKNOWN'
$root=$env:SystemDrive
if ($root -match '^[A-Z]:$') {
    $d=Probe { Get-PSDrive -Name $root.Substring(0,1) -PSProvider FileSystem -ErrorAction Stop }
    if ($null -ne $d -and $null -ne $d.Free) { $disk=Tri ([decimal]$d.Free -ge 40GB) }
}
$enc='UNKNOWN'
if ($root -match '^[A-Z]:$') {
    $bl=Probe { Get-BitLockerVolume -MountPoint $root -ErrorAction Stop }
    if ($null -ne $bl) {
        $status=[string]$bl.ProtectionStatus
        if ($status -eq 'On' -or $status -eq '1') { $enc='YES' }
        elseif ($status -eq 'Off' -or $status -eq '0') { $enc='NO' }
    }
}
$fw='UNKNOWN'
$profiles=Probe { @(Get-NetFirewallProfile -ErrorAction Stop) }
if ($null -ne $profiles -and @($profiles).Count -ge 3) {
    $fw=Tri (@($profiles | Where-Object { $_.Enabled -ne $true }).Count -eq 0)
}
$out=[ordered]@{
    schemaVersion=1
    evidenceKind='ISSUE75_LOCAL_WINDOWS_HOST_FACTS_UNATTESTED'
    observation='LOCAL_WINDOWS_POWERSHELL_UNATTESTED'
    windowsBuild=$build
    windowsEdition=$edition
    hyperVFeature=$hyperv
    firmwareVirtualization=$firmware
    cpuSlat=$slat
    physicalMemoryAtLeast8GiB=$memory
    systemDriveFreeAtLeast40GiB=$disk
    systemDriveEncryptionProtected=$enc
    allFirewallProfilesEnabled=$fw
    machineIdentityIncluded=$false
    credentialAccessAttempted=$false
    systemSettingsChanged=$false
    privateWriterRuntimeProven=$false
    publicationAuthorized=$false
}
$out | ConvertTo-Json -Depth 4 -Compress
