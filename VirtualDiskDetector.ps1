param(
    [switch]$VerboseMode
)

#region UI Helpers
function Write-Banner {
    cls
    Write-Host @"
==========================================================================================
  _________                                         .__                                  |
 /   _____/ ___________   ____   ____   ____   _____|  |__ _____ _______   ____          |
 \_____  \_/ ___\_  __ \_/ __ \_/ __ \ /    \ /  ___/  |  \\__  \\_  __ \_/ __ \         |
 /        \  \___|  | \/\  ___/\  ___/|   |  \\___ \|   Y  \/ __ \|  | \/\  ___/         |
/_______  /\___  >__|    \___  >\___  >___|  /____  >___|  (____  /__|    \___  >        |
        \/     \/            \/     \/     \/     \/     \/     \/            \/         |
   _____  .__  .__  .__                                                                  |
  /  _  \ |  | |  | |__|____    ____   ____  ____                                        |
 /  /_\  \|  | |  | |  \__  \  /    \_/ ___\/ __ \                                       |
/    |    \  |_|  |_|  |/ __ \|   |  \  \__\  ___/                                       |
\____|__  /____/____/__(____  /___|  /\___  >___  >                                      |
        \/                  \/     \/     \/    \/                                       |
==========================================================================================
 Virtual Disk Forensic Scanner
==========================================================================================
"@ -ForegroundColor White
}

function Write-Context {
    param($User,$HostName,$Date)
    Write-Host " Usuario : $User" -ForegroundColor Cyan
    Write-Host " Host    : $HostName" -ForegroundColor Cyan
    Write-Host " Fecha   : $Date" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
}

function Write-Section { param($Title) Write-Host "`n[+] $Title" -ForegroundColor Magenta; Write-Host ("-"*90) -ForegroundColor DarkGray }
function Write-Status { param($Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Done { param($Msg) Write-Host "[✓] $Msg" -ForegroundColor Green }
function Write-Warn { param($Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }
#endregion

#region Globals
$User     = $env:USERNAME
$HostName = $env:COMPUTERNAME
$Now      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$Findings = @()
$RiskAccumulator = 0
$RiskWeight = @{ High=3; Medium=2; Low=1 }

# Rutas sensibles a excluir
$ExcludedPaths = @(
    '\Windows\','\Program Files','\Program Files (x86)',
    '\$Recycle.Bin','\System Volume Information'
)
#endregion

#region Helpers
function Log { param($Msg) if ($VerboseMode) { Write-Host "[*] $Msg" -ForegroundColor DarkGray } }
function Is-ExcludedPath { param($Path) foreach ($e in $ExcludedPaths) { if ($Path -match [regex]::Escape($e)) { return $true } } return $false }
function Add-Finding { param($Time,$Artifact,$Event,$Path,$Risk,$Source) $script:Findings += [pscustomobject]@{Time=$Time;Artifact=$Artifact;Event=$Event;Path=$Path;Risk=$Risk;Source=$Source}; $script:RiskAccumulator += $RiskWeight[$Risk] }
#endregion

#region UI Init
Write-Banner
Write-Context -User $User -HostName $HostName -Date $Now
Write-Warn "El análisis puede tardar un poco dependiendo del tamaño del disco."
#endregion

#region USN Scan
Write-Section "USN Journal – Actividad reciente NTFS"
Write-Status "Analizando USN Journal en todo el disco..."

$usn = fsutil usn readjournal C: 2>$null | Select-String '\.vhd|\.vhdx|\.vmdk'

foreach ($l in $usn) {
    if (Is-ExcludedPath $l.Line) { continue }
    Add-Finding (Get-Date) 'Virtual Disk' 'USN Activity' $l.Line.Trim() 'Medium' 'USN'
}
Write-Done "$($Findings.Count) hallazgos encontrados en USN"
#endregion

#region Filesystem Scan
Write-Section "Filesystem – Discos virtuales presentes"
Write-Status "Enumerando VHD / VHDX / VMDK en todo el disco, excluyendo rutas sensibles..."

$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ge 0 }

foreach ($d in $drives) {
    try {
        [IO.Directory]::EnumerateFiles($d.Root,'*.vhd*','AllDirectories') | ForEach-Object {
            if (Is-ExcludedPath $_) { return }  # salta rutas protegidas
            Add-Finding (Get-Item $_).LastWriteTime 'Virtual Disk' 'File Present' $_ 'Low' 'Filesystem'
        }
    } catch { Log "Error accediendo a $($d.Root)" }
}
Write-Done "Filesystem scan completado"
#endregion

#region Mounted Volumes
Write-Section "Volúmenes montados sin letra"
Write-Status "Detectando volúmenes montados válidos sin letra..."

$volumes = Get-Volume | Where-Object { $_.DriveLetter -eq $null -and $_.FileSystemLabel -ne $null }

foreach ($v in $volumes) {
    Add-Finding (Get-Date) 'Mounted Volume' 'Mounted Without Drive Letter' $v.UniqueId 'High' 'MountVol'
}
Write-Done "Montajes válidos detectados"
#endregion

#region Correlation
Write-Section "Correlación USN + Filesystem + Montajes"
Write-Status "Correlacionando artefactos..."

$Grouped = $Findings | Group-Object Path
$Findings = @()

foreach ($g in $Grouped) {
    $u = $g.Group | ? Source -eq 'USN'
    $f = $g.Group | ? Source -eq 'Filesystem'
    $m = $g.Group | ? Source -eq 'MountVol'

    if ($m) {
        Add-Finding (Get-Date) 'Virtual Disk' 'Mounted Volume Detected' $g.Name 'High' 'Correlation'
    }
    elseif ($u -and $f) {
        Add-Finding (Get-Date) 'Virtual Disk' 'USN + File Present' $g.Name 'High' 'Correlation'
    }
    elseif ($u) {
        Add-Finding (Get-Date) 'Virtual Disk' 'USN Only (Deleted/Old)' $g.Name 'Medium' 'Correlation'
    }
    else {
        Add-Finding (Get-Date) 'Virtual Disk' 'File Present (No USN)' $g.Name 'Low' 'Correlation'
    }
}
Write-Done "Correlación completada"
#endregion

#region Timeline
Write-Section "TIMELINE"
$Findings | Sort Time | ForEach-Object {
    $c = @{High='Red';Medium='Yellow';Low='Green'}[$_.Risk]
    $timeStr = $_.Time.ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host ("{0,-20} | {1,-25} | {2}" -f $timeStr, $_.Event, $_.Path) -ForegroundColor $c
}
#endregion

#region Summary
Write-Section "RESUMEN FINAL"

# Tabla alineada por riesgo
$Findings | Sort Risk,Time | Format-Table @{Label='Risk';Expression={$_.Risk};Width=10}, @{Label='Event';Expression={$_.Event};Width=25}, @{Label='Path';Expression={$_.Path};Width=80} -AutoSize

$FinalRisk = if ($RiskAccumulator -ge 8) {'ALTO'} elseif ($RiskAccumulator -ge 4) {'MEDIO'} else {'BAJO'}
$Color = @{ALTO='Red';MEDIO='Yellow';BAJO='Green'}[$FinalRisk]

Write-Host "`nTotal Hallazgos : $($Findings.Count)"
Write-Host "Riesgo Global  : $FinalRisk" -ForegroundColor $Color
#endregion

#region Export
$OutDir = "$PWD\VDF_Output"
New-Item $OutDir -ItemType Directory -Force | Out-Null

$Findings | Export-Csv "$OutDir\results.csv" -NoTypeInformation -Encoding UTF8
$Findings | ConvertTo-Json -Depth 4 | Out-File "$OutDir\results.json" -Encoding UTF8

Write-Done "Resultados exportados a $OutDir"
#endregion
