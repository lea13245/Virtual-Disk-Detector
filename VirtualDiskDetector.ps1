param(
    [switch]$VerboseMode
)

#region UI
cls
$User     = $env:USERNAME
$HostName = $env:COMPUTERNAME
$Now      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

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
 Virtual Disk Forensic Scanner // discord.gg/ssa
------------------------------------------------------------------------------------------
 Usuario : $User
 Host    : $HostName
 Fecha   : $Now
------------------------------------------------------------------------------------------
[*] El análisis puede tardar un poco dependiendo del tamaño del disco.(Entre 2m-5m)
==========================================================================================
"@ -ForegroundColor White
#endregion

#region Globals
$Findings = @()
$RiskAccumulator = 0

$RiskWeight = @{ High=3; Medium=2; Low=1 }

$ExcludedPaths = @(
    '\Windows\','\Program Files','\Program Files (x86)',
    '\$Recycle.Bin','\System Volume Information'
)

$UserScopes = @(
    'C:\Users','C:\Users\Public','C:\ProgramData','C:\Temp'
)
#endregion

#region Helpers
function Log {
    param($Msg)
    if ($VerboseMode) {
        Write-Host "[*] $Msg" -ForegroundColor DarkGray
    }
}

function Is-ExcludedPath {
    param($Path)
    foreach ($e in $ExcludedPaths) {
        if ($Path -match [regex]::Escape($e)) { return $true }
    }
    return $false
}

function Add-Finding {
    param($Time,$Artifact,$Event,$Path,$Risk,$Source)

    $script:Findings += [pscustomobject]@{
        Time=$Time; Artifact=$Artifact; Event=$Event
        Path=$Path; Risk=$Risk; Source=$Source
    }

    $script:RiskAccumulator += $RiskWeight[$Risk]
}
#endregion

#region USN
Write-Host "`n[*] Analizando USN Journal..." -ForegroundColor Cyan
$usn = fsutil usn readjournal C: 2>$null | Select-String '\.vhd|\.vhdx|\.vmdk'

foreach ($l in $usn) {
    if (Is-ExcludedPath $l.Line) { continue }
    Add-Finding (Get-Date) 'Virtual Disk' 'USN Activity' $l.Line.Trim() 'Medium' 'USN'
}
#endregion

#region Filesystem
Write-Host "`n[*] Analizando sistema de archivos..." -ForegroundColor Cyan
foreach ($s in $UserScopes) {
    if (-not (Test-Path $s)) { continue }
    try {
        [IO.Directory]::EnumerateFiles($s,'*.vhd*','AllDirectories') | ForEach-Object {
            Add-Finding (Get-Item $_).LastWriteTime 'Virtual Disk' 'File Present' $_ 'Low' 'Filesystem'
        }
    } catch {}
}
#endregion

#region Mounted Volumes
Write-Host "`n[*] Analizando volúmenes montados sin letra..." -ForegroundColor Cyan
mountvol | Select-String '\\\?\\Volume' | ForEach-Object {
    if ($_ -notmatch 'C:\\') {
        Add-Finding (Get-Date) 'Mounted Volume' 'Mounted Without Drive Letter' $_.Line 'High' 'MountVol'
    }
}
#endregion

#region Correlation
Write-Host "`n[*] Correlacionando artefactos..." -ForegroundColor Cyan
$Grouped = $Findings | Group-Object Path
$Findings = @()

foreach ($g in $Grouped) {
    $u = $g.Group | ? Source -eq 'USN'
    $f = $g.Group | ? Source -eq 'Filesystem'

    if ($u -and $f) {
        Add-Finding (Get-Date) 'Virtual Disk' 'USN + File Present' $g.Name 'High' 'Correlation'
    } elseif ($u) {
        Add-Finding (Get-Date) 'Virtual Disk' 'USN Only (Deleted/Old)' $g.Name 'Medium' 'Correlation'
    } else {
        Add-Finding (Get-Date) 'Virtual Disk' 'File Present (No USN)' $g.Name 'Low' 'Correlation'
    }
}
#endregion

#region Timeline
Write-Host "`n================== TIMELINE ==================" -ForegroundColor White
$Findings | Sort Time | ForEach-Object {
    $c = @{High='Red';Medium='Yellow';Low='Green'}[$_.Risk]
    Write-Host "$($_.Time) | $($_.Event) | $($_.Path)" -ForegroundColor $c
}
#endregion

#region Summary
Write-Host "`n================== RESUMEN ==================" -ForegroundColor White
$Findings | Group Risk | Select Name,Count | Format-Table -AutoSize

$FinalRisk = if ($RiskAccumulator -ge 8) {'ALTO'} elseif ($RiskAccumulator -ge 4) {'MEDIO'} else {'BAJO'}
$Color = @{ALTO='Red';MEDIO='Yellow';BAJO='Green'}[$FinalRisk]

Write-Host "`nHallazgos : $($Findings.Count)"
Write-Host "Riesgo    : $FinalRisk" -ForegroundColor $Color
#endregion

#region Export
$OutDir = "$PWD\VDF_Output"
New-Item $OutDir -ItemType Directory -Force | Out-Null

$Findings | Export-Csv "$OutDir\results.csv" -NoTypeInformation -Encoding UTF8
$Findings | ConvertTo-Json -Depth 4 | Out-File "$OutDir\results.json" -Encoding UTF8

Write-Host "`n[*] Resultados exportados a $OutDir" -ForegroundColor Cyan
#endregion
