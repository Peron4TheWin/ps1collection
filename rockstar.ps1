$ErrorActionPreference = "Stop"
$hostV5  = "https://github.com/uxqc/L4unch3rH0sting/releases/download"
$hostV4  = "https://github.com/onajlikezz/Nightlight-Game-Launcher/raw/main/Modules"

$games = @{
    "GTAV" = @{
        Name      = "Grand Theft Auto V"
        Exes      = @("GTAV.exe","GTA5.exe","PlayGTAV.exe")
        LaunchExe = "PlayGTAV.exe"
        Urls      = @(
            "$hostV5/GTAVFix/bink2w64.dll",
            "$hostV5/GTAVFix/launc.dll",
            "$hostV5/GTAVFix/orig_socialclub.dll",
            "$hostV5/GTAVFix/PlayGTAV.exe",
            "$hostV5/GTAVFix/socialclub.dll"
        )
    }
    "GTAVEnhanced" = @{
        Name      = "Grand Theft Auto V Enhanced"
        Exes      = @("PlayGTAV.exe")
        Markers   = @("RUNE64.dll","socialclub_emu.ini")
        LaunchExe = "PlayGTAV.exe"
        Urls      = @(
            "$hostV5/gtave/RUNE64.dll",
            "$hostV5/gtave/version.dll",
            "$hostV5/gtave/socialclub_emu.ini",
            "$hostV5/gtave/PlayGTAV.exe",
            "$hostV5/gtave/socialclub.dll"
        )
    }
    "RDR2" = @{
        Name      = "Red Dead Redemption 2"
        Exes      = @("RDR2.exe")
        LaunchExe = "Launcher.exe"
        Urls      = @(
            "$hostV5/RDR2Files/1911.dll",
            "$hostV5/RDR2Files/bink2w64.dll",
            "$hostV5/RDR2Files/Launcher.exe",
            "$hostV5/RDR2Files/RDR2.exe"
        )
    }
    "GTAIV" = @{
        Name      = "Grand Theft Auto IV"
        Exes      = @("GTAIV.exe")
        LaunchExe = "PlayGTAIV.exe"
        Urls      = @(
            "$hostV5/GTAIVFiles/binkw32.dll",
            "$hostV5/GTAIVFiles/GTAIV.exe",
            "$hostV5/GTAIVFiles/launc.dll",
            "$hostV5/GTAIVFiles/orig_socialclub.dll",
            "$hostV5/GTAIVFiles/PlayGTAIV.exe",
            "$hostV5/GTAIVFiles/socialclub.dll"
        )
    }
    "RDR1" = @{
        Name      = "Red Dead Redemption"
        Exes      = @("RDR.exe")
        LaunchExe = "PlayRDR.exe"
        Urls      = @(
            "$hostV5/RDR1Files/1911.dll",
            "$hostV5/RDR1Files/PlayRDR.exe",
            "$hostV5/RDR1Files/RDR.exe",
            "$hostV5/RDR1Files/steam_api64.dll"
        )
    }
}

# ─── Funciones ───────────────────────────────────────────────

function Get-SteamPath {
    $paths = @(
        "HKCU:\Software\Valve\Steam",
        "HKLM:\Software\WOW6432Node\Valve\Steam",
        "HKLM:\Software\Valve\Steam"
    )
    foreach ($p in $paths) {
        try {
            $val = (Get-ItemProperty -Path $p -Name "SteamPath" -ErrorAction Stop).SteamPath
            if ($val) { return $val.Trim('"') -replace '/','\' }
        } catch {}
    }
    return "C:\Program Files (x86)\Steam"
}

function Get-SteamLibraries {
    param([string]$SteamPath)
    $libs = @("$SteamPath\steamapps")
    $vdf = "$SteamPath\steamapps\libraryfolders.vdf"
    if (-not (Test-Path -LiteralPath $vdf)) { return $libs }
    try {
        $content = Get-Content -LiteralPath $vdf -Raw -Encoding UTF8
        $regex = [regex]'"path"\s+"([^"]+)"'
        foreach ($m in $regex.Matches($content)) {
            $p = $m.Groups[1].Value -replace '\\\\','\' -replace '/','\'
            if ($p -and (Test-Path -LiteralPath "$p\steamapps" -PathType Container)) {
                $libs += "$p\steamapps"
            }
        }
    } catch {}
    return $libs
}

function Find-Games {
    param([string[]]$LibraryPaths)
    $found = @{}
    foreach ($lib in $LibraryPaths) {
        $common = "$lib\common"
        if (-not (Test-Path -LiteralPath $common -PathType Container)) { continue }
        foreach ($folder in Get-ChildItem -LiteralPath $common -Directory -ErrorAction SilentlyContinue) {
            foreach ($key in $games.Keys) {
                if ($found.ContainsKey($key)) { continue }
                $cfg = $games[$key]
                $match = $false
                foreach ($exe in $cfg.Exes) {
                    if (Test-Path -LiteralPath (Join-Path $folder.FullName $exe)) {
                        $match = $true
                        break
                    }
                }
                if ($match) {
                    if ($cfg.Markers) {
                        $hasMarkers = $false
                        foreach ($m in $cfg.Markers) {
                            if (Test-Path -LiteralPath (Join-Path $folder.FullName $m)) {
                                $hasMarkers = $true
                                break
                            }
                        }
                        if (-not $hasMarkers) { continue }
                    }
                    $found[$key] = $folder.FullName
                }
            }
        }
    }
    return $found
}

function Invoke-Bypass {
    param([string]$GameKey, [string]$GamePath)
    $cfg = $games[$GameKey]
    $urls = $cfg.Urls
    $total = $urls.Count
    $done = 0
    Write-Host "`nJuego: $($cfg.Name)" -ForegroundColor Cyan
    Write-Host "Destino: $GamePath" -ForegroundColor Cyan
    Write-Host "Descargando $total archivos...`n"
    foreach ($url in $urls) {
        $filename = Split-Path -Leaf $url
        $dest = Join-Path $GamePath $filename
        $done++
        Write-Host "  [$done/$total] $filename" -NoNewline
        try {
            Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
            Write-Host " - OK" -ForegroundColor Green
        } catch {
            Write-Host " - FALLO: $_" -ForegroundColor Red
        }
    }
    Write-Host "`nListo." -ForegroundColor Green
}

# ─── Main ────────────────────────────────────────────────────

Write-Host "`n=== Nightlight Game Launcher - Bypass Script ===" -ForegroundColor Magenta

$steamPath = Get-SteamPath
Write-Host "`nSteam detectado en: $steamPath" -ForegroundColor DarkGray
$libs = Get-SteamLibraries -SteamPath $steamPath
Write-Host "Escaneando $($libs.Count) librerias..." -ForegroundColor DarkGray

$found = Find-Games -LibraryPaths $libs

$menu = [ordered]@{}
$idx = 1
foreach ($key in $games.Keys) {
    if ($found.ContainsKey($key)) {
        $menu["$idx"] = @{ Key=$key; Path=$found[$key]; Auto=$true }
        Write-Host "  [$idx] $($games[$key].Name) -> $($found[$key])" -ForegroundColor Yellow
        $idx++
    }
}
$manualIdx = $idx
Write-Host "  [$manualIdx] Elegir carpeta manualmente..." -ForegroundColor Yellow
$menu["$manualIdx"] = @{ Key=$null; Path=$null; Auto=$false }
$idx++
$exitIdx = $idx
Write-Host "  [$exitIdx] Salir" -ForegroundColor Yellow

do {
    $choice = Read-Host "`nElegi un numero"
    if ($choice -eq $exitIdx) {
        Write-Host "Chau." -ForegroundColor Magenta
        exit 0
    }
    if ($choice -eq $manualIdx) {
        Write-Host "`nJuegos disponibles:" -ForegroundColor Cyan
        $gi = 1
        $gmap = @{}
        foreach ($key in $games.Keys) {
            Write-Host "  [$gi] $($games[$key].Name)" -ForegroundColor Yellow
            $gmap["$gi"] = $key
            $gi++
        }
        Write-Host "  [$gi] Volver" -ForegroundColor Yellow
        $gchoice = Read-Host "`nElegi el juego"
        if ($gchoice -eq $gi) { continue }
        if (-not $gmap.ContainsKey($gchoice)) {
            Write-Host "Opcion invalida." -ForegroundColor Red
            continue
        }
        $selKey = $gmap[$gchoice]
        $manualPath = Read-Host "Ruta de la carpeta del juego"
        if (-not (Test-Path -LiteralPath $manualPath -PathType Container)) {
            Write-Host "La carpeta no existe." -ForegroundColor Red
            continue
        }
        Invoke-Bypass -GameKey $selKey -GamePath $manualPath
        exit 0
    }
    if (-not $menu.Contains($choice)) {
        Write-Host "Opcion invalida." -ForegroundColor Red
        continue
    }
    $sel = $menu[$choice]
    Invoke-Bypass -GameKey $sel.Key -GamePath $sel.Path
    exit 0
} while ($true)
