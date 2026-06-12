param($AppId)

function Get-SteamPath {
    $paths = @(
        "HKCU:\Software\Valve\Steam",
        "HKLM:\Software\WOW6432Node\Valve\Steam",
        "HKLM:\Software\Valve\Steam"
    )
    foreach ($p in $paths) {
        try {
            $val = (Get-ItemProperty -Path $p -Name "SteamPath" -ErrorAction Stop).SteamPath
            if ($val) { return ($val.Trim('"') -replace '/', '\') }
        } catch {}
    }
    return "C:\Program Files (x86)\Steam"
}

function Get-SteamInstallPath($AppId) {
    $steam = Get-SteamPath
    $content = Get-Content "$steam\steamapps\libraryfolders.vdf" -Raw
    $paths = [regex]::Matches($content, '"path"\s+"([^"]+)"') | ForEach-Object { $_.Groups[1].Value -replace '\\\\','\' -replace '/','\' }
    foreach ($path in $paths) {
        $manifest = "$path\steamapps\appmanifest_$AppId.acf"
        if (Test-Path $manifest) {
            $mc = Get-Content $manifest -Raw
            $m = [regex]::Match($mc, '"installdir"\s+"([^"]+)"')
            if ($m.Success) { return "$path\steamapps\common\$($m.Groups[1].Value)" }
        }
    }
    return $null
}

# Patrones de exes a ignorar (redistributables, launchers de terceros, etc.)
$skipPatterns = @(
    'redist', 'vcredist', 'directx', 'dxsetup', 'vc_redist',
    'dotnet', 'setup', 'install', 'uninstall', 'crashreport',
    'crashhandler', 'bugsplat', 'easyanticheat', 'battleye',
    'be_service', 'launch', '_launcher', 'bootstrap',
    'cefprocess', 'cef_process', 'steamwebhelper', 'uplay'
)

function Should-Skip($exeName) {
    $lower = $exeName.ToLower()
    foreach ($p in $skipPatterns) {
        if ($lower -like "*$p*") { return $true }
    }
    return $false
}

$installPath = Get-SteamInstallPath $AppId
if (-not $installPath) { Write-Error "No se encontro la instalacion para appid $AppId"; exit 1 }

$exes = Get-ChildItem -Path $installPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue

$candidates = $exes | Where-Object { -not (Should-Skip $_.Name) }

Write-Host "Instalacion: $installPath"
Write-Host "Exes encontrados: $($exes.Count) total, $($candidates.Count) candidatos"

# Descargar Steamless una sola vez
$tmp = "$env:TEMP\steamless"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
if (-not (Test-Path "$tmp\Steamless.CLI.exe")) {
    Write-Host "Descargando Steamless..."
    irm "https://github.com/atom0s/Steamless/releases/download/v3.1.0.5/Steamless.v3.1.0.5.-.by.atom0s.zip" -OutFile "$tmp\s.zip"
    Expand-Archive "$tmp\s.zip" $tmp -Force
}

$ok = 0
$skipped = 0

foreach ($exe in $candidates) {
    Write-Host "`nProcesando: $($exe.FullName)"
    & "$tmp\Steamless.CLI.exe" $exe.FullName
    if (Test-Path "$($exe.FullName).unpacked.exe") {
        Remove-Item $exe.FullName -Force
        Rename-Item "$($exe.FullName).unpacked.exe" $exe.FullName
        Write-Host "  -> Unpacked OK"
        $ok++
    } else {
        Write-Host "  -> Sin DRM o fallo, se deja como esta"
        $skipped++
    }
}

Write-Host "`nListo: $ok unpacked, $skipped sin cambios"
