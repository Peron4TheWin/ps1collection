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

function Get-SteamExe($AppId) {
    $steam = Get-SteamPath
    $bytes = [IO.File]::ReadAllBytes("$steam\appcache\appinfo.vdf")
    $idBytes = [BitConverter]::GetBytes([uint32]$AppId)
    $idx = 0
    for($i=0;$i-lt$bytes.Length-4;$i++){
        if($bytes[$i] -eq $idBytes[0] -and $bytes[$i+1] -eq $idBytes[1] -and $bytes[$i+2] -eq $idBytes[2] -and $bytes[$i+3] -eq $idBytes[3]){$idx=$i;break}
    }
    if($idx -eq 0){ return $null }
    $str = [System.Text.Encoding]::ASCII.GetString($bytes[$idx..($idx+20000)])
    $m = [regex]::Match($str, '[^\x20-\x7E]([\w][\w\-. ]*\.exe)')
    if($m.Success){ return $m.Groups[1].Value.Trim() }
    return $null
}

function Get-SteamInstallPath($AppId) {
    $steam = Get-SteamPath
    $content = Get-Content "$steam\steamapps\libraryfolders.vdf" -Raw
    $paths = [regex]::Matches($content, '"path"\s+"([^"]+)"') | ForEach-Object { $_.Groups[1].Value -replace '\\\\','\' -replace '/','\' }
    foreach($path in $paths){
        $manifest = "$path\steamapps\appmanifest_$AppId.acf"
        if(Test-Path $manifest){
            $mc = Get-Content $manifest -Raw
            $m = [regex]::Match($mc, '"installdir"\s+"([^"]+)"')
            if($m.Success){ return "$path\steamapps\common\$($m.Groups[1].Value)" }
        }
    }
    return $null
}

$exeName = Get-SteamExe $AppId
$installPath = Get-SteamInstallPath $AppId
if(-not $exeName){ Write-Error "No se encontro el exe para appid $AppId"; exit 1 }
if(-not $installPath){ Write-Error "No se encontro la instalacion para appid $AppId"; exit 1 }
$exePath = "$installPath\$exeName"
if(-not (Test-Path $exePath)){ Write-Error "Exe no existe: $exePath"; exit 1 }
Write-Host "Exe encontrado: $exePath"
$tmp="$env:TEMP\steamless"
New-Item -ItemType Directory -Force -Path $tmp|Out-Null
irm "https://github.com/atom0s/Steamless/releases/download/v3.1.0.5/Steamless.v3.1.0.5.-.by.atom0s.zip" -OutFile "$tmp\s.zip"
Expand-Archive "$tmp\s.zip" $tmp -Force
& "$tmp\Steamless.CLI.exe" $exePath
if(Test-Path "$exePath.unpacked.exe"){
    Remove-Item $exePath -Force
    Rename-Item "$exePath.unpacked.exe" $exePath
    Write-Host "Done: $exePath"
}
