<#
.SYNOPSIS
    STFixer offline setup completo en PowerShell.
    Aplica P4/P5/P6 al payload + Core1/Core2 al DLL hijackeado.
    Soluciona "no internet connection" en SteamTools.
#>
#Requires -Version 5.1

$AesKey = [byte[]]@(
    0x31, 0x4C, 0x20, 0x86, 0x15, 0x05, 0x74, 0xE1,
    0x5C, 0xF1, 0x1D, 0x1B, 0xC1, 0x71, 0x25, 0x1A,
    0x47, 0x08, 0x6C, 0x00, 0x26, 0x93, 0x55, 0xCD,
    0x51, 0xC9, 0x3A, 0x42, 0x3C, 0x14, 0x02, 0x94
)
$KnownSections = @('.text', '.rdata', '.data', '.pdata', '.fptable', '.rsrc', '.reloc')
$HijackCandidates = @('xinput1_4.dll', 'dwmapi.dll')

# ── Embedded C# helpers ─────────────────────────────────────────────────────
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.IO.Compression;

public static class ZLibHelper
{
    public static byte[] Compress(byte[] data)
    {
        using (var ms = new MemoryStream())
        {
            ms.WriteByte(0x78); ms.WriteByte(0xDA);
            using (var deflate = new DeflateStream(ms, CompressionLevel.Optimal, true))
                deflate.Write(data, 0, data.Length);
            uint adler = Adler32(data);
            ms.WriteByte((byte)((adler >> 24) & 0xFF));
            ms.WriteByte((byte)((adler >> 16) & 0xFF));
            ms.WriteByte((byte)((adler >> 8) & 0xFF));
            ms.WriteByte((byte)(adler & 0xFF));
            return ms.ToArray();
        }
    }

    public static byte[] Decompress(byte[] data)
    {
        if (data.Length < 6) return null;
        using (var ms = new MemoryStream(data, 2, data.Length - 2))
        using (var deflate = new DeflateStream(ms, CompressionMode.Decompress))
        using (var outMs = new MemoryStream())
        {
            deflate.CopyTo(outMs);
            return outMs.ToArray();
        }
    }

    private static uint Adler32(byte[] data)
    {
        uint a = 1, b = 0;
        foreach (byte v in data) { a = (a + v) % 65521; b = (b + a) % 65521; }
        return (b << 16) | a;
    }
}
"@ -ErrorAction SilentlyContinue

# ── Crypto helpers ───────────────────────────────────────────────────────────
function Decrypt-AES {
    param([byte[]]$Ciphertext, [byte[]]$Key, [byte[]]$IV)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key; $aes.IV = $IV
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $ms = New-Object IO.MemoryStream(,$Ciphertext)
    $cs = New-Object Security.Cryptography.CryptoStream($ms, $aes.CreateDecryptor(), [Security.Cryptography.CryptoStreamMode]::Read)
    $out = New-Object IO.MemoryStream; $cs.CopyTo($out)
    $r = $out.ToArray(); $cs.Dispose(); $ms.Dispose(); $out.Dispose(); $aes.Dispose()
    return $r
}

function Encrypt-AES {
    param([byte[]]$Plaintext, [byte[]]$Key, [byte[]]$IV)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key; $aes.IV = $IV
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $ms = New-Object IO.MemoryStream
    $cs = New-Object Security.Cryptography.CryptoStream($ms, $aes.CreateEncryptor(), [Security.Cryptography.CryptoStreamMode]::Write)
    $cs.Write($Plaintext, 0, $Plaintext.Length); $cs.FlushFinalBlock()
    $r = $ms.ToArray(); $cs.Dispose(); $ms.Dispose(); $aes.Dispose()
    return $r
}

# ── Byte helpers ─────────────────────────────────────────────────────────────
function Test-Bytes {
    param([byte[]]$Data, [int]$Offset, [byte[]]$Expected)
    if ($Offset -lt 0 -or ($Offset + $Expected.Length) -gt $Data.Length) { return $false }
    for ($i = 0; $i -lt $Expected.Length; $i++) {
        if ($Data[$Offset + $i] -ne $Expected[$i]) { return $false }
    }
    return $true
}

function Find-Pattern {
    param([byte[]]$Data, [int]$Start, [int]$End, [byte[]]$Pattern, [byte[]]$Mask)
    $limit = [Math]::Min($End, $Data.Length) - $Pattern.Length
    for ($i = $Start; $i -le $limit; $i++) {
        $match = $true
        for ($j = 0; $j -lt $Pattern.Length; $j++) {
            if ($Mask[$j] -ne 0 -and $Data[$i + $j] -ne $Pattern[$j]) { $match = $false; break }
        }
        if ($match) { return $i }
    }
    return -1
}

function Find-Bytes {
    param([byte[]]$Data, [int]$Start, [int]$End, [byte[]]$Needle)
    $limit = [Math]::Min($End, $Data.Length) - $Needle.Length
    for ($i = $Start; $i -le $limit; $i++) {
        if (Test-Bytes $Data $i $Needle) { return $i }
    }
    return -1
}

function Read-I32 {
    param([byte[]]$Data, [int]$Offset)
    return [BitConverter]::ToInt32($Data, $Offset)
}

function Skip-Bridge {
    param([byte[]]$Data, [int]$Offset)
    if (Test-Bytes $Data $Offset @(0xE9)) { return $Offset + 5 }
    return $Offset
}

# ── PE parsing ───────────────────────────────────────────────────────────────
function Parse-PESections {
    param([byte[]]$Pe)
    if ($Pe.Length -lt 64) { return @() }
    $peOff = [BitConverter]::ToInt32($Pe, 0x3C)
    if ($peOff -lt 0 -or ($peOff + 24) -gt $Pe.Length) { return @() }
    if ($Pe[$peOff] -ne [byte]'P'[0] -or $Pe[$peOff+1] -ne [byte]'E'[0]) { return @() }
    $numSections = [BitConverter]::ToUInt16($Pe, $peOff + 6)
    if ($numSections -gt 96) { return @() }
    $optSize = [BitConverter]::ToUInt16($Pe, $peOff + 20)
    $firstSection = $peOff + 24 + $optSize
    if ($firstSection -gt $Pe.Length) { return @() }
    $sections = @()
    for ($i = 0; $i -lt $numSections; $i++) {
        $off = $firstSection + $i * 40
        if ($off + 40 -gt $Pe.Length) { break }
        $nameEnd = 0
        for ($j = 0; $j -lt 8; $j++) { if ($Pe[$off + $j] -eq 0) { break }; $nameEnd = $j + 1 }
        $name = [Text.Encoding]::ASCII.GetString($Pe, $off, $nameEnd)
        $sections += @{
            Name=$name; VirtualSize=[BitConverter]::ToUInt32($Pe,$off+8); VirtualAddress=[BitConverter]::ToUInt32($Pe,$off+12)
            RawSize=[BitConverter]::ToUInt32($Pe,$off+16); RawOffset=[BitConverter]::ToUInt32($Pe,$off+20)
        }
    }
    return $sections
}

# ── P4 resolver ──────────────────────────────────────────────────────────────
function Find-P4 {
    param([byte[]]$Payload, [int]$Start, [int]$End)
    $pattern = @(0x4D, 0x85, 0xC0); $mask = @(0xFF, 0xFF, 0xFF)
    $i = $Start
    while ($true) {
        $hit = Find-Pattern $Payload $i $End $pattern $mask
        if ($hit -lt 0) { return -1 }
        $pos = $hit + 3
        $pos = Skip-Bridge $Payload $pos
        if (-not (Test-Bytes $Payload $pos @(0x0F, 0x84))) { $i = $hit + 1; continue }
        $pos += 6
        if (-not (Test-Bytes $Payload $pos @(0xE8))) { $i = $hit + 1; continue }
        $pos += 5
        if (-not (Test-Bytes $Payload $pos @(0x85, 0xC0))) { $i = $hit + 1; continue }
        $pos += 2
        $pos = Skip-Bridge $Payload $pos
        if (-not (Test-Bytes $Payload $pos @(0x0F, 0x85))) { $i = $hit + 1; continue }
        $pos += 6
        if (-not (Test-Bytes $Payload $pos @(0xC6, 0x05))) { $i = $hit + 1; continue }
        if ($pos + 6 -ge $Payload.Length -or $Payload[$pos + 6] -ne 0x01) { $i = $hit + 1; continue }
        $pos += 7
        $pos = Skip-Bridge $Payload $pos
        if (-not (Test-Bytes $Payload $pos @(0xE9))) { $i = $hit + 1; continue }
        $pos += 5
        if (-not (Test-Bytes $Payload $pos @(0xC6, 0x05))) { $i = $hit + 1; continue }
        if ($pos + 6 -ge $Payload.Length) { $i = $hit + 1; continue }
        $val = $Payload[$pos + 6]
        if ($val -eq 0x00 -or $val -eq 0x01) { return $pos }
        $i = $hit + 1
    }
}

# ── P5 resolver ──────────────────────────────────────────────────────────────
function Find-P5 {
    param([byte[]]$Payload, [int]$Start, [int]$End)
    $pattern = @(
        0x66,0x48,0x0F,0x7E,0xC7, 0x66,0x48,0x0F,0x7E,0xCE,
        0x48,0x8D,0x4D,0x00, 0xE8,0x00,0x00,0x00,0x00,
        0x48,0x85,0xF6,0x00
    )
    $mask = @(
        0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0x00, 0xFF,0x00,0x00,0x00,0x00,
        0xFF,0xFF,0xFF,0x00
    )
    $i = $Start
    while ($true) {
        $hit = Find-Pattern $Payload $i $End $pattern $mask
        if ($hit -lt 0) { return -1 }
        # validator
        if ($hit + 24 -gt $Payload.Length) { $i = $hit + 1; continue }
        $opcode = $Payload[$hit + 22]
        if ($opcode -ne 0x75 -and $opcode -ne 0xEB) { $i = $hit + 1; continue }
        $skipDist = [int][sbyte]$Payload[$hit + 23]
        if ($skipDist -le 0) { $i = $hit + 1; continue }
        $afterSkip = $hit + 24 + $skipDist
        if ($afterSkip -gt $Payload.Length) { $i = $hit + 1; continue }
        $foundE9 = $false
        for ($j = $hit + 24; $j -lt $afterSkip -and $j -lt $Payload.Length - 4; $j++) {
            if ($Payload[$j] -eq 0xE9) {
                if ((Read-I32 $Payload ($j+1)) -lt 0) { $foundE9 = $true; break }
            }
        }
        if ($foundE9) { return $hit + 22 }  # patch offset = hit + pattern->PatchOffset(22)
        $i = $hit + 1
    }
}

# ── P6 resolver ──────────────────────────────────────────────────────────────
function Find-P6 {
    param([byte[]]$Payload)
    $pattern = @(
        0x34,0x38,0x20,0x38,0x39,0x20,0x35,0x43,0x20,0x32,0x34,0x20,0x31,0x38,0x20,0x35,0x35,0x20
    )
    $mask = @(
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    )
    $i = 0
    while ($true) {
        $hit = Find-Pattern $Payload $i $Payload.Length $pattern $mask
        if ($hit -lt 0) { return -1 }
        # validator: old or new
        if ($hit + 48 -gt $Payload.Length) { $i = $hit + 1; continue }
        $isOld = $Payload[$hit+18] -eq 0x35 -and $Payload[$hit+19] -eq 0x36 -and
                 $Payload[$hit+44] -eq 0x5E -and $Payload[$hit+45] -eq 0x00
        $isNew = $Payload[$hit+18] -eq 0x35 -and $Payload[$hit+19] -eq 0x37 -and
                 $Payload[$hit+46] -eq 0x43 -and $Payload[$hit+47] -eq 0x00
        if ($isOld -or $isNew) { return $hit }
        $i = $hit + 1
    }
}

# ── Core DLL resolver ────────────────────────────────────────────────────────
function Find-CoreDLL {
    param([string]$SteamPath)
    foreach ($name in $HijackCandidates) {
        $path = Join-Path $SteamPath $name
        if (Test-Path $path) {
            $buf = [IO.File]::ReadAllBytes($path)
            if ((Find-Bytes $buf 0 $buf.Length $AesKey) -ge 0) { return $path }
        }
    }
    return $null
}

function Find-Core1 {
    param([byte[]]$Dll, [int]$TextStart, [int]$TextEnd)
    $pattern = @(
        0x48,0x8B,0x4C,0x24,0x00, 0x48,0x8D,0x55,0x00,0x00,0x00,0x00,0x00,0x00,
        0x85,0xC0, 0x0F,0x84,0x00,0x00,0x00,0x00, 0x41,0x83,0xFC,0x01
    )
    $mask = @(
        0xFF,0xFF,0xFF,0xFF,0x00, 0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,
        0xFF,0xFF, 0xFF,0xFF,0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF
    )
    $i = $TextStart
    while ($true) {
        $hit = Find-Pattern $Dll $i $TextEnd $pattern $mask
        if ($hit -lt 0) { return -1 }
        # validator: opcode at hit+9 is E8 (CALL) or already patched B8
        $op = $Dll[$hit + 9]
        if ($op -eq 0xE8) {
            if ((Read-I32 $Dll ($hit+10)) -lt 0) { return $hit + 9 }
        } elseif ($op -eq 0xB8) {
            return $hit + 9
        }
        $i = $hit + 1
    }
}

function Find-Core2 {
    param([byte[]]$Dll, [int]$Core1Offset, [int]$TextStart, [int]$TextEnd)
    $start = [Math]::Max($TextStart, $Core1Offset - 0x300)
    $end = [Math]::Min($TextEnd, $Core1Offset + 0x300)
    $pattern = @(
        0x49,0x8B,0xD5, 0x48,0x8D,0x4D,0x00, 0xE8,0x00,0x00,0x00,0x00,
        0x85,0xC0, 0x00,0x00, 0x33,0xFF, 0xE9
    )
    $mask = @(
        0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0x00, 0xFF,0x00,0x00,0x00,0x00,
        0xFF,0xFF, 0x00,0x00, 0xFF,0xFF, 0xFF
    )
    $i = $start
    while ($true) {
        $hit = Find-Pattern $Dll $i $end $pattern $mask
        if ($hit -lt 0) { return -1 }
        # validator: byte at hit+14 is 0x74 (jz) or 0xEB (jmp)
        $b = $Dll[$hit + 14]
        if ($b -eq 0x74 -or $b -eq 0xEB) { return $hit + 14 }
        $i = $hit + 1
    }
}

# ── Steam / cache helpers ────────────────────────────────────────────────────
function Get-SteamPath {
    foreach ($rp in @('HKLM:\SOFTWARE\WOW6432Node\Valve\Steam', 'HKLM:\SOFTWARE\Valve\Steam')) {
        try { $p = (Get-ItemProperty $rp -EA Stop).InstallPath; if (Test-Path "$p\steam.exe") { return $p } } catch {}
    }
    foreach ($p in @('C:\Program Files (x86)\Steam', 'C:\Games\Steam')) {
        if (Test-Path "$p\steam.exe") { return $p }
    }
    return $null
}

function Find-PayloadCache {
    param([string]$SteamPath)
    $cacheDir = Join-Path $SteamPath 'appcache\httpcache\3b'
    if (-not (Test-Path $cacheDir)) { return $null }
    $candidates = Get-ChildItem $cacheDir -File | Where-Object {
        $_.Name.Length -eq 16 -and $_.Length -gt 500000 -and $_.Length -lt 5000000
    } | Sort-Object LastWriteTime -Descending
    foreach ($c in $candidates) {
        try {
            $raw = [IO.File]::ReadAllBytes($c.FullName)
            if ($raw.Length -lt 32) { continue }
            $iv = $raw[0..15]; $ct = $raw[16..($raw.Length-1)]
            $plain = Decrypt-AES $ct $AesKey $iv
            if ($plain.Length -lt 6) { continue }
            $decomp = [ZLibHelper]::Decompress($plain[4..($plain.Length-1)])
            if ($decomp.Length -ge 2 -and $decomp[0] -eq [byte]'M'[0] -and $decomp[1] -eq [byte]'Z'[0]) {
                return $c.FullName
            }
        } catch {}
    }
    return $null
}

function Stop-Steam {
    param([string]$SteamPath)
    if (Get-Process steam -EA SilentlyContinue) {
        Write-Host 'Steam is running - shutting down...' -ForegroundColor Yellow
        & "$SteamPath\steam.exe" -shutdown 2>$null
        for ($i = 0; $i -lt 30 -and (Get-Process steam -EA SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
        if (Get-Process steam -EA SilentlyContinue) {
            taskkill /F /IM steam.exe 2>$null | Out-Null; Start-Sleep -Seconds 2
        }
        Write-Host 'Steam closed.' -ForegroundColor Green
    }
}

function Backup-File {
    param([string]$Path)
    $orig = "$Path.orig"
    if (-not (Test-Path $orig)) { Copy-Item $Path $orig -Force; Write-Host "  Original saved: $orig" -ForegroundColor Gray }
    $bak = "$Path.bak"
    Copy-Item $Path $bak -Force; Write-Host "  Backup: $bak" -ForegroundColor Gray
}

function Write-PatchedDll {
    param([string]$Path, [byte[]]$Data)
    try { [IO.File]::WriteAllBytes($Path, $Data) } catch { throw "Could not write $Path - Steam may be running. Close it first." }
}

function Write-PatchedPayload {
    param([string]$CachePath, [byte[]]$PatchedPayload, [byte[]]$IV)
    $recomp = [ZLibHelper]::Compress($PatchedPayload)
    $size = [BitConverter]::GetBytes([uint32]$PatchedPayload.Length)
    $blob = $size + $recomp
    $newCt = Encrypt-AES $blob $AesKey $IV
    $out = $IV + $newCt
    [IO.File]::WriteAllBytes($CachePath, $out)
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
function End-Script {
    param([int]$Code = 0)
    Write-Host "`nPress Enter to exit (auto-closes in 6s)..." -ForegroundColor DarkGray -NoNewline
    if ($Host.Name -match 'ConsoleHost') {
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        while ($stopwatch.ElapsedMilliseconds -lt 6000) {
            if ([Console]::KeyAvailable) {
                [Console]::ReadKey($true) | Out-Null
                break
            }
            Start-Sleep -Milliseconds 100
        }
    } else {
        Start-Sleep -Seconds 6
    }
    exit $Code
}

Write-Host '=== STFixer (full offline setup) ===' -ForegroundColor Cyan
Write-Host ''

$steamPath = Get-SteamPath
if (-not $steamPath) { Write-Host 'ERROR: Steam not found.' -ForegroundColor Red; End-Script -Code 1 }
Write-Host "Steam: $steamPath" -ForegroundColor Gray

Stop-Steam $steamPath

# ── Core DLL ─────────────────────────────────────────────────────────────────
$dllPath = Find-CoreDLL $steamPath
if (-not $dllPath) {
    Write-Host 'WARNING: SteamTools core DLL (xinput1_4.dll / dwmapi.dll) not found.' -ForegroundColor Yellow
    Write-Host 'Patching payload only. Core DLL patches skipped.'
} else {
    Write-Host "`nCore DLL: $dllPath" -ForegroundColor Gray
    $dll = [IO.File]::ReadAllBytes($dllPath)
    $sections = Parse-PESections $dll
    $rdata = $sections | Where-Object Name -eq '.rdata'
    $text = $sections | Where-Object Name -eq '.text'
    if (-not $text) { Write-Host 'ERROR: .text section not found.' -ForegroundColor Red; End-Script -Code 1 }

    $tStart = [int]$text.RawOffset
    $tEnd = [Math]::Min($tStart + $text.RawSize, $dll.Length)

    Write-Host 'Patching Core DLL...' -ForegroundColor Gray

    # Core1: NOP download call
    $c1 = Find-Core1 $dll $tStart $tEnd
    if ($c1 -lt 0) { Write-Host 'ERROR: Core1 not found - unsupported version?' -ForegroundColor Red; End-Script -Code 1 }
    if (Test-Bytes $dll $c1 @(0xB8,0x01,0x00,0x00,0x00)) {
        Write-Host "  Core1: already patched" -ForegroundColor Green
        $c1Applied = $false
    } elseif (Test-Bytes $dll $c1 @(0xE8,0x7C,0xF5,0xFF,0xFF)) {
        $dll[$c1] = 0xB8; $dll[$c1+1] = 0x01; $dll[$c1+2] = 0x00; $dll[$c1+3] = 0x00; $dll[$c1+4] = 0x00
        Write-Host "  Core1 (download call): NOP'd at 0x$('{0:X}' -f $c1)" -ForegroundColor Green
        $c1Applied = $true
    } else {
        Write-Host "  Core1: unexpected bytes at 0x$('{0:X}' -f $c1) - skipping" -ForegroundColor Yellow
        $c1Applied = $false
    }

    # Core2: hash check bypass
    $c2 = Find-Core2 $dll $c1 $tStart $tEnd
    if ($c2 -lt 0) { Write-Host '  Core2: not found (optional, continuing)' -ForegroundColor Yellow }
    else {
        if ($dll[$c2] -eq 0xEB) {
            Write-Host "  Core2: already patched" -ForegroundColor Green
        } elseif ($dll[$c2] -eq 0x74) {
            $dll[$c2] = 0xEB
            Write-Host "  Core2 (hash check): jz->jmp at 0x$('{0:X}' -f $c2)" -ForegroundColor Green
        }
    }
}

# ── Payload ──────────────────────────────────────────────────────────────────
Write-Host "`nFinding payload cache..." -ForegroundColor Gray
$cachePath = Find-PayloadCache $steamPath
if (-not $cachePath) {
    Write-Host 'ERROR: No valid payload cache found.' -ForegroundColor Red
    Write-Host 'Run Steam with SteamTools installed at least once to generate the cache.' -ForegroundColor Yellow
    End-Script -Code 1
}
Write-Host "Payload cache: $cachePath" -ForegroundColor Gray

$raw = [IO.File]::ReadAllBytes($cachePath)
if ($raw.Length -lt 32) { Write-Host 'ERROR: Cache too small.' -ForegroundColor Red; End-Script -Code 1 }
$iv = $raw[0..15]; $ct = $raw[16..($raw.Length-1)]

Write-Host "Decrypting payload..." -ForegroundColor Gray
$dec = Decrypt-AES $ct $AesKey $iv
if ($dec.Length -lt 6) { Write-Host 'ERROR: Decryption failed.' -ForegroundColor Red; End-Script -Code 1 }
$payload = [ZLibHelper]::Decompress($dec[4..($dec.Length-1)])
Write-Host "  Payload: $($payload.Length) bytes" -ForegroundColor Gray
if ($payload[0] -ne [byte]'M'[0] -or $payload[1] -ne [byte]'Z'[0]) {
    Write-Host 'ERROR: Payload does not start with MZ.' -ForegroundColor Red; End-Script -Code 1
}

$sections = Parse-PESections $payload
$obf = $sections | Where-Object { $_.Name -notin $KnownSections } | Select-Object -First 1
$text = $sections | Where-Object Name -eq '.text'
if (-not $obf) { Write-Host 'ERROR: No obfuscated section found.' -ForegroundColor Red; End-Script -Code 1 }
$obfStart = [int]$obf.RawOffset; $obfEnd = [Math]::Min($obfStart + $obf.RawSize, $payload.Length)
$txtStart = if ($text) { [int]$text.RawOffset } else { 0 }
$txtEnd = if ($text) { [Math]::Min($txtStart + $text.RawSize, $payload.Length) } else { 0 }
Write-Host "  Sections: .obf=$($obf.Name) text=present" -ForegroundColor Gray

$patchesApplied = 0; $patchesSkipped = 0

# P4: activation flag
Write-Host "`nSearching patches..." -ForegroundColor Gray
$p4 = Find-P4 $payload $obfStart $obfEnd
if ($p4 -lt 0) {
    Write-Host '  P4 (activation): NOT FOUND - unsupported version?' -ForegroundColor Red
} elseif ($payload[$p4+6] -eq 0x01) {
    Write-Host "  P4 (activation): already patched (01)" -ForegroundColor Green
    $patchesSkipped++
} else {
    $payload[$p4+6] = 0x01
    Write-Host "  P4 (activation): 00 -> 01 at 0x$('{0:X}' -f $p4)" -ForegroundColor Green
    $patchesApplied++
}

# P5: GetCookie retry skip
$p5 = Find-P5 $payload $txtStart $txtEnd
if ($p5 -lt 0) {
    Write-Host '  P5 (GetCookie): NOT FOUND - optional' -ForegroundColor Yellow
} elseif ($payload[$p5] -eq 0xEB) {
    Write-Host '  P5 (GetCookie): already patched' -ForegroundColor Green
    $patchesSkipped++
} elseif ($payload[$p5] -eq 0x75) {
    $payload[$p5] = 0xEB
    Write-Host "  P5 (GetCookie): jnz->jmp at 0x$('{0:X}' -f $p5)" -ForegroundColor Green
    $patchesApplied++
} else {
    Write-Host "  P5: unexpected byte at patch site - skipping" -ForegroundColor Yellow
}

# P6: GMRC pattern fix
$p6 = Find-P6 $payload
if ($p6 -lt 0) {
    Write-Host '  P6 (GMRC): NOT FOUND - optional' -ForegroundColor Yellow
} else {
    $expectedOld = @(0x34,0x38,0x20,0x38,0x39,0x20,0x35,0x43,0x20,0x32,0x34,0x20,0x31,0x38,0x20,0x35,0x35,0x20,0x35,0x36,0x20,0x35,0x37,0x20,0x34,0x31,0x20,0x35,0x35,0x20,0x34,0x31,0x20,0x35,0x37,0x20,0x34,0x38,0x20,0x38,0x44,0x20,0x36,0x43,0x5E,0x00,0x00,0x00)
    $expectedNew = @(0x34,0x38,0x20,0x38,0x39,0x20,0x35,0x43,0x20,0x32,0x34,0x20,0x31,0x38,0x20,0x35,0x35,0x20,0x35,0x37,0x20,0x34,0x31,0x20,0x35,0x34,0x20,0x34,0x31,0x20,0x35,0x36,0x20,0x34,0x31,0x20,0x35,0x37,0x20,0x34,0x38,0x20,0x38,0x44,0x20,0x36,0x43,0x00)
    $isPatched = Test-Bytes $payload $p6 $expectedNew
    if ($isPatched) {
        Write-Host "  P6 (GMRC): already patched" -ForegroundColor Green
        $patchesSkipped++
    } elseif (Test-Bytes $payload $p6 $expectedOld) {
        for ($k = 0; $k -lt $expectedNew.Length; $k++) { $payload[$p6 + $k] = $expectedNew[$k] }
        Write-Host "  P6 (GMRC): string fixed at 0x$('{0:X}' -f $p6)" -ForegroundColor Green
        $patchesApplied++
    } else {
        Write-Host '  P6: unrecognized GMRC pattern - skipping' -ForegroundColor Yellow
    }
}

# ── Write back ───────────────────────────────────────────────────────────────
if ($patchesApplied -eq 0) {
    Write-Host "`nAll patches already applied. Nothing to do." -ForegroundColor Green
    if ($c1Applied) { Backup-File $dllPath; Write-PatchedDll $dllPath $dll }
    End-Script
}

Write-Host "`nApplying patches..." -ForegroundColor Cyan

# Backup and write DLL
if ($c1Applied) {
    Backup-File $dllPath
    Write-PatchedDll $dllPath $dll
    Write-Host "Core DLL updated." -ForegroundColor Green
}

# Backup and write payload
Backup-File $cachePath
Write-PatchedPayload $cachePath $payload $iv
Write-Host "Payload cache updated ($patchesApplied applied, $patchesSkipped skipped)." -ForegroundColor Green

Write-Host "`nDone. Launch Steam and test." -ForegroundColor Cyan
