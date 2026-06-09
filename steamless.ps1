param($ExePath)
$tmp="$env:TEMP\steamless"
New-Item -ItemType Directory -Force -Path $tmp|Out-Null
irm "https://github.com/atom0s/Steamless/releases/download/v3.1.0.5/Steamless.v3.1.0.5.-.by.atom0s.zip" -OutFile "$tmp\s.zip"
Expand-Archive "$tmp\s.zip" $tmp -Force
& "$tmp\Steamless.CLI.exe" $ExePath
if(Test-Path "$ExePath.unpacked.exe"){Remove-Item $ExePath -Force;Rename-Item "$ExePath.unpacked.exe" $ExePath}
