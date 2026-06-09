param($ExePath)
$tmp = "$env:TEMP\steamless"
$zip = "$tmp\steamless.zip"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Invoke-WebRequest "https://github.com/atom0s/Steamless/releases/download/v3.1.0.5/Steamless.v3.1.0.5.-.by.atom0s.zip" -OutFile $zip
Expand-Archive -Path $zip -DestinationPath $tmp -Force
& "$tmp\Steamless.CLI.exe" $ExePath
