$banner = @"

___________________________   ____ ___  _____ __________ 
\_   _____/  _____/\______ \ |    |   \/     \\______   \
 |    __)/   \  ___ |    |  \|    |   /  \ /  \|     ___/
 |     \ \    \_\  \|    `   \    |  /    Y    \    |    
 \___  /  \______  /_______  /______/\____|__  /____|    
     \/          \/        \/                \/          
	                                  
					Powered by Peppe

"@

Write-Host $banner -ForegroundColor Red


$putty_executable = "C:\Program Files\PuTTY\putty.exe"

# Download From: http://kb.fortinet.com/kb/viewContent.do?externalId=11186
$fgt2eth_executable = Get-ChildItem -Path $env:USERPROFILE -Recurse -Filter fgt2eth.exe 2> $null | Select-Object -ExpandProperty FullName


$FortigateHost = $( Write-Host "Fortigate IP: " -ForegroundColor Yellow -NoNewline; Read-Host )
$FortigateUser = $( Write-Host "Username: " -ForegroundColor Yellow -NoNewline; Read-Host )
$FortigatePassword = $( Write-Host "Password: " -ForegroundColor Yellow -NoNewline; Read-Host -AsSecureString )
$plainPwd =[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($FortigatePassword))

$CaptureInterface=$(  Write-Host "Interface: " -ForegroundColor Yellow -NoNewline; Read-Host )
$CaptureFilter=$(  Write-Host "Filter (es: host x.x.x.x): " -ForegroundColor Yellow -NoNewline; Read-Host )

$FortigateCommand = "diagnose sniffer packet $CaptureInterface '$CaptureFilter' 3 0 a"

Write-host " "
Write-host "Executing over Putty ""$FortigateCommand""" -ForegroundColor Green

[console]::Resetcolor()

# ------------------------- Debugging Variables --------------------------------
$KEEP_FORTIGATE_COMMAND_FILE = $false        # Keeps the Generate Fortigate Command file for Putty
$REMOVE_PUTTY_LOG_HEADER = $true            # Removes the ~~~Putty from Capture
$REMOVE_PUTTY_LOG_AFTER_PROCESSING = $true  # Removes Putty Log after Conveting it into fgt2eth
$DISABLE_FGT2ETH_PROCESSING = $false         # Disable the Conversion Process from PuttyLog to Etheral

# ---------------------- Constants ---------------------------------------------
$CaptureFolderName = "capture"
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$CaptureDirectory = "$DesktopPath\$CaptureFolderName"
$CaptureFileNameTemplate = "$($FortigateHost)-$($CaptureInterface)-$(get-date -f MM-dd-yyyy_HH_mm_ss)"
$CaptureFile = "$($CaptureDirectory)\$($CaptureFileNameTemplate).log"
$CapturePcapFile = "$($CaptureDirectory)\$($CaptureFileNameTemplate).pcap"

# Ensure Capture Folder Exists
if(-not (Test-Path -Path $CaptureDirectory)){
    New-Item -ItemType Directory -Path $CaptureDirectory | Out-Null
}

# Create Command File for Putty
$PuttySSHCommandFile = "$CaptureDirectory\$([guid]::NewGuid())-$(get-date -f yyMMdd_HHmmss).ftgcmd"
$FortigateCommand | Set-Content -Encoding ASCII -Path $PuttySSHCommandFile -Force
if(-not (Test-Path -Path $PuttySSHCommandFile)) { 
    Write-Error -Message "Could not find Generated Fortigate Putty Command file under $PuttySSHCommandFile" -ErrorAction Stop
    
}

# Run Putty as Process and Wait until someone close it
$cmd_args = @(
    "-ssh","$($FortigateUser)@$($FortigateHost)",
    "-pw","$($plainPwd)",
    "-sessionlog","$($CaptureFile)",
    "-m","$($PuttySSHCommandFile)"
)

$putty_process = Start-Process -Wait -WorkingDirectory $CaptureDirectory -FilePath $putty_executable -ArgumentList $cmd_args

# Remove Command File for Putty after processing
if((Test-Path -Path $PuttySSHCommandFile) -and -not $KEEP_FORTIGATE_COMMAND_FILE)
{
    Remove-Item $PuttySSHCommandFile -Confirm:$false
}

if( (Test-Path -Path $CaptureFile))
{
    if(-not $DISABLE_FGT2ETH_PROCESSING ){
        # Convert the Putty Log into pcap File with f2gteth.exe
        $cmd_fgt2eth_args = @(
            "-in","$($CaptureFile)",
            "-out","$($CapturePcapFile)",
            "-system","windows"
        )
        $fgt2eth_process = Start-Process -Wait -WorkingDirectory $CaptureDirectory -FilePath $fgt2eth_executable -ArgumentList $cmd_fgt2eth_args
    }
    
    if($REMOVE_PUTTY_LOG_AFTER_PROCESSING)
    {
        Remove-Item $CaptureFile -Confirm:$false
		    Remove-Item "$CaptureDirectory\output.tmp" -Confirm:$false
    }

}else{
    Write-Error -Message "Could not find the Captured file under $CaptureFile"
    return
}
