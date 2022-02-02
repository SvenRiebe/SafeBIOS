$SelectLastLog = Get-WinEvent -ProviderName 'Trusted Device | Security Assessment' -MaxEvents 1 | select -ExpandProperty message
$SelectScore = ($SelectLastLog.Split([Environment]::newline) | Select-String 'Score')
$SelectAntivirus = ($SelectLastLog.Split([Environment]::newline) | Select-String 'Antivirus')
$SelectAdminPW = ($SelectLastLog.Split([Environment]::newline) | Select-String 'BIOS Admin')
$SelectBIOSVerify = ($SelectLastLog.Split([Environment]::newline) | Select-String 'BIOS Verification')
$SelectMEVerify = ($SelectLastLog.Split([Environment]::newline) | Select-String 'ME Verification')
$SelectDiskEncrypt = ($SelectLastLog.Split([Environment]::newline) | Select-String 'Disk Encryption')
$SelectFirewall = ($SelectLastLog.Split([Environment]::newline) | Select-String 'Firewall solution')
$SelectIOA = ($SelectLastLog.Split([Environment]::newline) | Select-String 'Indicators of Attack')
$SelectTPM = ($SelectLastLog.Split([Environment]::newline) | Select-String 'TPM enabled')


$OutputScore = ($SelectScore.Line).Split(' ')
$OutputAntivirus = ($SelectAntivirus.Line).Split(' ')
$OutputAdminPW = ($SelectAdminPW.Line).Split(' ')
$OutputBIOSVerify =($SelectBIOSVerify.Line).Split(' ')
$OutputMEVerify = ($SelectMEVerify.Line).Split(' ')
$OutputDiskEncrypt = ($SelectDiskEncrypt.Line).Split(' ')
$OutputFirewall = ($SelectFirewall.Line).Split(' ')
$OutputIOA = ($SelectIOA.Line).Split(' ')
$OutputTPM = ($SelectTPM.Line).Split(' ')

if ($OutputMEVerify -match 'UNAVAILABLE')
    {
    $OutputMEVerify = 'Pass'
    }
Else
    {
    #No action needed
    }


$hash = @{ SecurityScore = $OutputScore[1]; AntiVirus = $OutputAntivirus[6]; BIOSAdminPW = $OutputAdminPW[5]; BIOSVerfication = $OutputBIOSVerify[3]; DiskEncryption = $OutputDiskEncrypt[3];Firewall = $OutputFirewall[6]; IndicatorOfAttack = $OutputIOA[5]; TPM = $OutputTPM[3]; vProVerification = $OutputMEVerify[3]} 

return $hash | ConvertTo-Json -Compress