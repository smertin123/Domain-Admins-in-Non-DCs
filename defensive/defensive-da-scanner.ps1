#Logs
#Create a timestamp variable
$Timestamp = Get-Date
#Specify log files
$LogPath = ".\log.txt"


#Function to check for DA sessions
Function Get-Sessions {
    param (
        $FileName
    )

    Write-Host ""
    Write-Host "Scanning for Domain Administrator sessions..."
    Write-Host ""

    Function Get-RemoteSessions {
        param (
            $HostName
        )

        $WMI = (Get-WmiObject Win32_LoggedOnUser -ComputerName $HostName -ErrorAction Stop).Antecedent
        $ActiveUsers = @()
        foreach($User in $WMI) {
            $StartOfUsername = $User.LastIndexOf('=') + 2
            $EndOfUsername = $User.Length - $User.LastIndexOf('=') -3
            $ActiveUsers += $User.Substring($StartOfUsername,$EndOfUsername)
        }
        $ActiveUsers = $ActiveUsers | Select-Object -Unique
        foreach($Da in $Das) {
            if ($ActiveUsers -contains $Da) {
            Write-Output "[+] $Da has a current session on $HostName"
            Add-Content -Path $LogPath -Value "$Timestamp $Da has a current session on $HostName"
            }
        }
        Write-Host ""
    }

    if ($FileName) {
        $HostFile = Get-Content -Path $FileName
        foreach($HostName in $HostFile) {
            Try {
                Get-RemoteSessions -HostName $HostName -ErrorAction Stop
                #if connection  error, output the host to log file
            } Catch [System.Runtime.InteropServices.COMException] {
                Add-Content -Path $LogPath -Value "$Timestamp $HostName is unavailable"
            }                                  
        }
    } else {
        throw "A list of hostnames is required"
    }
}

