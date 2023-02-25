switch ($args[0])
{
    #if arguments invalid, output error
    default {
        Write-Host "Use the -h flag for help"
    }

    #if argument -h show help
    "-h" {
        Write-Host ""
        Write-Host "This tool offers the ability to scan for Domain Administrator accounts (ActiveDirectory module required):"
        Write-Host "--da-scan: Scan for domain administrators using current user credentials"
        Write-Host "--get-creds: Promt for credentials"
        Write-Host "-o: Choose output file (Default domain-admin-scan-results.txt)"
        Write-Host ""
        Write-Host "To use the das in non dc checker tool:"
        Write-Host "-l: Provide a list of domain administrators"
        Write-Host "--local-sessions: Scan the local machine for current domain administrator sessions"
    }

    #if argument --da-scan, scan for domain admins and output to file
    "--da-scan" {
        Import-Module ActiveDirectory
        #if output file requested as second argument, store third argument as filename
        if($args[1] -eq "-o") {
            $FilePath = $args[2]
        #if output file requested as third argument, store fourth argument as filename
        } elseif($args[2] -eq "-o") {
            $FilePath = $args[3]
        } else {
        #else use the default filename
        $FilePath = ".\domain-admin-scan-results.txt"
        }
        if($args[1] -eq "--get-creds" -Or $args[3] -eq "--get-creds") {
            $cred = Get-Credential
            $DomainAdmins = Get-ADGroupMember -Credential $cred -Identity "Domain Admins" | select -ExpandProperty "SamAccountName" | Out-File -FilePath $FilePath
            Write-Host "File created: "$FilePath
        } else {
        #get a list of admins, select the name only, output results to file 
        $DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" | select -ExpandProperty "SamAccountName" | Out-File -FilePath $FilePath
        Write-Host "File created: "$FilePath
        }            
    }

    #if argument -l, accept a file
    "-l" {
        if ($args.Length -eq 1) {
           throw "List of domain admins required"
        } else {
            $Das = Get-Content -Path $args[1]

            switch ($args[2]) {
                "--local-sessions" {
                    Write-Host "Scanning $env:computername for active domain administrator sessions......."
                    Write-Host ""
                    $WMI = (Get-WmiObject Win32_LoggedOnUser).Antecedent
                    $ActiveUsers = @()
                    foreach($User in $WMI) {
                        $StartOfUsername = $User.LastIndexOf('=') + 2
                        $EndOfUsername = $User.Length - $User.LastIndexOf('=') -3
                        $ActiveUsers += $User.Substring($StartOfUsername,$EndOfUsername)
                    }
                    $ActiveUsers = $ActiveUsers | Select-Object -Unique
                    foreach($Da in $Das) {
                        if ($ActiveUsers -contains $Da) {
                        Write-Output "$Da has a current session"
                        }
                    }
                }

                "--remote-sessions" { 
                    #check for remote session argument
                    if ($args[3]) {
                        #if list argument passed
                        if ($args[3] -eq "-r") {
                            #check for filename
                            if ($args[4]) {
                                $FileName = $args[4]
                                #get the file contents
                                $HostFile = Get-Content -Path $FileName
                                Write-Host "Scanning all machines in $FileName for active domain administrator sessions......."
                                Write-Host ""
                                #loop through each host in file
                                foreach($HostName in $HostFile) {
                                    Try {
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
                                            Write-Output "$Da has a current session on $HostName"
                                            }
                                        }
                                        #if connection  error, output the host to console
                                    } Catch [System.Runtime.InteropServices.COMException] {
                                        Write-Error "Error: $HostName is unavailable"
                                    }                                  
                                }
                            } else {
                                throw "File required"
                            }
                        } else {
                            #if single remote host supplied
                            $RemoteHost = $args[3]
                            Write-Host "Scanning $RemoteHost for active domain administrator sessions......."
                            Write-Host ""
                            $WMI = (Get-WmiObject Win32_LoggedOnUser -ComputerName $RemoteHost).Antecedent
                            $ActiveUsers = @()
                                foreach($User in $WMI) {
                                $StartOfUsername = $User.LastIndexOf('=') + 2
                                $EndOfUsername = $User.Length - $User.LastIndexOf('=') -3
                                $ActiveUsers += $User.Substring($StartOfUsername,$EndOfUsername)
                            }
                            $ActiveUsers = $ActiveUsers | Select-Object -Unique
                            foreach($Da in $Das) {
                                if ($ActiveUsers -contains $Da) {
                                Write-Output "$Da has a current session"
                                }
                            }
                        }
                    } else {
                        throw "Remote host required"
                    }
                }
            }
        }
    }
}