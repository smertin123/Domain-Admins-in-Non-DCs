switch ($args[0])
{
    #if arguments invalid, output error
    default {
        Write-Host "Use the -h flag for help"
    }

    #if argument -h show help
    "-h" {
        Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
        Write-Host "#-#-#-#    Domain Administrators in Non-Domain Controllers Scanner    #-#-#-#"
        Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#=#-#-#"
        Write-Host ""
        Write-Host "-l: Provide list of Domain Administrators"
        Write-Host ""
        Write-Host "If you dont have a list of Domain Administrators, you can get one with:"
        Write-Host "--da-scan: Scan for domain administrators"
        Write-Host "-c: Promt for credentials"
        Write-Host "-o: Choose alternative output file (Default domain-admin-scan-results.txt)"
        Write-Host ""
        Write-Host ""
        Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#    Available scans   #-#-#-#-#-#-#-#-#-#-#-#-#-#"
        Write-Host ""
        Write-Host "Domain Administrator sessions:"
        Write-Host "--local-sessions: Scan the local machine for Domain Administrator sessions"
        Write-Host "--remote-sessions: Scan a remote machine for Domain Administrator sessions"
        Write-Host "-r: Provide a list of remote machines to scan"
        Write-Host ""
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
        if($args[1] -eq "-c" -Or $args[3] -eq "-c") {
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
        } elseif ($args.Length -eq 2) {
            throw "Scan argument required. See Help for available scans"  
        } else {
            $Das = Get-Content -Path $args[1]

            switch ($args[2]) {
                #if argument --local-sessions is passed do this:
                "--local-sessions" {
                    Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
                    Write-Host "#-#-#-#-#   Scanning $env:computername for Domain Administrator sessions  #-#-#-#-#"
                    Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
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
                        Write-Output "[+] $Da has a current session"
                        }
                    }
                    Write-Host ""
                }
                #if argument --remote-sessions is passed do this:
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
                                Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
                                Write-Host "#-#-#-#-#   Scanning all machines in $FileName for Domain Administrator sessions  #-#-#-#-#-#"
                                Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
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
                                            Write-Output "[+] $Da has a current session on $HostName"
                                            }
                                        }
                                        Write-Host ""
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
                            Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
                            Write-Host "#-#-#-#-#   Scanning $RemoteHost for Domain Administrator sessions     #-#-#-#-#"
                            Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
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
                                Write-Output "[+] $Da has a current session"
                                }
                            }
                            Write-Host "" 
                        }
                    } else {
                        throw "Remote host or list required"
                    }
                }
                #if argument --local-processes is passed do this:
                "--processes" {
                    Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
                    Write-Host "#-#-#-#-#   Scanning $env:computername for Domain Administrator processes  #-#-#-#-#"
                    Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
                    Write-Host ""
                    foreach($Da in $Das) {
                        Get-WmiObject -Class Win32_Process | Select Name, @{Name="UserName";Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}} | Select-String -Pattern $Da
                    }
                    Write-Host ""
                }
            }
        }
    }
}