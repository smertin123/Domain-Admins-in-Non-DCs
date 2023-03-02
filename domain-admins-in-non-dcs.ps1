#Store all scans in functions

Function Get-DAs {
    param (
        $FilePath,
        $GetCreds
    )

    Import-Module ActiveDirectory
    #if output file requested as second argument, store third argument as filename
    if($GetCreds -eq "True") {
        $cred = Get-Credential
        $DomainAdmins = Get-ADGroupMember -Credential $cred -Identity "Domain Admins" | select -ExpandProperty "SamAccountName" | Out-File -FilePath $FilePath
        Write-Host "File created: "$FilePath
    } else {
    #get a list of admins, select the name only, output results to file 
    $DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" | select -ExpandProperty "SamAccountName" | Out-File -FilePath $FilePath
    Write-Host "File created: "$FilePath
    }
}

Function Get-Sessions {
    param (
        $FileName,
        $HostName
    )

    Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
    Write-Host "#-#-#-#-#-#-#-#-#   Scanning for Domain Administrator sessions  #-#-#-#-#-#-#-#-#-#"
    Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
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
            }
        }
        Write-Host ""
    }

    if ($FileName) {
        $HostFile = Get-Content -Path $FileName
        foreach($HostName in $HostFile) {
            Try {
                Get-RemoteSessions -HostName $HostName
                #if connection  error, output the host to console
            } Catch [System.Runtime.InteropServices.COMException] {
                Write-Error "Error: $HostName is unavailable"
            }                                  
        }
    } elseif ($HostName) {
        Try {
            Get-RemoteSessions -HostName $HostName
            #if connection  error, output the host to console
        } Catch [System.Runtime.InteropServices.COMException] {
            Write-Error "Error: $HostName is unavailable"
        }
    } else {
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
}

Function Get-Processes {
    Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
    Write-Host "#-#-#-#-#-#-#-#   Scanning for Domain Administrator processes   #-#-#-#-#-#-#-#-#-#"
    Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
    Write-Host ""
    foreach($Da in $Das) {
        Get-WmiObject -Class Win32_Process | Select Name, @{Name="UserName";Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}} | Select-String -Pattern $Da
    }
}

Function Get-UserDirs {
    param (
        $FileName,
        $HostName
    )
    Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
    Write-Host "#-#-#-#-#-#-#   Scanning for Domain Administrator user directories  #-#-#-#-#-#-#-#"
    Write-Host "#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
    Write-Host ""

    Function Get-RemoteDirs {
        param (
            $HostName
        )

        Try {
            $drive = (Get-WmiObject Win32_OperatingSystem -ComputerName $HostName).SystemDrive
            $drive = $drive[0]
        } Catch {
            Write-Host "Cannot identify default Windows drive for machine $HostName"
        }
        Write-Host "[+] $HostName contains User directories for the following Domain Administrators:"
        #scan default drive user dir for domain administrators
        foreach($Da in $Das) {
            Try {
                Get-ChildItem \\$HostName\$drive$\Users | Select-String -Pattern $Da
            } Catch [System.Runtime.InteropServices.COMException] {
                Write-Error "Error: $HostName is unavailable"
            }
        }
    }

    if($FileName) {
        #get the file contents
        $HostFile = Get-Content -Path $FileName
        foreach($HostName in $HostFile) {
            #find the default Windows drive
            Get-RemoteDirs -HostName $HostName
        }
    } elseif ($HostName) {
        Get-RemoteDirs -HostName $HostName
    } else {
        #find the default Windows drive
        $drive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
        #scan default drive user dir for domain administrators
        foreach($Da in $Das) {
            Get-ChildItem $drive"\Users" | Select-String -Pattern $Da
        }
    }
}


#act based on arguments
switch ($args[0])
{
    #if arguments invalid, output error
    default {
        Write-Host "Use the -h flag for help"
    }

    #if argument -h show help
    "-h" {
        Write-Host ""
        Write-Host " #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#"
        Write-Host " #-#-#-#    Domain Administrators in Non-Domain Controllers Scanner    #-#-#-#"
        Write-Host " #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#=#-#-#"
        Write-Host ""
        Write-Host " -l: Provide list of Domain Administrators"
        Write-Host ""
        Write-Host "     -------------------------------------"
        Write-Host "     ##  Get Domain Administrator list  ##"
        Write-Host "     -------------------------------------"
        Write-Host " --da-scan: Scan for Domain Administrators"
        Write-Host " -c: Promt for credentials"
        Write-Host " -o: Choose alternative output file (Default domain-admin-scan-results.txt)"
        Write-Host ""
        Write-Host ""
        Write-Host " #-#-#-#-#-#-#-#-#-#-#    Available scans   #-#-#-#-#-#-#-#-#-#-#"
        Write-Host "     ***   All scans require a Domain Administrator list   ***"
        Write-Host ""
        Write-Host "       ----------------"
        Write-Host "       ##  Sessions  ##"
        Write-Host "       ----------------"
        Write-Host " --local-sessions: Scan the local machine for Domain Administrator sessions"
        Write-Host " --remote-sessions: Scan a remote machine for Domain Administrator sessions"
        Write-Host " -r: Provide a list of remote machines to scan"
        Write-Host ""
        Write-Host "       -----------------"
        Write-Host "       ##  Processes  ##"
        Write-Host "       -----------------"
        Write-Host " --processes: List processes on the local machine owned by Domain Administrators"
        Write-Host ""
        Write-Host "      ------------------------"
        Write-Host "      ##  User directories  ##"
        Write-Host "      ------------------------"
        Write-Host " --local-user-dirs: Scan the local machines default Windows drive for Domain Administrator user directories"
        Write-Host " --remote-user-dirs: Scan a remotel machines default Windows drive for Domain Administrator user directories"
        Write-Host " -r: Provide a list of remote machines to scan"
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
        #if user requests a cred prompt
        if($args[1] -eq "-c" -Or $args[3] -eq "-c") {
            #call Get-DAs function and prompt for creds
            Get-DAs -FilePath $FilePath -GetCreds True
            #if no cred prompt request, call Get-DAs function as current user
        } else {
            Get-DAs -FilePath $FilePath
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
                #if argument --local-sessions is passed call Get-Sessions function:
                "--local-sessions" {
                    Get-Sessions
                }
                #if argument --remote-sessions is passed Get-Sessions function with filename:
                "--remote-sessions" { 
                    if ($args[3]) {
                        #if list argument passed
                        if ($args[3] -eq "-r") {
                            #check for filename
                            if ($args[4]) {
                                $FileName = $args[4]
                                Get-Sessions -FileName $FileName
                            } else {
                                throw "File required"
                            }
                        } else {
                            #if single remote host supplied
                            $HostName = $args[3]
                            Get-Sessions -HostName $HostName 
                        }
                    } else {
                        throw "Remote host or list required"
                    }
                }
                #if argument --processes is passed do this:
                "--processes" {
                    Get-Processes
                }
                #if argument --local-users-dir is passed do this:
                "--local-user-dirs" {
                    Get-UserDirs
                }
                #if argument --remote-users-dir is passed do this:
                "--remote-user-dirs" {
                    #check for remote session argument
                    if ($args[3]) {
                        #get creds from the user
                        #if list argument passed
                        if ($args[3] -eq "-r") {
                            #check for filename
                            if ($args[4]) {
                                $FileName = $args[4]
                                Get-UserDirs -FileName $FileName
                            }
                        } else {
                            $HostName = $args[3]
                            Get-UserDirs -HostName $HostName
                        }
                    } else {
                        throw "Remote host or list required"
                    }
                }
            }
        }
    }
}