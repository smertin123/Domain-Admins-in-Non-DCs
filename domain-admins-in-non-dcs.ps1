$parameter = $args[0]

switch ($parameter)
{
    #if argument -h show help
    "-h" {
        Write-Host ""
        Write-Host "How to use this scanner:"
        Write-Host ""
        Write-Host "A list of Domain Admins can be obtained with:"
        Write-Host "--da-scan: Scan for domain administrators using Get-ADGroupMember (ActiveDirectory module required)"
        Write-Host "--da-scan-get-creds: Same as above, but request credentials"
        Write-Host ""
        Write-Host "To use the das in non dc checker tool:"
        Write-Host "-l: Provide a list of domain administrators"
        Write-Host ""
    }

    #if argument --da-scan, scan for domain admins and output to file
    "--da-scan" {
        Import-Module ActiveDirectory
        $FilePath = ".\domain-admins-results.txt"
        $DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" | select -ExpandProperty "SamAccountName" | Out-File -FilePath $FilePath
        if (.\domain-admins-results.txt) {
            Write-Host "List of domain administrator saved to: "$FilePath
            }  
        }

    "--da-scan-get-creds" {
        Import-Module ActiveDirectory
        $cred = Get-Credential
        $FilePath = ".\domain-admins-results.txt"
        $DomainAdmins = Get-ADGroupMember -Credential $cred -Identity "Domain Admins" | select -ExpandProperty "SamAccountName" | Out-File -FilePath $FilePath
        if ($FilePath) {
            Write-Host "List of domain administrator saved to: "$FilePath
            }  
        }

    #if arguments invalid, output error
    default {
        Write-Host "Use the -h flag for help"
    }

    #if argument -l, accept a file
    "-l" {
        if ($args.Length -eq 1) {
            throw "List of domain admins required"
        } else {
            $users = Get-Content -Path $args[1]
            # Output the users
            foreach ($user in $users) {
                Write-Host $user
            }
        }

    }
}