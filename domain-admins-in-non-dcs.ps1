#store the argument as a paramter
$parameter = $args[0]

param($l)

switch ($parameter)
{
    #if argument -h show help
    "-h" {
        Write-Host ""
        Write-Host "How to use this scanner:"
        Write-Host ""
        Write-Host "A list of Domain Admins can be obtained with:"
        Write-Host "--da-scan: Scan for domain administrators using Get-ADGroupMember (ActiveDirectory module required)"
        Write-Host "--da-scan-get-creds: Same as above, but force credential request"
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

    #if argument --da-scan-get-creds, ask for creds then scan for domain admins and output to file
    "--da-scan-get-creds" {
        Import-Module ActiveDirectory
        $cred = Get-Credential
        $FilePath = ".\domain-admins-results.txt"
        $DomainAdmins = Get-ADGroupMember -Credential $cred -Identity "Domain Admins" | select -ExpandProperty "SamAccountName" | Out-File -FilePath $FilePath
        if ($FilePath) {
            Write-Host "List of domain administrator saved to: "$FilePath
            }  
        }
    
    #if argument -l
    if ($l -eq null) {
        #if no file name passed, promt the user to pass a file
        $l = read-host -Prompt "Where is your list of domain administrators?" 
    } 
    #scan the list
    Get-Content -Path $list
    
    foreach ($user in $users) {
            Write-Host $user
        }

    #if arguments invalid, output error
    default {
        Write-Host "Use the -h flag for help"
    }
}