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
        Write-Host " #-#-#-#-#-#-#-#-#-#-#    Domain Administrator Grabber    -#-#-#-#-#-#-#-#-#-#"
        Write-Host " #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#=#-#-#"
        Write-Host ""
        Write-Host " --da-scan: Scan for Domain Administrators"
        Write-Host " -c: Promt for credentials"
        Write-Host " -o: Choose alternative output file (Default domain-admin-scan-results.txt)"
        Write-Host ""
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
}