# Domain Administrators in Non-Domain Controllers Scanner

Offensive and Defensive PowerShell scripts that check for domain administrators logging into non-domain controllers. The scripts have local and remote functionality with the option to supply a list of remote hosts. The scripts can search in local processes, local or remote sessions, and can check for local or remote user directories. 

The scripts require a list of domain adminstrators. If you dont have a list of domain administrators you can use the "da-scanner.ps1" tool to output a list to file.



# da-grabber

## Screenshot

![alt text](/da-grabber.png)

## Using the Grabber

## Grab a List of Domain Administrators

By default the tool grabs the list with the current PowerShell session credentials and stores in "domain-admin-scan-results.txt"

### Example: Grab using current credentials and output to default file

```Powershell
offensive-da-scanner.ps1 --da-scan
```

### Example: Change output file to "domain_admins.txt" and request credentials before scanning

```Powershell
offensive-da-scanner.ps1 --da-scan -c -o domain_admins.txt
```



# Offensive


## Screenshot

![alt text](/offensive/img/help.png)


# All scans require a list of domain administrators

## Using the scanner

By default all remote scans are against a single target

### Example: Scan remote host SQLSERVER01 using domain administrator list "DAs.txt"

```PowerShell
offensive-da-scanner.ps1 -l DAs.txt --remote-sessions SQLSERVER01
```

The tool also accepts a list of remote hosts

### Example: Scan remote host list "computers.txt" for current sessions using domain administrator list "DAs.txt"

```PowerShell
offensive-da-scanner.ps1 -l DAs.txt --remote-sessions -r computers.txt
```



# Defensive

Work in progress...



# Risk
Logging into non-domain controllers with domain administrator credentials poses a significant security risk, as the credentials are stored as hashes and tokens on the Windows platform. Malicious actors can use these to pivot to other systems within the domain, potentially resulting in a data breach. Possession of a domain administrator hash or token grants adversaries the capability to elevate their privileges, enabling them to access domain controllers and compromise the entire domain.

# Mitigations
The following recommendations should be considered when remediating the vulnerability:
* Restrict domain administrator accounts to log in to and carry out operations only on domain controllers.
* Restrict domain administrator accounts to a maximum of two (2).
* Install and configure LAPS to perform elevated duties on workstations and servers.