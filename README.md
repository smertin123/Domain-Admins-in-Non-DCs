# Domain-Admins-in-Non-DCs

A PowerShell script that checks for domain administrators logging into non-domain controllers. The script has local and remote functionality with the option to supply a list of remote hosts. Users can search in local processes, local or remote sessions, and local or remote user directories. 

The script requires a list of domain adminstrators. If you dont have a list of domain administrators the script can scan for them and output to file.


## Screenshot

![alt text](/img/help.png)


## Usage

By default the tool scans for domain administrators with the current PowerShell session credentials and stores in "domain-admin-scan-results.txt"

### Example: Change output file to "domain_admins.txt" and request credentials before scanning

```Powershell
domain-admins-in-non-dcs.ps1 -c -o domain_admins.txt
```

** All scans require a list of domain administrators **

By default all remote scans are against a single target

### Example: Scan remote host SQLSERVER01 using domain administrator list "DAs.txt"

```PowerShell
domain-admins-in-non-dcs.ps1 -l DAs.txt --remote-sessions SQLSERVER01
```

The tool also accepts a list of remote hosts

### Example: Scan remote host list "computers.txt" using domain administrator list "DAs.txt"

```PowerShell
domain-admins-in-non-dcs.ps1 -l DAs.txt --remote-sessions -r computers.txt
```

## Risk
Logging into non-domain controllers with domain administrator credentials poses a significant security risk, as the credentials are stored as hashes and tokens on the Windows platform. Malicious actors can use these to pivot to other systems within the domain, potentially resulting in a data breach. Possession of a domain administrator hash or token grants adversaries the capability to elevate their privileges, enabling them to access domain controllers and compromise the entire domain.

## Mitigations
The following recommendations should be considered when remediating the vulnerability:
* Restrict domain administrator accounts to log in to and carry out operations only on domain controllers.
* Restrict domain administrator accounts to a maximum of two (2).
* Install and configure LAPS to perform elevated duties on workstations and servers.