# Endpoint Shell
Endpoint Response Shell

# Setup
```console
$ pip install -r requirements.txt
```

# Usage
```console
$ endpoint_shell.py --kibana https://<kibana-url> --user elastic
Enter password:
[endpoint shell] > !help
 = Endpoint Response Shell =
Available commands:
!list                             List active endpoints
!interact <host name>             Interact with a host
!shell                            Launch a pseudo shell on host
!download <path>                  Download a file from a host
!upload <local path> <file name>  Upload a file to a host
!alerts                           Display recent endpoint alerts
!remediate <alert id>             Malware remediaton for an alert
[endpoint shell] > !list
Active hosts: 1
  desktop-mpqrk7t - Windows 10 Pro 1909 (10.0.18363.418) - dab8c81e-1234-1234-1234-4ba1b0387db5
[endpoint shell] > !interact desktop-mpqrk7t
[desktop-mpqrk7t] > !shell
[desktop-mpqrk7t] shell > dir \
 Volume in drive C has no label.
 Volume Serial Number is 1234-1234

 Directory of C:\

03/18/2019  09:52 PM    <DIR>          PerfLogs
04/10/2024  06:49 AM    <DIR>          Program Files
08/11/2021  06:42 AM    <DIR>          Program Files (x86)
08/08/2022  08:31 PM    <DIR>          Python27
08/08/2022  08:32 PM    <DIR>          Python310
01/17/2020  11:15 AM    <DIR>          Users
04/10/2024  05:49 PM    <DIR>          Windows
               1 File(s)             14 bytes
               7 Dir(s)  91,220,337,911 bytes free

[desktop-mpqrk7t] shell > exit
[desktop-mpqrk7t] > exit
```

