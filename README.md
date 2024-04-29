# Endpoint Shell
Endpoint Response Shell. This is a proof of concept, use at your own risk.

# Setup
```console
$ pip install -r requirements.txt
```

# Usage
```console
$ endpoint_shell.py --help
usage: endpoint_shell.py [-h] --kibana-url KIBANA_URL [--user USER] [--password PASSWORD] [--cloud] [--no-verify]

optional arguments:
  -h, --help            show this help message and exit
  --kibana-url KIBANA_URL
                        Kibana URL
  --user USER           Kibana username
  --password PASSWORD   Kibana password
  --cloud               Login using Elastic Cloud account
  --no-verify           Don't validate TLS certificate

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
!tree <alert id>                  Display process tree surrounding alert
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
# Remediation
Given an alert id, endpoint shell can automatically remediate common malware threats. This is done by querying applicable process, file, and registry activity surrounding the alert. 
```console
[endpoint shell] > !alerts
+------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------+--------------------------+
| executable                                                                         | message                                                                                 | alert id                 |
+------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------+--------------------------+
| C:\Users\user\Desktop\sample\Talking_Points_for_China\Talking_Points_for_China.exe | Malicious Behavior Detection Alert: VirtualProtect API Call from an Unsigned DLL        | NVQfH1BWpJAjia0k++++0/SG |
| C:\Users\user\Desktop\sample\Talking_Points_for_China\Talking_Points_for_China.exe | Malicious Behavior Detection Alert: Shellcode Execution from Low Reputation Module      | NVQfH1BWpJAjia0k++++0/SQ |
| C:\Users\user\Desktop\sample\Talking_Points_for_China\Talking_Points_for_China.exe | Malicious Behavior Detection Alert: Suspicious String Value Written to Registry Run Key | NVQfH1BWpJAjia0k++++0/H2 |
+------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------+--------------------------+
[endpoint shell] > !remediate NVQfH1BWpJAjia0k++++0/H2
Agent id: dab8c81e-1234-1234-1234-4ba1b0387db5, User: user
Launched processes:
  Process: C:\Users\user\Desktop\sample\Talking_Points_for_China\Talking_Points_for_China.exe, Entity: ZGFiOGM4MWUtODJkMS00NTVkLTkwMWMtNGJhMWIwMzg3ZGI1LTEyMjY4LTE3MTI4NTg4MDUuOTI0MzM5MDAw, Pid: 12268
Registry persistence:
  Path: HKEY_USERS\S-1-5-21-1938409289-1938409289-1938409289-1001\Software\Microsoft\Windows\CurrentVersion\Run\KeyScrambler, Data: C:\Users\Public\Libraries\SmileTV\KeyScrambler.exe
Dropped files:
  Process: C:\Windows\explorer.exe, Path: C:\Users\user\Desktop\sample\Talking_Points_for_China\KeyScramblerIE.DLL
  Process: C:\Windows\explorer.exe, Path: C:\Users\user\Desktop\sample\Talking_Points_for_China\Talking_Points_for_China.exe
  Process: C:\Users\user\Desktop\sample\Talking_Points_for_China\Talking_Points_for_China.exe, Path: C:\Users\Public\Libraries\SmileTV\KeyScrambler.exe
  Process: C:\Users\user\Desktop\sample\Talking_Points_for_China\Talking_Points_for_China.exe, Path: C:\Users\Public\Libraries\SmileTV\KeyScramblerIE.DLL
Execute remediation [y/n]: y
Terminating processes..
Collecting dropped files..
File saved to: downloads\KeyScramblerIE.DLL
File saved to: downloads\Talking_Points_for_China.exe
File saved to: downloads\KeyScrambler.exe
File saved to: downloads\KeyScramblerIE.DLL
Cleaning up files/registry..
Remediation complete!
[endpoint shell] >
```

# Process Tree
Given an alert id, endpoint shell can generare a text process tree summary.

```console
[endpoint shell] > !tree NVQfH1BWpJAjia0k++++0/SG
* C:\Windows\System32\wininit.exe:
   * C:\Windows\System32\services.exe:
      * C:\Windows\System32\svchost.exe: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
         * C:\Windows\explorer.exe: C:\Windows\explorer.exe /NOUACCHECK
            * C:\Users\user\Desktop\sample\Talking_Points_for_China\Talking_Points_for_China.exe: "C:\Users\user\Desktop\sample\Talking_Points_for_China\Talking_Points_for_China.exe"
               library - load: C:\Users\user\Desktop\sample\Talking_Points_for_China\KeyScramblerIE.DLL
               api - VirtualProtect( keyscramblerie.dll, 0x15c, RWX, R-- ), ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|apphelp.dll|ntdll.dll
               api - VirtualProtect( keyscramblerie.dll, 0x1000, R--, RWX ), ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|apphelp.dll|ntdll.dll
               api - VirtualProtect( ole32.dll, 0xc08, RWX, R-- ), ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|apphelp.dll|ntdll.dll
               api - VirtualProtect( ole32.dll, 0x1000, R--, RWX ), ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|apphelp.dll|ntdll.dll
               api - VirtualProtect( talking_points_for_china.exe, 0x2e4, RWX, R-- ), ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|apphelp.dll|ntdll.dll
               api - VirtualProtect( talking_points_for_china.exe, 0x1000, R--, RWX ), ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|apphelp.dll|ntdll.dll
               api - VirtualProtect( user32.dll, 0x24, RW-, R-X ), ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|user32.dll|ntdll.dll
               api - VirtualProtect( user32.dll, 0x1000, R-X, RW- ), ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|user32.dll|ntdll.dll
               file - creation: C:\Users\Public\Libraries\SmileTV\KeyScrambler.exe
               registry - modification: HKEY_USERS\S-1-5-21-1938409289-1938409289-1938409289-1001\Software\Microsoft\Windows\CurrentVersion\Run\KeyScrambler -> ['C:\\Users\\Public\\Libraries\\SmileTV\\KeyScrambler.exe']
               file - modification: C:\Users\Public\Libraries\SmileTV\KeyScrambler.exe [b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00']
               file - creation: C:\Users\Public\Libraries\SmileTV\KeyScramblerIE.DLL [b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00']
               Behavior Detection Alert - behavior - Suspicious String Value Written to Registry Run Key
               api - VirtualAlloc( NULL, 0x1a8d, COMMIT|RESERVE, RWX ), ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|kernelbase.dll|keyscramblerie.dll|Unknown|kernel32.dll|ntdll.dll
               api - connect( ipv4, tcp, 103.27.109.157, 443 ), wow64cpu.dll|wow64.dll|ntdll.dll|mswsock.dll|ws2_32.dll|Unbacked|comdlg32.dll|user32.dll|comdlg32.dll|keyscramblerie.dll|Unknown|kernel32.dll|ntdll.dll
               network - connection_attempted: 103.27.109.157:443
               api - VirtualProtect( Unbacked, 0x2a05, RWX, RW- ), ntdll.dll|wow64.dll|wow64cpu.dll|wow64.dll|ntdll.dll|kernelbase.dll|Unbacked|comdlg32.dll|user32.dll|comdlg32.dll|keyscramblerie.dll|Unknown|kernel32.dll|ntdll.dll
               Behavior Detection Alert - behavior - VirtualProtect API Call from an Unsigned DLL
               Behavior Detection Alert - behavior - Shellcode Execution from Low Reputation Module
```
