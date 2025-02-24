---
title: "HackTheBox - Beginner Track: Blue"
date: 2023-04-29 22:00:00 +/-0500
categories: [Cybersecurity, CTFs, HackTheBox]
tags:
  [ctf, hackthebox, cybersecurity, windows, msrpc, remote code execution, smb]
---

## Challenge: Blue

There wasn't a description, so I ran `nmap` on the IP address that I was given:

```
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2023-04-30T01:23:49
|_  start_date: 2023-04-30T01:19:21
| smb2-security-mode:
|   210:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-04-30T02:23:51+01:00
|_clock-skew: mean: -19m03s, deviation: 34m35s, median: 54s
```

Port 135 was open, so I googled if there were any exploits regarding the msrpc
service. I was able to find this [article](https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc).

As mentioned in the article, MSRPC (or Microsoft Remote Procedure Call) is a protocol
that uses the client-server model in order to allow one program to request
service from a program on another computer without having to understand the
details of that computer's network.

This could be the vulnerability that I can use to attack the system, so I
decided to jump on this first.

### Port 135

I couldn't find any vulnerabilities regarding MSRPC.

### Port 139: NetBIOS

According to the link above, NetBIOS stands for Network Basic Input Output
System. And this is known as 'NBT over IP'.

### Port 445: SMB

According to the link, port 445 is 'SMB over IP'. SMB stands for 'Server Message
Blocks'. This in modern language is also known as **Common Internet File System**.

### Conclusion

This room was about EternalBlue vulnerability - CVE-2017-0143. [Resource](https://steflan-security.com/hack-the-box-blue-walkthrough/)
Should be a simple exploitation after attempting to enumerate the SMB client to
see if we can find anything useful. If not successful, then we can try to run
`nmap` with existing scripts regarding `smb` such as `smb-enum` series. We can
also use `smb-vuln` scripts to see if there are any vulnerabilities. The
resource above provided this useful EternalBlue exploitation [resource](https://github.com/3ndG4me/AutoBlue-MS17-010).

Follow the direction then we will be able to launch the reverse shell.
