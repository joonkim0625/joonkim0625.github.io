---
title: "IA-32 Assembly"
date: 2022-5-27 00:00:00 +/-0500
categories: [Cybersecurity, CTFs]
tags: [CTF, picoCTF2021, cybersecurity, assembly]
---


## IA32 Assembly Language 

As I was working on picoCTF2021 - filtered-shellcode challenge, I realized that
I need to write the shellcode in 32 bit assembly rather than in 64 bit. And
compiling 32 bit assembly code is different than compiling 64 bit assembly code
using `gcc`.

Great reference: [https://academic.macewan.ca/boersn/images/quickref-20121215.pdf](https://academic.macewan.ca/boersn/images/quickref-20121215.pdf)


First, to create an object file, use `nasm`.

`nasm -f elf32 -o file.o file.s`. This creates an object file `file.o`

Then link the object file with `ld`. The object file must have `global _start`.

`ld -m elf_i386 -e _start -o file file.o`

This will create a binary file. We can get the assembly code back by running
this command `objdump -M intel-mnemonic -D ./file`

The assembly code would start as below:

```
global _start
section .text
_start:

      xor eax, eax
      ...
```

You can look at how many bytes each instruction takes up by using `objdump`, but
if you want to get the string literal and use that to pass in as data stream,
you can go here: [https://defuse.ca/online-x86-assembler.htm#disassembly](https://defuse.ca/online-x86-assembler.htm#disassembly) and enter your shellcode.
