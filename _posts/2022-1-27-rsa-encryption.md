---
title: "RSA Encryption"
date: 2022-1-27 00:00:00 +/-0500
categories: [Blogging]
tags: [security, RSA, learning]
---

# RSA Encryption

I was working on picoCTF 2021: Mind your Ps and Qs problem and the problem was
about decrypting a RSA encryption. I have used RSA encryption to create some SSH
keys. And, of course, there are many times that I just don't realize but RSA
encryption is being used under the hood. So, I wanted to know about how it would
actually work. I watched this [Youtube video](https://www.youtube.com/watch?v=4zahvcJ9glg) by Eddie Woo and it was really helpful!

How RSA works:

1. Pair of numbers is needed for encryption. This is published by me. If you
   want to send me a message, use that pair of keys to encrypt your message. I
   am the only one who can decrypt the message. Let's say the public key I have
   published is `(5, 14)`. Someone wants to send me a message 'B' which can be a
   value of 2 numerically (A -> 1, B -> 2, C -> 3, and so on).

2. We want to raise the value 2 to the power of the first number from the public
   key and mod it by the second number. It can be written as $2^5$ (mod 14).
   This will give us 32 (mod 14). The remainder should be 4 (32 % 28).

3. The ciphertext is 4 and this is a letter 'D'. How do I decrypt this message?
   Let's say I have my secret key of (11, 14). The process of decrypting the
   message is to take the numerical value of 'D' and go through the same process
   as the encryption process. 

4. $4^11$ (mod 14) => 4194304 (mod 14) = 2. So we have the original text 'B'! 

But, how do we come up with my secret key that matches the public key?

1. We need to pick two prime numbers! Of course, the two prime numbers will be
   very very large compared to the numbers that are used here in this example.
   Here, p = 2, q = 7 are selected. And they should be kept secret!

2. N = p * q = 14. This number becomes the modulo of the encryption key and the
   decryption key.

3. We are going to have to choose a number that does not share a common factor
   with 14 (between 1 and 14). Let's not worry about 1 since it is a factor for
   all the numbers. 2 should not be considered since it has a common factor
   with 14 which is '2'. This allows us to not consider all the even numbers. 7
   should not be considered as it also shares a common factor with 14. The
   leftover numbers are now 1, 3, 5, 9, 11, 13. These numbers are called
   'coprime' numbers with 14. The count of these numbers is 6. 6 is going to be
   our $\phi$(N) value. But, this 6 can be easily calculated by (p-1)*(q-1)!!
   (2-1)*(7-1) = 6.

4. Now, we need to pick a number for the first number for the encryption key. We
   are going to call it 'e' for encryption. To choose a number of 'e', it has to
   obey some properties. 1. 'e' has to be a number that is $1 < e < \phi (N)$.
   2. The number must be coprime with N, $\phi(N)$. So, after the first
      property, we only have 2, 3, 4, 5 (since phi is 6). What would be the
      number that can be coprime with 6, 14? That number is 5. So, this was how
      5 was selected as the first number for the public key. With our N, we have
      the public key of (5, 14).

6. Now, we need to choose 'd' value for decryption. We are going to choose a
   number such that is $de(mod \phi(N)) = 1$. This can be re-written as $5d(mod
   6) = 1$. Since it is a multiple of 5, the pattern of the multiple is going to
   be 5, 10, 15, 20, 25, 30 ... The corresponding remainder when it is moded by 6 is
   5, 4, 3, 2, 1, 0. We can pick any numbers that we get 1! So, the decryption
   is key (11, 14) and 11 was selected (or could be a candidate of the first part) was because 5*11 (mod 6) = 1. It is obvious that we want to choose a large number to make computations harder.

This short example by Eddie Woo was very helpful for me to understand how RSA
encryption decides the public key and the decryption key. 


