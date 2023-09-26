---
title: "tamuctf 2022 - Lockout"
date: 2022-4-22 00:00:00 +/-0500
categories: [Cybersecurity, CTFs]
tags: [CTF, tamuctf, cybersecurity, web] 
---

# taumf2022: lockout

Author: SwitchBlade

I seem to have locked myself out of my admin panel! Can you find a way back in for me?

Do not connect with HTTPS, make sure to connect with HTTP

Link: http://lockout.tamuctf.com

## Solve

I couldn't solve this one so I referred to this [https://www.youtube.com/watch?v=f198HnqCwng&t=206s](https://www.youtube.com/watch?v=f198HnqCwng&t=206s) video.


When you attempt to login to the blog, the page gets redirected back to the login
page right away because of the 302 response.

![redirect](https://joonkim0625.github.io/assets/img/screenshots/redirect.png)

I learned that if we can pass a 200 response instead of 302, we will be able to
pass to see `admin.php`.

Burp Suite is the best tool for this task.

Make sure that 'Intercept responses based on the following rules' box checked to
capture/modify the response.

![burpesuite](https://joonkim0625.github.io/assets/img/screenshots/burpesuite.png)


Once you are on the login page, pass in any username/password to get the
response from the site. Then you would see something like this from Burp Suite.

![resp](https://joonkim0625.github.io/assets/img/screenshots/response.png)

Now, we can replace 302 with 200 and click 'forward' to get to the admin page.
Once you do that, you will see the admin page.

![adminpage](https://joonkim0625.github.io/assets/img/screenshots/admin.png)

Let's click the 'PrintFlag' button since that is what we are most interested in.
If you forward the response that you get from the server, you will be able to
see another response with the flag.

![flag](https://joonkim0625.github.io/assets/img/screenshots/flag.png)

This challenge taught me two things:

1. look at the network responses and see if I can bypass it with manipulating
   http status codes
2. If that seems to be the case, use Burp Suite to capture responses and
   manipulate them.


