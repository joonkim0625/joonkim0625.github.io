---
title: webhacking.kr: old-18
date: 2024-10-25 22:51:34 
categories: [Cybersecurity, Web Application Security, Penetration Testing, CTF]
tags:
  [SQLi, SQL Injection, Filter Bypass, PHP]
---

This is a challenge from `webhacking.kr`. As the name of the website suggests, it is about SQL injection. You can check the source code of the page: 


```php
<?php
if($_GET['no']){
  $db = dbconnect();
  if(preg_match("/ |\/|\(|\)|\||&|select|from|0x/i",$_GET['no'])) exit("no hack");
  $result = mysqli_fetch_array(mysqli_query($db,"select id from chall18 where id='guest' and no=$_GET[no]")); // admin's no = 2

  if($result['id']=="guest") echo "hi guest";
  if($result['id']=="admin"){
    solve(18);
    echo "hi admin!";
  }
}
?>
```

Our goal seems to be creating a payload that would make the `id` value `admin` and also make the `no` value `2`. So, let's assume that there is no filter so we can enter anything as a payload. When we enter `2` as our input, you will see something like this:


![screenshot](https://joonkim0625.github.io/images/webhackingkr-old-18.png)

So, because of this `where id='guest' and no=$_GET[no]` line, we can try to inject SQLi through this. We want the `id='admin'` for sure. So, it can look something like `no=2 or id='admin'`


From the page source code, we can see that there is a `preg_match` function that filters some of the characters and words that can be possibly used for SQLi. As you can see, the first part of the regex filters out the space character. We can bypass this by using an URL encoded payload that represents a tab character which is `%09`. 

`no=2%09or%09id='admin'`

If you use this payload, you will see the message that you have solved the challenge. 
