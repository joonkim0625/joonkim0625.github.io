---
title: "DNS & Web Browser Request"
date: 2023-02-14 00:00:00 +/-0500
categories: [Cybersecurity, Computer Network]
tags: [DNS, Domain Name System]
---


## What happens if a web browser (client) sends a reqeust to a server?

- [Reference](https://www.youtube.com/watch?v=mpQZVYPuDGU)

- What is DNS (Domain Name System)?
  - DNS resolves names domain names to IP addresses

- Steps that DNS takes:
  - 1. We try to access `yahoo.com` in our browser

  - 2. The browser (or your OS) checks its own cache memory for IP Address
  - 3. if not found, it sends the query to the resolver server
    - The resolver server is basically your ISP (Internet service provider)
    - Once it receives the query, it checks its own cache memory to find the IP
        address to `yahoo.com`
  - 4. if not found, it sends the query to the root server
    - Root server is the top, or the root, of the DNS hierarchy
    - 13 sets of these root servers strategically placed around the world
    - operated by 12 different organizations
    - each set has their own unique IP address
    - when the root server receives the query for the IP address for
        `yahoo.com`, it is not going to know what the IP address is. But, it
        knows where to send the resolver to find the IP address. The root server
        will direct the resolver to the TLD (Top Level Domain server) server for
        the `.com` domain
    - Top Level Domain Server stores the address information for top level
        domains such as `.com`, `.net`, `.org` etc.

  - 5. TLD server is not going to know what the IP address for `yahoo.com`. So
       it will direct the resolver to the next and final level which
       are the Authoritative Name servers
    
  - 6. The resolver asks the authoritative name server for the IP address for
       `yahoo.com`
    - Authoritative Name Servers are responsible for knowing everything about
        the domain including the IP address
    - when it receives for the query from the resolver, the name server responds
        with the IP address for `yahoo.com`
  - 7. Finally, the resolver tells your computer the IP address for `yahoo.com`
       and your computer now can retrieve the web page for `yahoo.com` 
    - once the resolver receives the IP address for `yahoo.com`, it will store
        the IP address in its cache memory to prevent going through all these
        steps again

After the steps above...

- Then the browser requests passes through a Web Application Firewall
- Them the request passes through a Load Balancer
- Then it connects to the webserver on port 80 (http) or 443 (https)
- Then the web application talks to database
- Your browser renders the HTML into a viewable website

