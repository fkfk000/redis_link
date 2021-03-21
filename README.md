# redis_link
PostgreSQL's FDW to redis

## update from 2021-03-21 
Now, redis_link supports COPY command!
We could use \COPY table from 'table.csv' with csv; command to bulk loading data from CSV file to redis server.

## What is this redis_link
This project is a FDW(Foreign Data Wrapper) in PostgreSQL for redis. It supports read and write data from or to a remote redis server.
For now, it only supports PostgreSQL 11.

## How to use this package
## How to build 
1. You need to have PostgreSQL source code.
2. move the files to postgresql-11.10/contrib/redis_link
3. cd postgresql-11.10/contrib/redis_link && make install

## How to create tables
1. create extension redis_link;
2. CREATE SERVER localredis FOREIGN DATA WRAPPER redis_link;
3. create user mapping for public server localredis;
4. CREATE FOREIGN TABLE rft_str(key text,val text, ttl int) server localredis options (tabletype 'string', prefixname 'key');


## How to query table
For now, it only supports tabletype string. Because in redis, there is no concept of table, so for a key with certain prefix, we call it a table.
For example, key_a/key_b/key_c are the 3 row in table key_.

After creating the table,
* select * from table;
* select * from table where key like 'aaa%aa';
* \COPY table from '/path/to/table.csv' with csv;
* \COPY table to '/path/to/table.csv' with csv;
