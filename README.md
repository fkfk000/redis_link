# redis_link
PostgreSQL's FDW to redis

## What is this redis_link
This project is a FDW(Foreign Data Wrapper) in PostgreSQL for redis. It supports read and write data from or to a remote redis server. Cluster mode at redis side is supported.
Currently it is tested in Postgres 16. It should apply to other recent versions.

## How to use this package
## How to build 
1. You need to have PostgreSQL source code.
2. move the files to postgresql-source/contrib/redis_link
3. cd postgresql-source/contrib/redis_link && make install

## How to use it
## create necessary objects
To successfully connect to a clusterd redis server, we need 
* create the extension it self.
* create a server that contains the server information.
* create the table. Currently, hash/set/string types are supported.

## How to create tables
1. create extension redis_link;
2. create server redis_server FOREIGN DATA WRAPPER redis_link options (host_port '127.0.0.1:9001, 127.0.0.1:9002, 127.0.0.1:9003');
4. create foreign table tb (name text, content text, expire int) server redis_server options (key 'name', value 'content', prefix 'project:group:user1:', table_type 'string', ttl 'expire');


## How to query table
After creating the table, we could write data into the redis cluster

insert into tb select ('key' || generate_series(1,100))::text, ('val' || generate_series(1,100))::text, 1000000;

Then use select command to query the data.

select * from tb;
