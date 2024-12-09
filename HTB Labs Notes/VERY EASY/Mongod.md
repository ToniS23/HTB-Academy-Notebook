
27-07-2024 20:46 pm

Tags: [[MongoDB]] [[Databases]] [[Recon]] [[Misconfiguration]] [[Anon or Guest Access]]

References: https://app.hackthebox.com/starting-point


# Mongod

download mongo with:
url -O https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-3.4.7.tgz

extract the file:
tar xvf mongodb-linux-x86_64-3.4.7.tgz

run the script from bin:
./mongo mongodb://10.129.209.239:27017

show dbs; to show databases

use {db_name}; to switch database

show collections; to see the contents of the database

db.flag.find().pretty()

get the flag

easy



# Useful Links:

