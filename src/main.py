# global vars
## test whois to ensure proper installation and configuration
test_whoisDomain = "google.com"         # domain with wich to test whois is working
test_whoisLocation = "US"               # expected location of test_whoisDomain
webserverPort = 8080                    # port on wich to run the webserver
webserverHost = "0.0.0.0"               # host on wich to run the webserver
mainDatabaseFile = 'domains.sqlite'     # database file to use for the webserver

# import packages
import whois
from waitress import serve
import sqlite3
import os
import encryption

#import custom packages
import webserver as webserver

# tests
whoisTestResult = whois.whois(test_whoisDomain).country
if (whoisTestResult == test_whoisLocation):
    print(test_whoisDomain + " is indeed from the " + test_whoisLocation + ".")
else:
    print(test_whoisDomain + " is not from the " + test_whoisLocation + ", something went wrong..." + str(whoisTestResult) + "\n" + "Exiting...")
    exit(1)

# check if database and table exists and create it


sqliteHandle = sqlite3.connect(mainDatabaseFile)
sqliteCursor = sqliteHandle.cursor()
sqliteTables = sqliteCursor.execute("select name from sqlite_schema where type = 'table' and name not like 'sqlite_%'")

# setup initial database
if (len(sqliteTables.fetchall()) == 0):
    print("Database and table not found, creating...")
    sqliteCursor.execute("create table users (user text primary key, password text, status text)")
    sqliteCursor.execute("create table domainsByUser (user text, domain text, whoisValue text, primary key (user, domain), foreign key (user) references users (user) on delete cascade on update cascade)")
    sqliteHandle.commit()

# setup encryption key
if (sqliteCursor.execute("SELECT COUNT(*) AS CNTREC FROM pragma_table_info('users') WHERE name='encryptionKey'").fetchall()[0][0] == 0):
    print("Column encryptionKey not found, creating...")
    sqliteCursor.execute("alter table users add column encryptionKey blob")
    sqliteHandle.commit()

# populate encryption key where missing
if (len(sqliteCursor.execute("select encryptionKey from users where encryptionKey is null").fetchall()) > 0):
    print("Populating column encryptionKey...")
    sqliteCursor.execute("select user from users")
    for user in sqliteCursor.fetchall():
        sqliteCursor.execute("update users set encryptionKey = ? where user = ?", (encryption.generateKey(), user[0]))
    sqliteHandle.commit()

# setup virustotal credentials tables
if (len(sqliteCursor.execute("select name from sqlite_schema where type = 'table' and name not like 'sqlite_%' and name = 'virustotalCredentials'").fetchall()) == 0):
    print("Table virustotalCredentials not found, creating...")
    sqliteCursor.execute("create table virustotalCredentials (user text primary key, apiKey text)")
    sqliteHandle.commit()
sqliteHandle.close()


### add httpHostRoot and httpHostWww to databse according to whois function


# run webserver
print("Starting webserver on " + webserverHost + ":" + str(webserverPort) + "...")
webserver.passSqliteFileName(mainDatabaseFile)
# webserver.app.run(host=webserverHost, port=webserverPort)
serve(webserver.app, host=webserverHost, port=webserverPort)
print("Goodbye!")