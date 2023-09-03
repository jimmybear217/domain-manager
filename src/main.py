# global vars
## test whois to ensure proper installation and configuration
test_whoisDomain = "google.com"         # domain with wich to test whois is working
test_whoisLocation = "US"               # expected location of test_whoisDomain
webserverPort = 80                      # port on wich to run the webserver
webserverHost = "0.0.0.0"               # host on wich to run the webserver
mainDatabaseFile = 'domains.sqlite'     # database file to use for the webserver

# install packages
import packages as pkg
pkg.install('whois')    # pip install whois
pkg.install('waitress') # pip install waitress

# import packages
import whois
from waitress import serve
import sqlite3
import os

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
if (len(sqliteTables.fetchall()) == 0):
    print("Database and table not found, creating...")
    sqliteCursor.execute("create table users (user text primary key, password text, status text)")
    sqliteCursor.execute("create table domainsByUser (user text, domain text, whoisValue text, primary key (user, domain), foreign key (user) references users (user) on delete cascade on update cascade)")
    sqliteHandle.commit()
sqliteHandle.close()

# run webserver
# webserver.app.run(host=webserverHost, port=webserverPort)
webserver.passSqliteFileName(mainDatabaseFile)
print("Starting webserver on " + webserverHost + ":" + str(webserverPort) + "...")
serve(webserver.app, host=webserverHost, port=webserverPort)
print("Goodbye!")