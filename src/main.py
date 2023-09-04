# global vars
## test whois to ensure proper installation and configuration
import config
if (config.doesConfigExist() == False):
    print("Config file not found, creating...")
    config.writeConfig()
    print("Config file created, please edit it and run the program again.")
config.loadConfig()

test_whoisDomain = config.get("test_whoisDomain")
test_whoisLocation = config.get("test_whoisLocation")
webserverPort = config.get("webserverPort")
webserverHost = config.get("webserverHost")
mainDatabaseFile = config.get("mainDatabaseFile")

import logging
logging.basicConfig(filename=config.get("mainLogFile"), level=config.get("mainLogLevel"), style='{', format='{asctime} [{levelname}] {message}', datefmt='%Y-%m-%d %H:%M:%S')

logging.info("Starting...")

# import packages
import whois
from waitress import serve
import sqlite3
import os
import encryption

#import custom packages
import webserver as webserver

# tests
logging.debug("Testing whois...")
whoisTestResult = whois.whois(test_whoisDomain).country
if (whoisTestResult == test_whoisLocation):
    print(test_whoisDomain + " is indeed from the " + test_whoisLocation + ".")
    logging.debug(test_whoisDomain + " is indeed from the " + test_whoisLocation + ".")
else:
    print(test_whoisDomain + " is not from the " + test_whoisLocation + ", something went wrong..." + str(whoisTestResult) + "\n" + "Exiting...")
    logging.critical(test_whoisDomain + " is not from the " + test_whoisLocation + ", something went wrong..." + str(whoisTestResult) + "\n" + "Exiting...")
    exit(1)

# check if database and table exists and create it
sqliteHandle = sqlite3.connect(mainDatabaseFile)
sqliteCursor = sqliteHandle.cursor()
sqliteTables = sqliteCursor.execute("select name from sqlite_schema where type = 'table' and name not like 'sqlite_%'")

# setup initial database
if (len(sqliteTables.fetchall()) == 0):
    print("Database and table not found, creating...")
    logging.info("Database and table not found, creating...")
    sqliteCursor.execute("create table users (user text primary key, password text, status text)")
    sqliteCursor.execute("create table domainsByUser (user text, domain text, whoisValue text, primary key (user, domain), foreign key (user) references users (user) on delete cascade on update cascade)")
    sqliteHandle.commit()

# setup encryption key
if (sqliteCursor.execute("SELECT COUNT(*) AS CNTREC FROM pragma_table_info('users') WHERE name='encryptionKey'").fetchall()[0][0] == 0):
    print("Column encryptionKey not found, creating...")
    logging.info("Column encryptionKey not found, creating...")
    sqliteCursor.execute("alter table users add column encryptionKey blob")
    sqliteHandle.commit()

# populate encryption key where missing
if (len(sqliteCursor.execute("select encryptionKey from users where encryptionKey is null").fetchall()) > 0):
    print("Populating column encryptionKey...")
    logging.info("Populating column encryptionKey...")  
    sqliteCursor.execute("select user from users")
    for user in sqliteCursor.fetchall():
        sqliteCursor.execute("update users set encryptionKey = ? where user = ?", (encryption.generateKey(), user[0]))
    sqliteHandle.commit()

# setup virustotal credentials tables
if (len(sqliteCursor.execute("select name from sqlite_schema where type = 'table' and name not like 'sqlite_%' and name = 'virustotalCredentials'").fetchall()) == 0):
    print("Table virustotalCredntials not found, creating...")
    logging.info("Table virustotalCredntials not found, creating...")
    sqliteCursor.execute("create table virustotalCredentials (user text primary key, apiKey text)")
    sqliteHandle.commit()

### add ip and asn columns to domainsByUser table
if (sqliteCursor.execute("SELECT COUNT(*) AS CNTREC FROM pragma_table_info('domainsByUser') WHERE name='rootIPs'").fetchall()[0][0] == 0):
    print("Column rootIPs not found, creating...")
    logging.info("Column rootIPs not found, creating...")
    sqliteCursor.execute("alter table domainsByUser add column rootIPs text")
    sqliteHandle.commit()

if (sqliteCursor.execute("SELECT COUNT(*) AS CNTREC FROM pragma_table_info('domainsByUser') WHERE name='wwwIPs'").fetchall()[0][0] == 0):
    print("Column wwwIPs not found, creating...")
    logging.info("Column wwwIPs not found, creating...")
    sqliteCursor.execute("alter table domainsByUser add column wwwIPs text")
    sqliteHandle.commit()

if (sqliteCursor.execute("SELECT COUNT(*) AS CNTREC FROM pragma_table_info('domainsByUser') WHERE name='rootASN'").fetchall()[0][0] == 0):
    print("Column rootASN not found, creating...")
    logging.info("Column rootASN not found, creating...")
    sqliteCursor.execute("alter table domainsByUser add column rootASN text")
    sqliteHandle.commit()

if (sqliteCursor.execute("SELECT COUNT(*) AS CNTREC FROM pragma_table_info('domainsByUser') WHERE name='wwwASN'").fetchall()[0][0] == 0):
    print("Column wwwASN not found, creating...")
    logging.info("Column wwwASN not found, creating...")
    sqliteCursor.execute("alter table domainsByUser add column wwwASN text")
    sqliteHandle.commit()

sqliteHandle.close()

# run webserver
print("Starting webserver on interface " + webserverHost + " and port " + str(webserverPort) + "...")
logging.info("Starting webserver on interface " + webserverHost + " and port " + str(webserverPort) + "...")
# webserver.app.run(host=webserverHost, port=webserverPort, debug=True)
serve(webserver.app, host=webserverHost, port=webserverPort)
print("Goodbye!")
logging.info("Exitting...")
exit(0)