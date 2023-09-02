import sqlite3

def queryDB(sqliteFileName, query, queryArgs):
    dbh = sqlite3.connect(sqliteFileName)
    cur = dbh.cursor()
    returnValue = cur.execute(query, queryArgs).fetchall()
    dbh.close()
    return returnValue

def writeDB(sqliteFileName, query, queryArgs):
    dbh = sqlite3.connect(sqliteFileName)
    cur = dbh.cursor()
    returnValue = cur.execute(query, queryArgs)
    dbh.commit()
    dbh.close()
    return returnValue