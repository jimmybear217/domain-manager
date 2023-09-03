import hashlib
from database import queryDB, writeDB
import config

sqliteFileName = config.get("mainDatabaseFile")

def setSqliteFileName(filename):
    global sqliteFileName
    sqliteFileName = filename

def hash_password(password):
    password = password.encode('utf-8')
    return hashlib.sha3_512(password).hexdigest()

def verify_password(password, hash):
    return hash_password(password) == hash

def lookupPassword(user):
    return queryDB(sqliteFileName, "select password from users where user = ? and status = 'active'", (user,))[0][0]

def verifyLogin(user, password):
    return verify_password(password, lookupPassword(user))

def registerUser(user, password):
    return writeDB(sqliteFileName, "insert into users (user, password, status) values (?, ?, ?)", (user, hash_password(password), "active"))