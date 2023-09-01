import hashlib
from database import queryDB, writeDB

def hash_password(password):
    password = password.encode('utf-8')
    return hashlib.sha3_512(password).hexdigest()

def verify_password(password, hash):
    return hash_password(password) == hash

def lookupPassword(user, sqliteFileName):
    return queryDB(sqliteFileName, "select password from users where user = ? and status = 'active'", (user,))[0][0]

def verifyLogin(user, password, sqliteFileName):
    return verify_password(password, lookupPassword(user, sqliteFileName))

def registerUser(user, password, sqliteFileName):
    return writeDB(sqliteFileName, "insert into users (user, password, status) values (?, ?, ?)", (user, hash_password(password), "active"))