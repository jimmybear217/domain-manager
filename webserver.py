import whois
import passwords
import encryption
import packages as pkg
import random
from database import queryDB, writeDB
pkg.install('flask') # pip install flask
from flask import Flask, render_template, redirect, url_for, request, session, flash  # import flask

sqliteFileName = None
def passSqliteFileName(filename):
    global sqliteFileName
    sqliteFileName = filename

app = Flask(__name__)

## set secret key for session - generate it randomly if it does not exist and encrypt it into a file
secretKeyHandle = encryption.Encryption()
secretKey = secretKeyHandle.decryptFile("flask.key")
if (secretKey == None):
    # generate key if it doesn't exist
    secretKey = random_string = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))
    secretKeyHandle.encryptFile("flask.key", secretKey)
app.secret_key = secretKey


## main page
@app.route("/")
def index():
    if (checkLogin() == False):
        return redirect(url_for("login"))
    return render_template("index.html", title='Home')


## account management
@app.route("/account/register", methods=["POST"])
def register():
    if request.method == "POST":
        if passwords.registerUser(request.form["username"], request.form["password"], sqliteFileName):
            flash("Registration successful.")
            return redirect(url_for("login"))
        else:
            flash("User already exists.")
    return render_template("register.html", title='Register')


@app.route("/account/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if passwords.verifyLogin(request.form["username"], request.form["password"], sqliteFileName):
            session["user"] = request.form["username"]
            flash("Login successful.")
            return redirect(url_for("index"))
        else:
            flash("Incorrect password.")
    return render_template("login.html", title='Login')

@app.route("/account/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

def checkLogin():
    if "user" in session:
        return True
    else:
        return False


## whois lookup
@app.route("/whois/list", methods=["GET"])
def whois_list():
    if (checkLogin() == False):
        return redirect(url_for("login"))
    if request.args.get('domain') != None:
        domain = request.args.get('domain')
        whoisData = whois.whois(domain)
        try:
            writeDB(sqliteFileName, "insert into domainsByUser (user, domain, whoisValue) values (?, ?, ?)", (session["user"], domain, str(whoisData)))
        except:
            flash("Domain already exists.")
    return render_template("whois_list.html", domains=queryDB(sqliteFileName, "select domain, whoisValue from domainsByUser where user = ?", (session["user"],)))

@app.route("/whois/lookup", methods=["GET"])
def whois_start():
    if (checkLogin() == False):
        return redirect(url_for("login"))
    
    domain = ""
    if request.args.get('domain') != None:
        domain = request.args.get('domain')
    if domain == "":
        whoisData = "Please enter a domain."
    else:
        whoisData = whois.whois(domain)
    return render_template("whois.html", domain=domain, whoisData=str(whoisData))