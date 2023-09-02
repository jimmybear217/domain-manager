import json
import whois
import passwords
import encryption
import packages as pkg
import random
import datetime
import re
import socket
from database import queryDB, writeDB
pkg.install('flask') # pip install flask
from flask import Flask, render_template, redirect, url_for, request, session, flash  # import flask
pkg.install('dnspython') # pip install dns.resolver
import dns.resolver

sqliteFileName = None
def passSqliteFileName(filename):
    global sqliteFileName
    sqliteFileName = filename

app = Flask(__name__)

## set secret key for session - generate it randomly if it does not exist and encrypt it into a file
secretKeyHandle = encryption.Encryption()
secretKey = secretKeyHandle.decryptFile("data/flask.key")
if (secretKey == None):
    # generate key if it doesn't exist
    secretKey = random_string = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))
    secretKeyHandle.encryptFile("data/flask.key", secretKey)
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
@app.template_filter('fromJson')
def parseJson(jsonStr):
    return json.loads(jsonStr.replace("'", "\""))

@app.template_filter('toLocateDateTime')
def toLocateDateTime(timestamp):
    if (type(timestamp) == list):
        output = list()
        for entry in timestamp:
            output.append(toLocateDateTime(entry))
        return output

    if (type(timestamp) != str):
        timestamp = str(timestamp)
    return datetime.datetime.fromisoformat(timestamp).astimezone().strftime("%m/%d/%Y")

@app.route("/whois/list", methods=["GET"])
def whois_list():
    if (checkLogin() == False):
        return redirect(url_for("login"))
    if request.args.get('domain') != None:
        domain = request.args.get('domain')
        if (queryDB(sqliteFileName, "SELECT count(domain) from domainsByUser WHERE domain = ? AND user = ?", (domain, session["user"]))[0][0] == 0):
            whoisData = whois.whois(domain)
            try:
                writeDB(sqliteFileName, "insert into domainsByUser (user, domain, whoisValue) values (?, ?, ?)", (session["user"], domain, str(whoisData)))
                flash("Domain Added: " + domain)
            except:
                flash("Write failed for domain " + domain + ". See logs for more details.")
        else:
            flash("Domain already exists: " + domain)
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

@app.route("/whois/refresh", methods=["GET"])
def whois_refresh():
    if (checkLogin() == False):
        return redirect(url_for("login"))
    if request.args.get('domain') != None:
        domain = request.args.get('domain')
        whoisData = whois.whois(domain)
        writeDB(sqliteFileName, "update domainsByUser set whoisValue = ? where domain = ?", (str(whoisData), domain))
        flash("Domain Refreshed: " + domain)
    return redirect(url_for("whois_list"))

@app.route("/whois/delete", methods=["GET"])
def whois_delete():
    if (checkLogin() == False):
        return redirect(url_for("login"))
    if request.args.get('domain') != None:
        domain = request.args.get('domain')
        writeDB(sqliteFileName, "delete from domainsByUser where domain = ? and user = ?", (domain, session["user"]))
        flash("Domain Deleted: " + domain)
    return redirect(url_for("whois_list"))

## DNS lookup
def is_ip_address(ip_address):
  regex = re.compile(r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$')
  return regex.match(ip_address) is not None

@app.route("/dns/lookup", methods=["GET"])
def dns_lookup():
    if (checkLogin() == False):
        return redirect(url_for("login"))
    if request.args.get('domain') != None:
        domain = request.args.get('domain')
        recordType = "A"
        if request.args.get('recordType') != None:
            recordType = request.args.get('recordType')
        resolver = dns.resolver.Resolver()
        if request.args.get('nameServer') not in ["", None]:
            if is_ip_address(request.args.get('nameServer')):
                resolver.nameservers = [request.args.get('nameServer')]
            else:
                resolver.nameservers = [socket.gethostbyname(request.args.get('nameServer'))]
        try:
            dnsData = resolver.query(domain, recordType).response.to_text()
            flash("DNS Lookup successful.", "success")
        except:
            dnsData = ""
            flash("DNS Lookup failed. Please check your domain, record type, and name server.", "error")
        return render_template("dns.html", domain=domain, recordType=recordType, nameServer=resolver.nameservers[0], dnsData=dnsData)
    else:
        domain = ""
        dnsData = "Please enter a domain."
        return render_template("dns.html", domain=domain, dnsData=dnsData)