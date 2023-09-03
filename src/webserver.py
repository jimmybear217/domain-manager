import json
import whois
import passwords
import encryption
import random
import datetime
import re
import socket
import virustotal_python
from database import queryDB, writeDB
from flask import Flask, render_template, redirect, url_for, request, session, flash
import dns.resolver
import logging
import config

## logging
logging.basicConfig(filename=config.get("mainLogFile"), level=config.get("mainLogLevel"))

## database
sqliteFileName = config.get("mainDatabaseFile")

## webserver
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
    app.logger.debug("Index page requested from " + request.remote_addr + " as user " + session.get("user", "anonymous"))
    if (checkLogin() == False):
        app.logger.warning("User not logged in, redirecting to login page.")
        return redirect(url_for("login"))
    return render_template("index.html", title='Home')


## account management
@app.route("/account/register", methods=["POST"])
def register():
    if request.method == "POST":
        if passwords.registerUser(request.form["username"], request.form["password"]):
            app.logger.info("User " + request.form["username"] + " registered from ip " + request.remote_addr + ".")
            flash("Registration successful.")
            return redirect(url_for("login"))
        else:
            app.logger.warning("User " + request.form["username"] + " registration failed from ip " + request.remote_addr + ".")
            flash("User already exists.")
    return render_template("register.html", title='Register')


@app.route("/account/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if passwords.verifyLogin(request.form["username"], request.form["password"]):
            session["user"] = request.form["username"]
            app.logger.info("User " + request.form["username"] + " logged in from ip " + request.remote_addr + ".")
            flash("Login successful.")
            return redirect(url_for("index"))
        else:
            app.logger.warning("User " + request.form["username"] + " login failed from ip " + request.remote_addr + ".")
            flash("Incorrect password.")
    return render_template("login.html", title='Login')

@app.route("/account/logout")
def logout():
    app.logger.info("User " + session.get("user", "anonymous") + " logged out from ip " + request.remote_addr + ".")
    session.pop("user", None)
    return redirect(url_for("index"))

def checkLogin():
    if "user" in session:
        return True
    else:
        return False


## template processors
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


## whois
@app.route("/whois/list", methods=["GET"])
def whois_list():
    app.logger.debug("Whois List page requested from " + request.remote_addr + " as user " + session.get("user", "anonymous"))
    if (checkLogin() == False):
        app.logger.warning("User not logged in, redirecting to login page.")
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
        ## lookup host IPs
    return render_template("whois_list.html", domains=queryDB(sqliteFileName, "select domain, whoisValue from domainsByUser where user = ?", (session["user"],)))

@app.route("/whois/lookup", methods=["GET"])
def whois_start():
    app.logger.debug("Whois Query page requested from " + request.remote_addr + " as user " + session.get("user", "anonymous"))
    if (checkLogin() == False):
        app.logger.warning("User not logged in, redirecting to login page.")
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
    app.logger.debug("Whois Refresh page requested from " + request.remote_addr + " as user " + session.get("user", "anonymous"))
    if (checkLogin() == False):
        app.logger.warning("User not logged in, redirecting to login page.")
        return redirect(url_for("login"))
    
    if request.args.get('domain') != None:
        domain = request.args.get('domain')
        whoisData = whois.whois(domain)
        writeDB(sqliteFileName, "update domainsByUser set whoisValue = ? where domain = ?", (str(whoisData), domain))
        flash("Domain Refreshed: " + domain)
    return redirect(url_for("whois_list"))

@app.route("/whois/delete", methods=["GET"])
def whois_delete():
    app.logger.debug("Whois delete page requested from " + request.remote_addr + " as user " + session.get("user", "anonymous"))
    if (checkLogin() == False):
        app.logger.warning("User not logged in, redirecting to login page.")
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
    app.logger.debug("DNS Lookup page requested from " + request.remote_addr + " as user " + session.get("user", "anonymous"))
    if (checkLogin() == False):
        app.logger.warning("User not logged in, redirecting to login page.")
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

## security menus

@app.route("/security", methods=["GET"])
def security_menu():
    app.logger.debug("Security menu page requested from " + request.remote_addr + " as user " + session.get("user", "anonymous"))
    if (checkLogin() == False):
        app.logger.warning("User not logged in, redirecting to login page.")
        return redirect(url_for("login"))
    
    return render_template("security.html")

@app.route("/security/virustotal", methods=["GET", "POST"])
def security_virustotal():
    app.logger.debug("VirusTotal page requested from " + request.remote_addr + " as user " + session.get("user", "anonymous"))
    if (checkLogin() == False):
        app.logger.warning("User not logged in, redirecting to login page.")
        return redirect(url_for("login"))
    
    domain = ""
    if (request.method == "POST" and request.form['domain'] != None):
        domain = request.form['domain']

    # get api key from form or database
    apikey = ""
    if (request.method == "POST" and request.form['apikey'] != None):
        apikey = request.form['apikey']
        if (apikey != ""):
            flash("API key provided.", "success")
    else:
        # read api key from databse if it's not specificed in the form
        apikeyEncrypted = queryDB(sqliteFileName, "select apikey from virustotalCredentials where user = ?", (session["user"],))
        apikeyPrivateKey = queryDB(sqliteFileName, "select encryptionKey from users where user = ?", (session["user"],))
        if (len(apikeyEncrypted) > 0):
            apikey = secretKeyHandle.decryptWithKey(apikeyEncrypted[0][0], apikeyPrivateKey[0][0]).decode('utf-8')
            flash("API key found.", "success")
        else:
            flash("API key not found.", "warning")
        del apikeyPrivateKey, apikeyEncrypted

    # save api key
    saveApiKey = False
    saveApiKeyChecked = ""
    if (request.method == "POST" and "saveApiKey" in request.form and request.form['saveApiKey'] == "on"):
        saveApiKey = True
        saveApiKeyChecked = "checked"

    if (saveApiKey == True and apikey != ""):
        apikeyPrivateKey = queryDB(sqliteFileName, "select encryptionKey from users where user = ?", (session["user"],))
        writeDB(sqliteFileName, "insert or replace into virustotalCredentials (user, apikey) values (?, ?)", (session["user"], secretKeyHandle.encryptWithKey(bytes(apikey, encoding='utf-8'), apikeyPrivateKey[0][0])))
        flash("API key saved.", "success")
        del apikeyPrivateKey
    
    
    # lookup or scan action
    action = "lookup"
    if (request.method == "POST" and "action" in request.form and request.form['action'] != None):
        action = request.form['action']

    # lookup
    vt_data = ""
    if (domain != "" and apikey != "" and action != ""):
        try:
            with virustotal_python.Virustotal(API_KEY=apikey, API_VERSION=3) as vtotal:
                resp = vtotal.request(f"domains/{domain}")
                vt_data=resp.data
                flash("VirusTotal Lookup successful.", "success")
        except:
            flash("VirusTotal Lookup failed. Please check your domain, API key, and action.", "error")
            vt_data=json.loads("{Error: 'VirusTotal Lookup failed. Please check your domain, API key, and action.'}")
    
    # render
    return render_template("virustotal.html", domain=domain, apikey=apikey, action=action, saveApiKeyChecked=saveApiKeyChecked, vt_data=vt_data)

@app.route("/security/certs", methods=["GET"])
def security_certs():
    app.logger.debug("certs page requested from " + request.remote_addr + " as user " + session.get("user", "anonymous"))
    if (checkLogin() == False):
        app.logger.warning("User not logged in, redirecting to login page.")
        return redirect(url_for("login"))

    return render_template("certs.html")

@app.route("/security/urlscan", methods=["GET"])
def security_urlscan():
    app.logger.debug("urlscan page requested from " + request.remote_addr + " as user " + session.get("user", "anonymous"))
    if (checkLogin() == False):
        app.logger.warning("User not logged in, redirecting to login page.")
        return redirect(url_for("login"))

    return render_template("urlscan.html")