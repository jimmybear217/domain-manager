import whois
import packages as pkg
pkg.install('flask') # pip install flask
from flask import Flask, render_template, redirect, url_for, request, session, flash  # import flask

sqliteHandle = None
def passSqliteHandle(handle):
    global sqliteHandle
    sqliteHandle = handle

app = Flask(__name__)
@app.route("/")
def index():
    return render_template("index.html", title='Home')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["password"] == "password":
            session["user"] = request.form["username"]
            return redirect(url_for("index"))
        else:
            flash("Incorrect password.")
    return render_template("login.html", title='Login')

@app.route("/whois")
def whois_start():
    domain = ""
    if request.args.get('domain') != None:
        domain = request.args.get('domain')
    if domain == "":
        whoisData = "Please enter a domain."
    else:
        whoisData = whois.whois(domain)
    return render_template("whois.html", domain=domain, whoisData=str(whoisData))