import packages as pkg
pkg.install('flask') # pip install flask
import whois

from flask import Flask, render_template, redirect, url_for, request, session, flash  # import flask

app = Flask(__name__)
@app.route("/")
def index():
    return render_template("index.html", title='Home')

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