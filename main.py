# global vars
## test whois to ensure proper installation and configuration
test_whoisDomain = "google.com"
test_whoisLocation = "US"
webserverPort = 80
webserverHost = "0.0.0.0"

# install packages
import packages as pkg
pkg.install('whois') # pip install whois
pkg.install('waitress') # pip install waitress

# import installed packages
import whois
import webserver as webserver
from waitress import serve

# tests
whoisTestResult = whois.whois(test_whoisDomain).country
if (whoisTestResult == test_whoisLocation):
    print(test_whoisDomain + " is indeed from the " + test_whoisLocation + ".")
else:
    print(test_whoisDomain + " is not from the " + test_whoisLocation + ", something went wrong..." + str(whoisTestResult) + "\n" + "Exiting...")
    exit(1)

# run webserver
webserver.app.run(host=webserverHost, port=webserverPort)
# serve(webserver.app, host=webserverHost, port=webserverPort)