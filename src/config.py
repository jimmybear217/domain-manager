import configparser
import logging

configFile = 'config.ini'

default_config = {
    "test_whoisDomain": "google.com",
    "test_whoisLocation": "US",
    "webserverPort": 8080,
    "webserverHost": "0.0.0.0",
    "mainDatabaseFile": 'main.sqlite',
    "mainLogFile": 'main.log',
    "mainLogLevel": logging.DEBUG,
    "developmentmode": False,
    "ipDataApiKey": "",
}

current_config = default_config

def doesConfigExist():
    try:
        with open(configFile, 'r') as configfile:
            configfile.close()
            return True
    except FileNotFoundError:
        return False

def loadConfig():
    print("Loading config from '" + configFile + "'...")
    global current_config
    config = configparser.ConfigParser()
    config.read(configFile)
    for key in default_config.keys():
        if (key in config['DEFAULT']):
            current_config[key] = config['DEFAULT'][key]
        else:
            current_config[key] = default_config[key]
    print("Configuration file loaded.")

def writeConfig():
    global current_config
    config = configparser.ConfigParser()
    config['DEFAULT'] = current_config
    with open(configFile, 'w') as configfile:
        config.write(configfile)

def get(key):
    global current_config
    if (key in current_config):
        return current_config[key]
    else:
        return None
    
def set(key, value):
    global current_config
    current_config[key] = value

def exists(key):
    global current_config
    if (key in current_config):
        return True
    else:
        return False