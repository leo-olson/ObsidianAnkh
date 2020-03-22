import threading
import pymongo
from requests import get

def init():

    global ipaddr
    global db
    global geoip_url

    print_lock = threading.Lock()
    
    ipaddr = get('https://api.ipify.org').text
    #print('My public IP address is: {}'.format(ipaddr))

    with open("config.txt") as json_file:
        items = json.load(json_file)
        geoip_url = items["geoip_url"]
        pymongo_url = items["pymongo_url"]

    # pymongo setup
    client = pymongo.MongoClient(pymongo_url)
    db = client.data


    
