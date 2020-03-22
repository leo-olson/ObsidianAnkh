import json
import pymongo
from collections import Counter
import datetime

with open("config.txt") as json_file:
    items = json.load(json_file)
    geoip_url = items["geoip_url"]
    pymongo_url = items["pymongo_url"]

client = pymongo.MongoClient(pymongo_url)
db = client.data


def counter():
    counter = db.mar30.find({"countrycode":"RU"}).count()
    print(counter)

def aggregate2():
    totals = db.mar30.aggregate([{"$match": {"countrycode":"RU"}}])

    counter = []
    for items in list(totals):
        counter.append(items["srcip"])
        #print(items["srcip"])
        
    for key, value in Counter(counter).items():
        print(key, value)

def aggregate():
    for x in db.Apr1.aggregate([{"$match": {"countrycode":"RU"}}, {"$group":{"_id":"$srcip","port":{"$push":"$dpt"}, "total":{"$sum":1}}}]):
        result = dict(Counter(x["port"]))
        print(result)

def pullLocs():
    print("pulling Locations")
    locData = {}
    tracker = {}
    cursor = db.Apr1.find()
    for doc in cursor:
        try:
            if doc["countrycode"] != None:
                if doc["srcip"] not in tracker:
                    tracker[doc["srcip"]] = "y"
                    locData["srcip"] = doc.get("srcip")
                    locData["countrycode"] = doc.get("countrycode")
                    locData["city"] = doc.get("city")
                    locData["lat"] = doc.get("lat")
                    locData["long"] = doc.get("long")
                    
                    print(locData["srcip"]+":"+locData["countrycode"]+","+str(locData["city"])+","+str(locData["lat"])+","+str(locData["long"]))
        except:
            continue

def pullData():

    fromTime = datetime.datetime(2019,1,11,0,0,0)
    toTime = datetime.datetime(2019,11,11,23,59,59)
    
    for x in db.Apr1.find({"srcip":"73.180.246.57","time":{"$gt":fromTime,"$lt":toTime}},{"_id":1,"time":1,"srcip":1,"dpt":1}):
        print(x)


def removeData():

        fromTime = datetime.datetime(2019,1,11,0,0,0)
        toTime = datetime.datetime(2019,12,11,23,59,59)

        result = db.Apr1.remove({"srcip":"73.180.246.57","time":{"$gt":fromTime,"$lt":toTime}})
        print(result)

def insertPorts():
    updates = {"23":"Telnet",
               "25":"SMTP",
               "80":"HTTP",
               "81":"GoAhead IoT",
               "110":"POP3",
               "118":"?",
               "123":"NTP",
               "135":"RPC DCOM",
               "139":"NetBIOS",
               "143":"IMAP",
               "161":"POP",
               "389":"LDAP",
               "443":"TLS",
               "554":"RTSP CAMERA",
               "587":"?",
               "623":"IPMI-RMCP",
               "631":"CUPS/IPP PRINTER",
               "636":"LDAP SSL",
               "760":"?",
               "990":"FTPS",
               "992":"TelnetS",
               "993":"IMAP over SSL",
               "995":"POP over SSL",
               "1025":"NFS",
               "1080":"SOCKS Proxy",
               "1400":"Sonos",
               "1433":"MS SQL",
               "2001":"VoiP related?",
               "2082":"CPanel",
               "2083":"CPanel",
               "2222":"?",
               "2323":"telnet",
               "2375":"Docker Daemon",
               "2379":"DigialOcean Kubernetes",
               "2628":"?",
               "3000":"Node.js",
               "3030":"Real Server",
               "3128":"SquidProxy",
               "3129":"HTTP-Proxy",
               "3260":"iSCSI",
               "3306":"MSSQL",
               "3335":"poipoi",
               "3389":"RDP",
               "3390":"MS SQL",
               "3391":"?",
               "3397":"?",
               "4782":"Quasar RAT",
               "4786":"Cisco Smart Install",
               "5038":"Asterisk Call Manager",
               "5060":"SIP",
               "5800":"VNC",
               "5822":"Y3K RAT",
               "5555":"ADB",
               "5901":"VNC",
               "5908":"VNC",
               "5903":"VNC-3",
               "5984":"couchDB",
               "6001":"x11",
               "6010":"x11",
               "6379":"redis",
               "6669":"MiRC",
               "7001":"Oracle Weblogic",
               "7547":"SOAP",
               "8001":"Icecast/SmartTV",
               "8008":"Chromecast",
               "8080":"?",
               "8081":"?",
               "8089":"Splunk",
               "8090":"?",
               "8118":"Privoxy",
               "8443":"Ubiquiti Web UI",
               "8545":"JSON RPC (Etherium)",
               "8998":"?",
               "9000":"kGuard Camera",
               "9200":"Elasticsearch",
               "9999":"Abyss Web",
               "10001":"Ubiquiti",
               "11211":"Memcached",
               "27017":"MongoDB",
               "44818":"Rockwell Automation Control",
               "65533":"?"
               }
    
    for x in updates:
        print(updates[x])
        portToSend = {}
        portToSend[x]=updates[x]
    result =  db.ports.insert(updates)

print("Starting up")
#pullData()
#aggregate()
#removeData()
#insertPorts()
pullLocs()
