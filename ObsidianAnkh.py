import json
import socket
from _thread import *
import threading
import select
import traceback
import time
import subprocess
import datetime
import requests
import pymongo
import ipaddress
import ssl


from lib import modProtocols
from lib import settings
from lib import modSendUtils

print_lock = threading.Lock()

ports2 = [443]
uports = [5556,7000]


# Read the ufw logs
def readLogs(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def locationLookup(srcip):

    locData ={}
    passedData = {}

    if srcip in ipLocations:

        locs = ipLocations[srcip].split(",")
        locData["isp"] = locs[0]
        locData["org"] = locs[1]
        locData["countryname"] = locs[2]
        locData["connection"] = locs[3]
        locData["countrycode"] = locs[4]
        locData["city"] = locs[5]
        locData["lat"] = locs[6]
        locData["long"] = locs[7]

        return locData
    else:

        
        URL = geoip_url+srcip
        
        try:
            locData = r = requests.get(url = URL)
            locData = r.json()
            passedData["isp"] = locData["isp"]
            passedData["org"] = locData["organization"]
            passedData["countryname"] = locData["country_name"]
            passedData["connection"] = locData["connection_type"]
            passedData["countrycode"] = locData["country_code2"]
            passedData["city"] = locData["city"]
            passedData["lat"] = locData["latitude"]
            passedData["long"] = locData["longitude"]
            
            ipLocations[srcip] = (str(passedData["isp"])+","+
                                  str(passedData["org"])+","+
                                  str(passedData["countryname"])+","+
                                  str(passedData["connection"])+","+
                                  str(passedData["countrycode"])+","+
                                  str(passedData["city"])+","+
                                  str(passedData["lat"])+","+
                                  str(passedData["long"]))
            return passedData

        except:
            print(URL)
            traceback.print_exc()
            passedData["countrycode"] = "UNK"
            passedData["city"] = "UNK"
            passedData["lat"] = "0"
            passedData["long"] = "0"
            return passedData


def startlogfiles():

    logfile = open("/var/log/ufw.log","r")
    loglines = readLogs(logfile)
    for line in loglines:

        if "[UFW AUDIT]" in line and ("SRC="+socket.gethostbyname(socket.gethostname())) not in line:
        #if "[UFW AUDIT]" in line and ("SRC=127.0.0.1") not in line:

            packetDict = {}
            data = {}
            data2 = {}
            date = ""
            results = line.split(" ")

            if(datetime.date.today().day) < 10:
                date_preFormat = ('2019-'+results[0]+'-'+results[2]+' '+results[3])
                data["nodename"] = results[4]
            else:
                date_preFormat = ('2019-'+results[0]+'-'+results[1]+' '+results[2])
                data["nodename"] = results[3]
            
            data["nodeip"] = settings.ipaddr
            timer = (datetime.datetime.strptime(date_preFormat,'%Y-%b-%d %H:%M:%S'))
            data['time'] = timer

            for i in results:
                if "=" in i:
                    item = i.split("=")
                    packetDict[item[0]] = item[1]
            try:
                data["dpt"] = packetDict.get("DPT")
                data["srcip"] = packetDict.get("SRC")
                data["proto"] = packetDict.get("PROTO")
                data["ttl"] = packetDict.get("TTL")
                data["type"] = packetDict.get("TYPE")
                data["code"] = packetDict.get("CODE")
                data["windowsize"] = packetDict.get("WINDOW")

            except:
                    print_lock.acquire()
                    print(results)
                    traceback.print_exc()
                    print_lock.release()
            #locational info based on Src IP ==========

            data2 = locationLookup(data["srcip"])
            data["isp"] = data2.get("isp")
            data["org"] = data2.get("org")
            data["countryname"] = data2.get("countryname")
            data["connection"] = data2.get("connection")
            data["countrycode"] = data2.get("countrycode")
            data["city"] = data2.get("city")
            data["lat"] = data2.get("lat")
            data["long"] = data2.get("long")

            #Reverse DNS info ========
            addr4 = ipaddress.ip_address(data["srcip"])
            URL2 = "https://dns.google.com/resolve?name="+str(ipaddress.ip_address(socket.htonl(int(addr4))))+".in-addr.arpa&type=PTR"
            r = requests.get(URL2)
            if "Answer" in r.json():
                rDNS = r.json()["Answer"][0]
                data["rdns"] = rDNS["data"]
            else:
                data["rdns"] = "None"
            #collection set for firecloud
            currentDT = datetime.datetime.now()
            resultDayMonth = currentDT.strftime("%d%b")
            print_lock.acquire()
            #print(data)
            print_lock.release()

            settings.db.Apr1.insert(data)

def threaded(c):

    print_lock.acquire()
    print("\n" + str(datetime.datetime.now()) + " - Connection to tasked port " + str(c.getsockname()[1]))
    print_lock.release()
    result = []
    try:
        metadata = {}
        metadata["nodename"] = socket.gethostname()
        metadata["srcip"] = c.getpeername()[0]
        metadata["dpt"] = c.getsockname()[1]
    except:
        print_lock.acquire()
        print("Error Getting Metadata")
        traceback.print_exc()
        print_lock.release()
        c.close()
        return

    if (c.getsockname()[1] == 23) or (c.getsockname()[1] == 2323):
        modProtocols.telnet(c, metadata)
        return
    if c.getsockname()[1] == 21:
        modProtocols.ftp(c, metadata)
        print_lock.acquire()
        print("Out of FTP")
        print_lock.release()
        return
    if c.getsockname()[1] == 25:
        modProtocols.smtp(c, metadata)
        print_lock.acquire()
        print("Out of SMTP")
        print_lock.release()
        return
    if c.getsockname()[1] == 445:
        modProtocols.smb(c, metadata)
        return
    if c.getsockname()[1] == 443:
        modProtocols.tls(c, metadata)
        return
    if c.getsockname()[1] == 4786:
        modProtocols.cisco(c, metadata)
        return
    if c.getsockname()[1] == 3389:
        modProtocols.rdp(c, metadata)
        return
    if c.getsockname()[1] == 7001:
        modProtocols.weblogic(c, metadata)
        return
    if c.getsockname()[1] == 5555:
        modProtocols.adb(c, metadata)
        return
    if c.getsockname()[1] == 81:
        modProtocols.goAhead(c, metadata)
        return
    if c.getsockname()[1] == 80 or c.getsockname()[1] == 8545:
        modProtocols.http(c, metadata)
        return
    if c.getsockname()[1] == 8086868:
        hadoop(c, metadata)
        return

    while True:
        try:
            data = c.recv(4096)
            result.append(str(data))
            if not data:
                break
            
        except:
            print_lock.acquire()
            print("No data from Generic Connection")
            traceback.print_exc()
            print_lock.release()
            result.append(" ")
            #return

        print_lock.acquire()
        print(str(result))
        modSendUtils.sendData(metadata,str(result))
        print_lock.release()
        break
    print_lock.acquire()
    print( str(datetime.datetime.now()) + " - Connection closed to port", c.getsockname()[1])
    print_lock.release()    
    c.close()
    return

def connectionAccept(servers):
    while True:
        readable,_,_ = select.select(servers,[],[])
        ready_server = readable[0]

        
        c, addr = ready_server.accept()
        if c.getsockname()[1] == 443:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile="cert.pem")
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')  
            c = context.wrap_socket(c, server_side=True)
            start_new_thread(threaded,(c,))

        else:
            start_new_thread(threaded,(c,))


servers = []
ipLocations = {}

settings.init()


try:
    results = list(settings.db.tasklist.find({"name":"p1"}))
    #results = list(settings.db.tasklist.find({"name":"p2"}))

    ports = (results[0]["tasklist"])
except:
    print("!!!!! Unable to download task list; switching to local task list !!!!!")
    ports = ports2

for x in reversed(range(2,100)):
    try:
        subprocess.run(["ufw", "--force", "delete", str(x)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(e.output)

# Setup for locational information
filename = "locs"
for line in open(filename, 'r'):
    try:
        (key, val) = line.split(":")
        ipLocations[key] = val
    except:
        print(line)

host = ""

for port in ports:
    output = subprocess.run(["ufw", "allow", str(port)], stdout=subprocess.PIPE)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(15)
    servers.append(s)

for port in uports:
    output = subprocess.run(["ufw", "allow", str(port)], stdout=subprocess.PIPE)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))
    #s.listen(5)
    servers.append(s)   


print_lock.acquire()
print("Bound to " + str(ports))
start_new_thread(startlogfiles,())
#start_new_thread(commands,())
print_lock.release()


connectionAccept(servers)


s.close()



