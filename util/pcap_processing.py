# Goal: Parse PCAP files using Kamene

# KOAES 23 January 2019

import logging

logging.getLogger("kamene.runtime").setLevel(logging.ERROR)

from kamene.all import *

import time



def CreateCSV(pkts, number, fo):

    options =""
    finalString = ""
    raw = ""
    dtg = ""

    dtg = (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkts.time))).split(" ")
    finalString += dtg[0] + "," + dtg[1] + ","
    try:
        finalString += str(pkts[IP].src) + ","
        finalString += str(pkts[IP].len) + ","
        finalString += str(pkts[IP].ttl) + ","
    except:
        print ("Not IP")
        return
    try:
        finalString += str(pkts[TCP].sport) + ","
        finalString += str(pkts[TCP].dport) + ","
        finalString += str(pkts[TCP].flags) + ","
        finalString += str(pkts[TCP].window) + ","
        test = (pkts[TCP].options)

        for i in test:
            options+=(i[0] + " " + str(i[1]) + " ")
        options = options.replace(",","")
        finalString += options + ","
    except:
        try:
            if ("M-SEARCH" in str(pkts[Raw])):
                finalString += options + ""
        except:
            pass
        try:
            finalString += str(pkts[UDP].sport) + ","
            finalString += str(pkts[UDP].dport) + ",,,,"

            try:
               finalString += str(pkts[DNS].opcode) + ""
            except:
                print("No DNS")
                pass
            try:
                if("5060" in str(pkts[UDP].dport)):
                   finalString += options + ""
            except:
                print("No SIP")
                pass
            
        except:
            pass
            print("No UDP")

        try:
            finalString += str(pkts[ICMP].type) + ","
            finalString += str(pkts[ICMP].code) + ",,,,"
               
        except:
            print("Not TCP\n" + str(pkts.show()))

    try:
        raw = str(pkts[Raw]).replace(",","") 
        finalString += str(raw)
    except:
        pass
    finalString += ",35.204.86.191"
    fo.write(finalString + "\n")
    

pkts = rdpcap("30Jan_tokyo.pcap")


action = 2

if action == 0:
    print (pkts[252].show())
elif action == 1:
    k = (pkts[77])
    fo = open("test.txt","a")
    CreateCSV(k, 335, fo)
    fo.close()
else:
    fo = open("30Jan_tokyo.csv","a")
    fo.write("Date,Time,srcIP,len,ttl,sport,dport,flags,window,options,raw,hid\n")
    for i,k in enumerate(pkts):
        CreateCSV(k, 335, fo)
    fo.close()


#print(pkts.sessions().items())
#for k,v in pkts.sessions().items():
    #print(v.show())
    #print ("Session" + str(i))
    #for pkts in v:
    #    print(pkts.show())
    #i = i+1




    
