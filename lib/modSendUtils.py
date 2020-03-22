import datetime
from lib import settings

def sendData(metadata, results):

    currentDT = datetime.datetime.now()
    dataToSend = {"nodename":metadata["nodename"],"time":currentDT, "srcip":str(metadata["srcip"]),"dpt":str(metadata["dpt"]),"result":results,"nodeip":settings.ipaddr}
    settings.db.Apr1.insert(dataToSend)
