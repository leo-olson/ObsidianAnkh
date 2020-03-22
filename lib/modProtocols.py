import threading
import traceback
from lib import modSendUtils
import datetime


telnetPrev = {}

def telnet(c, metadata):
    print_lock = threading.Lock()
    #metadata = {}
    #metadata["nodename"] = socket.gethostname()
    #metadata["srcip"] = c.getpeername()[0]
    #metadata["dpt"] = c.getsockname()[1]

    lineFeed = 0 # used to track telnet upcoming line feed
    cmd = "" # string variable that holds telnet strings
    iac = 0 # used to track telnet IAC commands
    telnetArray = [] # array that holds cmd variables before sending to database
    telnetCmd = []
    codeWord = []
    accessAttempts = 0
    firstround = 0
    username = "" # string that will store the first username attempted and then populate the cmd prompt with that
    flag = "initial"
    #Banner = "MikroTik v6.27"
    #Banner = "BCM96318 Broadband Router\r\nLogin: "
    Banner = "PLi dm500 OpenPLi 20130505 (based on 1.09)\r\nWelcome to your dreambox! - Kernel 2.6.9 (17:27:29)."
    #Banner=""
    cmdPrompt = ""


    shellTesting = ["enable", "system", "shell", "bah", "wlahh", "linuxshell","wget", "Zfbin/busyboxxbzz"]

    #cat: can't open '.s': No such file or directory

    echoHeader = (b'\x7F\x45\x4C\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x02\x00\x3E\x00\x01\x00\x00\x00\x00\x18\x40\x00\x00\x00\x00\x00'
    b'\x40\x00\x00\x00\x00\x00\x00\x00\x50\x73\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00')
    ddOutput = "1+0 records in\r\n1+0 records out\r\n52 bytes copied, 0.00034588 .s, 150kb/s"

    ###print("\r\nTelnet connection from "+ str(c.getpeername()[0]) + " at " + str(datetime.datetime.now()))
    ###print_lock.release()
    c.send(b'\xff\xfb\x01')
    while 1:
        if flag == "disconnect":
            ###print("Exiting")
            break
        while 1:

            try:
                ###print("Flag is: "+flag)
                # Send the banner and login; query for password
                if flag == "initial":
                    #print("Initial: Sending: "+Banner+"\r\ndm500 Login:")
                    c.send(str.encode(Banner+"\r\ndm500 Login: "))
                    flag = "password"
                    break
                # Check if the IP has been seen before
                if flag == "password":
                    # IP seen before; deny access 
                    if (metadata["srcip"]) in telnetPrev.keys():
                        #print("\nPassword: IP Seen Before.  Starting failed login loop\n")
                        flag = "login"
                    # IP new; log it in telnetPrev and grant access; currently, this means IP can only access system once
                    else:
                        telnetPrev[metadata["srcip"]] = "" #comment to turn off limited access
                        flag = "access" # comment to also send to password Gather mode
                        #print("\nPassword: IP not seen before; adding it")
                        #flag = "login" # comment to block Gather mode
                    #print(str(telnetPrev))
                    #print("Password: ")
                    c.send(str.encode("\r\nPassword: "))
                    break

                if flag == "login":
                    if cmd == telnetPrev[metadata["srcip"]]:
                        flag = "access"
                        break

                    #print("\nLogin Loop: Sending: Login Incorrect\r\ndm500 Login: ")
                    c.send(str.encode("\r\nLogin incorrect\r\n"))
                    c.send(str.encode(Banner+"\r\ndm500 Login: "))
                    flag = "password"
                    break
                
                if flag == "disconnect":
                    break
                
                if flag == "access":
                    if accessAttempts == 1:
                        telnetPrev[metadata["srcip"]] = cmd
                        accessAttempts == 2

                    cmdPrompt = username+"@Ingenic-uc1_1:~#"
                    #print("*** Access has been Granted***")
                    if cmd in shellTesting:
                        #print(("\r\nsh: "+cmd+": not found\r\n"+cmdPrompt))
                        c.send(str.encode("\r\nsh: "+cmd+": not found\r\n"+cmdPrompt))
                        accessAttempts+=1
                    elif "cat /proc/mounts" in cmd:
                        #mountSend = "\r\n"+cmdPrompt+"\r\nrootfs / ext2 ro 0 0\r\n/dev/root / ext2 ro 0 0\r\npublic /var tmpfs rw 0 0\r\n"+codeWord[1]+": applet not found\r\n[root@fox /]#"
                        mountSend = "\r\n"+cmdPrompt+"\r\nrootfs / ext2 ro 0 0\r\n/dev/root / ext2 ro 0 0\r\npublic /var tmpfs rw 0 0\r\n"+cmdPrompt+"\r\n"+codeWord2[1]+": applet not found\r\n"+cmdPrompt

                        #print(mountSend)
                        c.send(str.encode(mountSend))
                    #elif "wget" in cmd:
                    #    print(cmdPrompt+"\r\nBusyBox v1.20.0 (2012-04-22 12:29:58 CEST) multi-call binary.\r\n\r\nUsage: wget [-c|--continue] [-s|--spider] [-q|--quiet] [-O|--output-document FILE]\r\nRetrieve files via HTTP or FTP\r\n[root@fox /]#")
                        #c.send(str.encode("\r\n"+cmdPrompt+"\r\nBusyBox v1.20.0 (2012-04-22 12:29:58 CEST) multi-call binary.\r\n\r\nUsage: wget [-c|--continue] [-s|--spider] [-q|--quiet] [-O|--output-document FILE]\r\nRetrieve files via HTTP or FTP\r\n"+codeWord[1]+": applet not found\r\n[root@fox /]#"))
                    #    c.send(str.encode("\r\n"+cmdPrompt+"\r\nBusyBox v1.20.0 (2012-04-22 12:29:58 CEST) multi-call binary.\r\n\r\nUsage: wget [-c|--continue] [-s|--spider] [-q|--quiet] [-O|--output-document FILE]\r\nRetrieve files via HTTP or FTP\r\n[root@fox /]#"))
                    elif "dd bs=52 count=1" in cmd:
                        #print("Sending: "+str(echoHeader))
                        c.send(echoHeader)
                    elif " ps;" in cmd:
                        psSend = "\r\n"+cmdPrompt+"\r\nPID    USER    TIME    COMMAND\r\n   1  0      0:00  {init} /bin/sh /sbin/init\r\n"+cmdPrompt+"\r\n"+codeWord2[1]+": applet not found\r\n"+cmdPrompt
                        #print(psSend)
                        c.send(str.encode(psSend))
                    elif "/bin/busybox rm" in cmd:
                        #print("Sending: "+cmdPrompt)
                        c.send(str.encode("\r\n"+cmdPrompt+""))
                    elif "/bin/busybox cp /" in cmd:
                        #print("Sending: "+codeWord2[1]+": applet not found\r\n"+cmdPrompt)
                        c.send(str.encode("\r\n"+cmdPrompt+"\r\n"+codeWord2[1]+": applet not found\r\n"+cmdPrompt))
                    elif "/bin/busybox cat" in cmd:
                        catSend = "ELF>x@@@8@@@yy .shstrtab.text"
                        #print(echoHeader)
                        c.send(str.encode(echoHeader))
                        
                    elif "/bin/busybox " in cmd:
                        #print("Sending: "+codeWord[1]+": applet not found\r\n"+cmdPrompt)
                        c.send(str.encode("\r\n"+cmdPrompt+"\r\n"+codeWord[1]+": applet not found\r\n"+cmdPrompt))
                    else:
                        #print("Sending: "+cmdPrompt)
                        c.send(str.encode("\r\n"+cmdPrompt+""))
                    break

            except:
                print_lock.acquire()
                print("Error sending login")
                print_lock.release()
                traceback.print_exc()
                break

        cmd = ""
        while 1:
            try:
                data = c.recv(1)
                if data == b'':
                    c.close()
                    ###print("No Data Sent; Exiting out of loop")
                    flag = "disconnect"
                    break
                #print(str(data) + "\t" + str(data.hex()) + "   " + str(ord(data)))
                if data is not None or data is not '':
                    if ord(data) == 13:
                        lineFeed = 1
                        continue
                    if (lineFeed == 1 and ord(data)==10) or (lineFeed == 1 and ord(data)==0):
                        #print("Breaking")
                        lineFeed = 0
                        break

                    if(ord(data)) == 255:
                        iac = 1
                        continue
                    if iac>0 and iac < 3:
                        if iac == 2:
                            iac = 0
                            telnetCmd.append(data)
                            continue
                        else:
                            iac+=1
                            telnetCmd.append(data)
                            continue

                    if iac == 0:
                        if (ord(data) > 31) and (ord(data) < 128):
                            cmd+= data.decode('ascii')
                        else:
                            print_lock.acquire()
                            #print(data)
                            print_lock.release()
            
            except TypeError:
                print_lock.acquire()
                print(data)
                print_lock.release()
            except ConnectionResetError:
                print_lock.acquire()
                print("ConnectionResetError; Exiting out of Loop")
                flag = "disconnect"
                print_lock.release()
                break

        #if cmd == "admin":
        #    print("Setting flag")
        #    flag = "access"

        ###print("== Recv'd: "+cmd)
        if accessAttempts == 0:
            username = cmd
            ###print("Setting username to : "+ username)
            accessAttempts+=1 #turned off for auto login

        if "/bin/busybox" in cmd:
            #flag = "access"
            codeWord = cmd.split("/bin/busybox ")
            if firstround == 0:
                codeWord2 = cmd.split("/bin/busybox ")
                firstround = 1

        #print(cmd)
        telnetArray.append(cmd)
        #if flag=="access":
        #    print(telnetArray)
        #print(telnetCmd)
        #print("Flag is: "+flag)



    if not len(telnetArray) == 0:
        
        modSendUtils.sendData(metadata,str(telnetCmd)+str(telnetArray))
        print_lock.acquire()
        print("\nConnection complete: ")
        print(telnetArray)
        print_lock.release()
    c.close()
    return (metadata,str(telnetCmd)+str(telnetArray))


def ftp(c, metadata):
    print_lock = threading.Lock()
    result = []
    srcip = str(metadata["srcip"])
    while 1:
        try:
            c.send(str.encode("220 ProFTPD 1.3.4a server (ftp.geombh.de) [::ffff:"+srcip+"]\n"))
            data = c.recv(1028)
            if not data:
                print("well")
            result.append(str(data))
            c.send(str.encode("331 Anonymous login ok, send your complete email address as your password\n"))
            data = c.recv(1028)
            if not data:
                print("well")
            result.append(str(data))
            c.send(str.encode("230- Welcome, archive user!\n"))
            c.send(str.encode("230-\n"))
            c.send(str.encode("230 Anonymous access granted\n"))
            data = c.recv(1028)
            if not data:
                print("well")
            result.append(str(data))
            c.send(b'\x32\x31\x35\x20\x55\x4e\x49\x58\x20\x54\x79\x70\x65\x3a\x20\x4c\x38\x0d\x0a')

        except:
            print_lock.acquire()
            print("Error in 1st sending")
            traceback.print_exc()
            cmd = 1
            print_lock.release()
            break
        print(result)
        return

def smtp(c, metadata):
    print_lock = threading.Lock()
    result = []
    cmd = 0
    prepToBreak = 0
    while 1:
        if cmd==0:
            try:
                data = c.recv(1028)
                if not data:
                    print("well")
                result.append(str(data))
                c.send(str.encode("220 maildb01.netsetter.net ESMTP Postfix (Ubuntu)\n"))
            except:
                print_lock.acquire()
                print("Error in 1st sending")
                traceback.print_exc()
                cmd = 1
                print_lock.release()
                break

            while 1:
                try:
                    data = c.recv(1028)
                    if data == b'':
                        cmd==1
                        break
                    result.append(str(data))


                    if ("EHLO" in str(data)) or ("HELO" in str(data)):
                        c.send(str.encode('250-maildb01.netsetter.net\n'
                                          '250-PIPELINING\n'
                                          '250-SIZE 10240000\n'
                                          '250 DSN\n'
                                          ))

                    elif("MAIL FROM:" in str(data)):
                        c.send(str.encode('250 2.1.0 Ok\n'))
                    elif("RCPT TO:" in str(data)):
                        c.send(str.encode('250 2.1.5 Ok\n'))
                    elif("QUIT" in str(data)):
                        c.send(str.encode('221 2.0.0 Bye\n'))
                        cmd = 1
                        break
                    elif("DATA" in str(data)):
                        c.send(str.encode('354 End data with <CR><LF>.<CR><LF>\n'))
                        while 1:
                            data = c.recv(1028)
                            if data == b'':
                                cmd == 1
                                break
                            result.append(str(data))                       
                            if(data == b"\x2e\x0d\x0a"):
                                c.send(str.encode('250 2.0.0 Ok: queued as 65A5E1A026d\n'))
                                break 
                            elif data.find(b'\r\n.\r\n') > 0:
                                c.send(str.encode('250 2.0.0 Ok: queued as 65A5E1A026d\n'))
                                break 
                    else:
                        c.send(str.encode('502 5.5.2 Error: command not recognized\n'))
                except:
                    print_lock.acquire()
                    print("Error in 2nd Sending")
                    traceback.print_exc()
                    cmd == 1
                    print_lock.release()

                if cmd == 1:
                    break
        else:
            break

    try:

        modSendUtils.sendData(metadata,str(result))
        print_lock.acquire()
        print(result)
        print( str(datetime.datetime.now()) + " - Connection closed to port", c.getsockname()[1])
        print_lock.release()    
        
        return
    except:
        print_lock.acquire()
        print("At return")
        print_lock.release() 
        return



def smb(c, metadata):
    smbresults=""
    result=[]
    
    smbHeader = (b'\x00\x00\x00\x7f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x98\x01\x28\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    smbHeader2 = (b'\x00\x00\x01\x37\xff\x53\x4d\x42\x73\x16\x00\x00\xc0\x98\x01\x28\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    smbHeaderStatusLoginFailure = (b'\x00\x00\x00\x23\xff\x53\x4d\x42\x73\x6d\x00\x00\xc0\x98\x01\x68\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    smbHeaderBasicResp = (b'\x00\x00\x00\x79\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x98\x01\x20\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    smbHeaderTreeConnectResponse = (b'\x00\x00\x00\x2e\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x98\x01\x28\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08')

    smbHeaderTransResp = (b'\x00\x00\x00\x23\xff\x53\x4d\x42\x25\x05\x02\x00\xc0\x98\x01\x68\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08')

    smbHeaderTransResp2 = (b'\x00\x00\x00\x23\xff\x53\x4d\x42\x32\x02\x00\x00\xc0\x98\x07\xc0\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08')

    smbHeaderTransResp3 = (b'\x00\x00\x00\x23\xff\x53\x4d\x42\xa0\x00\x00\x00\x00\x98\x07\xc0\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08')

    vulnSmbHeader = (b'\x00\x00\x00\xb4\xff\x53\x4d\x42\x72\x05\x02\x00\xc0\x98\x53\xc8\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00')

    response = (b'\x11\x03\x00\x03\x32\x00\x01\x00\x04\x11\x00\x00\x00\x00\x01\x00'
    b'\x00\x00\x00\x00\xfc\xe3\x01\x80\xc8\x0e\x9f\x6e\x5a\x1a\xd5\x01'
    b'\x68\x01\x00\x3a\x00\x4d\x57\xa2\xbd\xfa\xfb\xb9\x4b\xb8\xb0\x2a'
    b'\x6f\x05\xa2\x26\xe0\x60\x28\x06\x06\x2b\x06\x01\x05\x05\x02\xa0'
    b'\x1e\x30\x1c\xa0\x1a\x30\x18\x06\x0a\x2b\x06\x01\x04\x01\x82\x37'
    b'\x02\x02\x1e\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a')

    challenge = (b'\x04\xff\x00\x37\x01\x00\x00\xc6\x00\x0c\x01\x4e\x54\x4c\x4d\x53'
    b'\x53\x50\x00\x02\x00\x00\x00\x16\x00\x16\x00\x38\x00\x00\x00\x05'
    b'\x02\x8a\xa2\x21\xa9\x34\x58\x81\xd0\xd0\xb0\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x78\x00\x78\x00\x4e\x00\x00\x00\x06\x01\xb1\x1d\x00'
    b'\x00\x00\x0f\x44\x00\x41\x00\x52\x00\x4b\x00\x53\x00\x49\x00\x44'
    b'\x00\x45\x00\x44\x00\x45\x00\x56\x00\x02\x00\x16\x00\x44\x00\x41'
    b'\x00\x52\x00\x4b\x00\x53\x00\x49\x00\x44\x00\x45\x00\x44\x00\x45'
    b'\x00\x56\x00\x01\x00\x16\x00\x44\x00\x41\x00\x52\x00\x4b\x00\x53'
    b'\x00\x49\x00\x44\x00\x45\x00\x44\x00\x45\x00\x56\x00\x04\x00\x16'
    b'\x00\x44\x00\x41\x00\x52\x00\x4b\x00\x53\x00\x49\x00\x44\x00\x45'
    b'\x00\x44\x00\x45\x00\x56\x00\x03\x00\x16\x00\x44\x00\x41\x00\x52'
    b'\x00\x4b\x00\x53\x00\x49\x00\x44\x00\x45\x00\x44\x00\x45\x00\x56'
    b'\x00\x07\x00\x08\x00\xf1\x23\x9a\x17\x5e\x1a\xd5\x01\x00\x00\x00'
    b'\x00\x57\x69\x6e\x64\x6f\x77\x73\x20\x37\x20\x50\x72\x6f\x66\x65'
    b'\x73\x73\x69\x6f\x6e\x61\x6c\x20\x37\x36\x30\x31\x20\x53\x65\x72'
    b'\x76\x69\x63\x65\x20\x50\x61\x63\x6b\x20\x31\x00\x57\x69\x6e\x64'
    b'\x6f\x77\x73\x20\x37\x20\x50\x72\x6f\x66\x65\x73\x73\x69\x6f\x6e'
    b'\x61\x6c\x20\x36\x2e\x31\x00')

    sessionSetupResponse73 = (b'\x03\xff\x00\x79\x00\x00\x00\x50\x00\x57\x69\x6e\x64\x6f\x77\x73'
    b'\x20\x37\x20\x50\x72\x6f\x66\x65\x73\x73\x69\x6f\x6e\x61\x6c\x20'
    b'\x37\x36\x30\x31\x20\x53\x65\x72\x76\x69\x63\x65\x20\x50\x61\x63'
    b'\x6b\x20\x31\x00\x57\x69\x6e\x64\x6f\x77\x73\x20\x37\x20\x50\x72'
    b'\x6f\x66\x65\x73\x73\x69\x6f\x6e\x61\x6c\x20\x36\x2e\x31\x00\x57'
    b'\x4f\x52\x4b\x47\x52\x4f\x55\x50\x00')

    while 1:
        #print("Recv'ing Data")
        data = c.recv(1024)
        if not data:
            break
        data3 = (''.join(["%02X " % (x) for x in data]).strip())
        smbheader = data[0:36]
        #print("\nSMB Header")
        
        #print (''.join(["%02X " % (x) for x in smbheader]).strip())
        smbCmd = ord(smbheader[8:9])
        #print ("SMB Command = " + (smbheader[8:9].hex()))
        #print("Flags2 = " + str(smbheader[14:16].hex()))
        processID = smbheader[30:32]
        #print("Process Id: "+str(processID.hex()))
        multiplexID = smbheader[34:36]
        #print("Multiplex Id: "+str(multiplexID.hex()))
        
        if smbCmd == 114:
            #print ("\nNegotiate Protocol Request")
            data2 = data[36:]
            #print (''.join(["%02X " % (x) for x in data2]).strip())
            #print("Requested Dialects:")
            dialects = ((data[39:]).split(b'\x02'))
            for i in dialects:
                #print (i)
                if b'NT LM 0.12' in i:
                    dialectIndex = (dialects.index(i)) - 1
            #print("Dialect Index = " + str(dialectIndex)+"\n")
            result.append(str(smbCmd)+","+str(processID)+","+str(multiplexID)+","+str(dialectIndex))
        
            #print("Sending SMB Negotiate Response")
            c.send(smbHeader+processID+b'\x00\x00'+multiplexID+response)
            
        if smbCmd == 115:
            #print("\nSession Setup andX Request 1:NTLMSSP_Negotiate")
            data2 = data[36:]
            #print (''.join(["%02X " % (x) for x in data2]).strip())
                          
            #print(data2[35])
            result.append("NTLMSSP_Negotiate "+data3)
            if (data2[35]) == 1:
                #print("\nSending NTLMSSP_Challenge")
                c.send(smbHeader2+processID+b'\x00\x00'+multiplexID+challenge)

            elif (data2[35]) == 3:
                #print("Session Setup andX Request: NTLMSSP_AUTH")
                #print("\nSending Login Failure\n")
                c.send(smbHeaderStatusLoginFailure+processID+b'\x00\x00'+multiplexID+b'\x00\x00\x00')
                data = c.recv(1024)
                #print(data)
                #print("Session Setup andX Request: Basic_Auth")
                #print("\nSending 73 Response")
                c.send(smbHeaderBasicResp+processID+b'\x00\x00'+multiplexID+sessionSetupResponse73)
            else:
                #print("Session Setup andX Request: Basic_Auth")
                #print("\nSending 73 Response")
                c.send(smbHeaderBasicResp+processID+b'\x00\x00'+multiplexID+sessionSetupResponse73)
           

        if (smbCmd) == 117:
            #print("Tree Connect AndX Request")
            #print("\nSending TreeConnect Response")
            result.append("TreeConnect "+data3)
            c.send(smbHeaderTreeConnectResponse+processID+b'\x00\x00'+multiplexID+b'\x03\xff\x00\x2e\x00\x01\x00\x05\x00\x49\x50\x43\x00\x00')

        if (smbCmd) == 37:
            #print("PeekNamedPipe")
            #print("\nSending PeekNamedPipe Response")
            result.append("PeekNamedPipe "+data3)
            c.send(smbHeaderTransResp+processID+b'\x00\x00'+multiplexID+b'\x00\x00\x00')
        if (smbCmd) == 50:
            #print("Trans2")
            result.append("Trans2 "+data3)
            c.send(smbHeaderTransResp2+processID+b'\x00\x00'+multiplexID+b'\x00\x00\x00')
        if (smbCmd) == 10:
            #print("Trans Request")
            result.append("TransRequest "+data3)
            c.send(smbHeaderTransResp3+processID+b'\x00\x00'+multiplexID+b'\x00\x00\x00')

 

    modSendUtils.sendData(metadata,str(result))
    return


def cisco(c, metadata):
    print_lock = threading.Lock()
    metadata = {}
    try:
        metadata["nodename"] = socket.gethostname()
        metadata["srcip"] = c.getpeername()[0]
        metadata["dpt"] = c.getsockname()[1]
    except:
        c.close()
        return

    result = []
    while True:
        try:
            
            data = c.recv(1024)
            if not data:
                break
            result.append(str(data))
            print_lock.acquire()
            print(str(data))
            print_lock.release()
            if data == b'\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00':
                c.send(b'\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00')
                data =  c.recv(1024)
                result.append(str(data))
                break
            else:
                break
        except:
            print_lock.acquire()
            print("Error sending login")
            traceback.print_exc()
            print_lock.release()
            break

    if not len(result) == 0:
        modSendutils.sendData(metadata,str(result))
        #print_lock.acquire()
        #print(str(result))
        #print_lock.release()
    c.close()
    return 

def rdp(c, metadata):
    print_lock = threading.Lock()
    result = []

    while 1:
        try:
            data = c.recv(4096)
            result.append(str(data))
            
        except:
            print_lock.acquire()
            print("Failed")
            print_lock.release()

        if "mstshash" in str(data):
            c.send(b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x00\x00\x00\x00)')
        data = c.recv(4096)
        result.append(str(data))
        print_lock.acquire()
        print(result)
        print_lock.release()
        modSendUtils.sendData(metadata,str(result))
        break
    
    return



def weblogic(c, metadata):
    print_lock = threading.Lock()
    result = []
    while True:
        try:
            data = c.recv(1024)
            if not data:
                break
            result.append(str(data))
            print_lock.acquire()
            print(str(data))
            print_lock.release()
            #["b't3 10.3.1\\nAS:255\\nHL:19\\n\\n'"]
            #["b't3 7.0.0.0\\nAS:10\\nHL:19\\n\\n'"]
            if "t3 " in str(data):
                c.send(str.encode("HELO"))
                c.send(str.encode(":10.3.6. 0.false."))
                c.send(str.encode("AS:204 8.HL;19.."))
                break
            else:

                c.send(('HTTP/1.1 200 OK\nConection: close\nContent-Type: text/html\n\nOracle WebLogic Server Administration Console<b><br><version>10.3.6.0'.encode(encoding='utf-8')))
                break
        except:
            print_lock.acquire()
            print("Error sending login")
            
            traceback.print_exc()
            print_lock.release()
            break

    if not len(result) == 0:
        modSendUtils.sendData(metadata,str(result))
        #print_lock.acquire()
        #print(str(result))
        #print_lock.release()
    c.close()
    return


# adb version - get version
# adb connect 192.168.1.2:5555 - connect to device
# adb devices - list of devices attached
# adb kill-server - stop server

def adb(c, metadata):
    print_lock = threading.Lock()
    result = []

    auth = (b'\x41\x55\x54\x48\x01\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00'
            b'\x59\x08\x00\x00\xbe\xaa\xab\xb7\xa6\x22\x05\x71\x2b\xf1\x25\x76'
            b'\xec\x0a\xc7\x8c\x23\x7b\x43\x2a\x7c\xde\x45\x71')

    while True:
        try:
            data = c.recv(1024)
            if not data:
                print_lock.acquire()
                print("No data sent; exiting")
                print_lock.release()
                break
            result.append(str(data))
            c.send(auth)
            data = c.recv(1024)
            if not data:
                print_lock.acquire()
                print("No data sent; exiting")
                print_lock.release()
                break
            result.append(str(data))
        except:
            print_lock.acquire() 
            print("Connection broken")
            print_lock.release()
            break

        if not len(result) == 0:
            modSendUtils.sendData(metadata,str(result))

            print_lock.acquire()
            print( str(datetime.datetime.now()) + " - Connection closed to port", c.getsockname()[1])

            print(str(result))
            print_lock.release()

    c.close()
    return



# CVE-2017-18377

def goAhead(c, metadata):
    print_lock = threading.Lock()
    result = []
    while True:
        try:

            data = c.recv(8192)
            if not data:
                break
            result.append(str(data))
            print_lock.acquire()
            print(str(data))
            print_lock.release()
            if "GET login.cgi" in str(data):
                c.send(('HTTP/1.1 200 OK\nDate: Wed May 3 06:11:22 2019\nServer: GoAhead-Webs\nLast-modified: Thu Jan 1 00:00:00 1970\n'
                                  'Content-type: text/html\nCache-Control:no-cache\nContent-length: 69\nConnection: close\n\n'
                                  'var loginuser="admin";<br><br>var loginpass="admin"<br><br>var pri=10;'.encode(encoding='utf-8')))
            else:
                c.send(('HTTP/1.1 200 OK\nConection: close\nContent-Type: text/html\n\n'.encode(encoding='utf-8')))

        except:
            print_lock.acquire()
            print("Error bytes")
            
            traceback.print_exc()
            print_lock.release()
            break

    if not len(result) == 0:
        modSendUtils.sendData(metadata,str(result))
        #print_lock.acquire()
        #print(str(result))
        #print_lock.release()
    c.close()
    return



def http(c, metadata):
    print_lock = threading.Lock()
    while True:
        try:
            data = c.recv(1024)
        except:
            print_lock.acquire()
            print("Connection broken")
            print_lock.release()
            break
        if not data:
            break
        print_lock.acquire()
        print(data)
        print_lock.release()

        if "ws/v1/cluster/apps/new-application" in str(data):
            r2 = ('HTTP/1.1 200 OK\nConection: close\nContent-Type: text/html\n\n{"application-id":"application_1404198295326_0003"}\n'.encode(encoding='utf-8'))

        elif "eth_blockNumber" in str(data):
            r2 = ('HTTP/1.1 200 OK\nConection: close\nContent-Type: text/html\n\n{"jsonrpc": "2.0","id": 1, "result": "0x4be742"}\n'.encode(encoding='utf-8'))

        else:
            r2 = ('HTTP/1.1 200 OK\nConection: close\nContent-Type: text/html\n\n'.encode(encoding='utf-8'))
            break

        c.send(r2)
        break
        #c.close()

    if not len(str(data)) == 0:
        modSendUtils.sendData(metadata,str(data))

    c.close()
    return

def tls(c, metadata):
    print_lock = threading.Lock()


    while True:
        try:
            
            
            data = c.recv(1024)
        except:
            print_lock.acquire()
            print("Connection broken")
            print_lock.release()
            break
        if not data:
            break
        print_lock.acquire()
        print(data)
        print_lock.release()

        if "ws/v1/cluster/apps/new-application" in str(data):
            r2 = ('HTTP/1.1 200 OK\nConection: close\nContent-Type: text/html\n\n{"application-id":"application_1404198295326_0003"}\n'.encode(encoding='utf-8'))

        elif "eth_blockNumber" in str(data):
            r2 = ('HTTP/1.1 200 OK\nConection: close\nContent-Type: text/html\n\n{"jsonrpc": "2.0","id": 1, "result": "0x4be742"}\n'.encode(encoding='utf-8'))

        else:
            r2 = ('HTTP/1.1 200 OK\nConection: close\nContent-Type: text/html\n\n'.encode(encoding='utf-8'))
            print("Sent page")
            break

        r2 = ('HTTP/1.1 200 OK\nConection: close\nContent-Type: text/html\n\n'.encode(encoding='utf-8'))
        c.send(r2)
        break
        #c.close()

    if not len(str(data)) == 0:
        modSendUtils.sendData(metadata,str(data))

    c.close()
    return
