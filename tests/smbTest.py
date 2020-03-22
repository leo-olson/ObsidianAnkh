import socket

host = ""
port = 445
bbb=0

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

#sessionSetupResponse75

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(5)
print("Server Listening...")

while 1:
    c, client_address = s.accept()
    print("Connection from ", client_address)

    while 1:
        print("Recv'ing Data")
        data = c.recv(1024)
        if not data:
            break
        print (''.join(["%02X " % (x) for x in data]).strip())
        smbheader = data[0:36]
        print("\nSMB Header")
        
        print (''.join(["%02X " % (x) for x in smbheader]).strip())
        smbCmd = ord(smbheader[8:9])
        print ("SMB Command = " + (smbheader[8:9].hex()))
        print("Flags2 = " + str(smbheader[14:16].hex()))
        processID = smbheader[30:32]
        print("Process Id: "+str(processID.hex()))
        multiplexID = smbheader[34:36]
        print("Multiplex Id: "+str(multiplexID.hex()))


        if smbCmd == 114:
            print ("\nNegotiate Protocol Request")
            data2 = data[36:]
            print (''.join(["%02X " % (x) for x in data2]).strip())
            print("Requested Dialects:")
            dialects = ((data[39:]).split(b'\x02'))
            for i in dialects:
                print (i)
                if b'NT LM 0.12' in i:
                    dialectIndex = (dialects.index(i)) - 1
            print("Dialect Index = " + str(dialectIndex)+"\n")

        
            print("Sending SMB Negotiate Response")
            c.send(smbHeader+processID+b'\x00\x00'+multiplexID+response)
            
        #data = c.recv(1024)
        #print(data)
        if smbCmd == 115:
            print("\nSession Setup andX Request 1:NTLMSSP_Negotiate")
            data2 = data[36:]
            print (''.join(["%02X " % (x) for x in data2]).strip())
            print(data2[35])

            if (data2[35]) == 1:
                print("\nSending NTLMSSP_Challenge")
                c.send(smbHeader2+processID+b'\x00\x00'+multiplexID+challenge)

            elif (data2[35]) == 3:
                print("Session Setup andX Request: NTLMSSP_AUTH")
                print("\nSending Login Failure\n")
                c.send(smbHeaderStatusLoginFailure+processID+b'\x00\x00'+multiplexID+b'\x00\x00\x00')
                data = c.recv(1024)
                print(data)
                print("Session Setup andX Request: Basic_Auth")
                print("\nSending 73 Response")
                c.send(smbHeaderBasicResp+processID+b'\x00\x00'+multiplexID+sessionSetupResponse73)
            else:
                print("Session Setup andX Request: Basic_Auth")
                print("\nSending 73 Response")
                c.send(smbHeaderBasicResp+processID+b'\x00\x00'+multiplexID+sessionSetupResponse73)
           

        if (smbCmd) == 117:
            print("Tree Connect AndX Request")
            print("\nSending TreeConnect Response")
            c.send(smbHeaderTreeConnectResponse+processID+b'\x00\x00'+multiplexID+b'\x03\xff\x00\x2e\x00\x01\x00\x05\x00\x49\x50\x43\x00\x00')

        if (smbCmd) == 37:
            print("PeekNamedPipe")
            print("\nSending PeekNamedPipe Response")
            c.send(smbHeaderTransResp+processID+b'\x00\x00'+multiplexID+b'\x00\x00\x00')
        if (smbCmd) == 50:
            print("Trans2")
            c.send(smbHeaderTransResp2+processID+b'\x00\x00'+multiplexID+b'\x00\x00\x00')

 
            



