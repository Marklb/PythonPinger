# from socket import *
import socket
import os
import sys
import struct
import time
import select
import binascii 


ICMP_ECHO_REQUEST = 8

min_rtt = 0.0;
max_rtt = 0.0;
total_rtt = 0.0;
packets_transmitted = 0;
packets_recieved = 0;
 
def checksum(str): 
    csum = 0
    countTo = (len(str) / 2) * 2
    
    count = 0
    while count < countTo:
        thisVal = ord(str[count+1]) * 256 + ord(str[count]) 
        csum = csum + thisVal 
        csum = csum & 0xffffffffL
        count = count + 2
    if countTo < len(str):
        csum = csum + ord(str[len(str) - 1])
        csum = csum & 0xffffffffL
         
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff 
    answer = answer >> 8 | (answer << 8 & 0xff00) 
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    global min_rtt
    global max_rtt
    global total_rtt
    global packets_transmitted
    global packets_recieved
    
    timeLeft = timeout
    
    while 1:
        
        packets_transmitted += 1;
         
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        
        if whatReady[0] == []: # Timeout
            return "Request timed out."
        
        timeReceived = time.time() 
        recPacket, addr = mySocket.recvfrom(1024)
        
        #Fill in start
        
        #Fetch the ICMP header from the IP packet
        ip_header = recPacket[:20] #first 20 bytes
        unpackedData = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        version_and_ihl = unpackedData[0]
        differentiated_services = unpackedData[1]
        total_length = unpackedData[2]
        identification = unpackedData[3]
        flags_and_fragment_offset = unpackedData[4]
        ttl = unpackedData[5]
        protocol = unpackedData[6]
        header_checksum = unpackedData[7]
        source_ip = unpackedData[8]
        dest_ip = unpackedData[9]
        
        print "Version: " + str(version_and_ihl >> 4)
        print "Internet Header Length: " + str(version_and_ihl & 0xF)
        print "ID: " + str(identification)
        print "TTL: " + str(ttl)
        print "Source IP: " + socket.inet_ntoa(source_ip)
        print "Destination IP: " + socket.inet_ntoa(dest_ip)
        print "Bytes:" + str(total_length)
        
#         icmp_header = recPacket[20:28]
        icmp_header = recPacket[20:36]
#         type, code, checksum, id, seq= struct.unpack("bbHHh", icmp_header)
        icmp_header_unpacked = struct.unpack("bbHHhd", icmp_header)
        type = icmp_header_unpacked[0]
        code = icmp_header_unpacked[1]
        checksum_rec = icmp_header_unpacked[2]
        id = icmp_header_unpacked[3]
        sequence = icmp_header_unpacked[4]
        
        
        if id == ID:
                #process error code
                errorMsgs = {0: {0: "Zero-Zero", 1: "Zero-One"}, 1: {0: "One-Zero"}}
                tempType = 0
                tempCode = 0
                
                if tempType in errorMsgs:
                    if tempCode in errorMsgs[tempType]:
                        print errorMsgs[tempType][tempCode]  
                
                
                
                packets_recieved += 1;
#                 sizeofdouble = struct.calcsize("d")
#                 print sizeofdouble
#                 payload = recPacket[28 : 28+sizeofdouble]
#                 unpackedPayload = struct.unpack("d", payload)
#                 timeSent = unpackedPayload[0]
                timeSent = icmp_header_unpacked[5]
                print "efiejf   " + str(icmp_header_unpacked[5])
                timeCalc = (timeReceived-timeSent)*1000
                if timeCalc > max_rtt:
                    max_rtt = timeCalc;
                if min_rtt == 0 or timeCalc < min_rtt:
                    min_rtt = timeCalc;
                
                total_rtt += timeCalc;
                avg_rtt = total_rtt/packets_recieved;
#                 print "Transmitted: " + str(packets_transmitted) + "   Received: " + str(packets_recieved)
                return "TYPE:%d CODE:%d CHECKSUM:0x%08x ID:%d SEQ:%d TIME:%f ms RTT(MIN/AVG/MAX): (%f/%f/%f) LOST: %d   TOTAL TIME: %f" % (type, code, checksum_rec, id, sequence, timeCalc, min_rtt, avg_rtt, max_rtt, (packets_transmitted-packets_recieved), total_rtt)
            
        
        #Fill in end
        
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out. bottom of receive 1 ping"  #fix this
     
def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    
    myChecksum = 0
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1) 
    data = struct.pack("d", time.time()) 
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
    
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff 
        #Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = socket.htons(myChecksum)
         
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1) 
    packet = header + data
    
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    #Both LISTS and TUPLES consist of a number of objects 
    #which can be referenced by their position number within the object
    
def doOnePing(destAddr, timeout): 
    icmp = socket.getprotobyname("icmp")#SOCK_RAW is a powerful socket type. For more details see: http://sock-raw.org/papers/sock_raw
    
    #Fill in start
    
    #Create Socket here
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    
    #Fill in end
    
    myID = os.getpid() & 0xFFFF #Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
       
       
    mySocket.close() 
    return delay

def ping(host, timeout=1):
    print "My Version"
    #timeout=1 means: If one second goes by without a reply from the server,
    #the client assumes that either the client's ping or the server's pong is lost
    dest = socket.gethostbyname(host)
    print "Pinging " + dest + " using Python:"
    print ""
    #Send ping requests to a server separated by approximately one second
    count = 10
#     while 1 :
    while count > 0:
        count -= 1;
        delay = doOnePing(dest, timeout)
        print delay
        time.sleep(1)# one second
    return delay

ping("www.google.com")
# ping("127.0.0.1")