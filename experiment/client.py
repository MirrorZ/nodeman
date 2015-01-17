#!/usr/bin/env python
import datetime
import socket
import select    

startTime = datetime.datetime.now()

NUMBER = 16
TCP_IP = '192.168.42.5'
TCP_PORT = 80
BUFFER_SIZE = 1024
MESSAGE = "Hello, World!"
START_PORT = 46000

sl = []   
fx = []

for i in range(0,NUMBER):
        x = open("file" + str(i), 'w')  
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #print "s is : " + str(s)
        s.bind(('', START_PORT + i))
        s.connect((TCP_IP, TCP_PORT))
        sl.append(s)
        fx.append(x)
        req = 'GET /1M HTTP/1.1\r\nHost: 192.168.42.5\r\nConnection: close\r\nUser-Agent: SCAR/1.0.0\r\nAccept-Encoding: application/octet-stream\r\nAccept-Charset: ISO-8859-1,UTF-8;q=0.7,*;q=0.7\r\nCache-Control: no-cache\r\n\r\n'
        s.send(req)

#print "SL IS : " + str(sl)

#for xx in sl:
        #print "Index is " + str(sl.index(xx)) + "for " + str(xx)

input = []
for x in sl:
        input.append(x)  

#for xx in input:
 #       print "INPUT Index is " + str(input.index(xx)) + "for " + str(xx)


running = 1 
in_header = [False]*NUMBER

while running: 
        inputready,outputready,exceptready = select.select(input,[],[]) 

        for fi in inputready: 
                data = fi.recv(BUFFER_SIZE) 
                
                if data:
                        #print str(sl)
                        #print str(sl.index(fi)) + ' ---->>> INPUT : ' + str(inputready.index(fi)) + str(fi)
                        #print 'Actual data\n' + data
                        stra = data
                        index = data.find("\r\n\r\n")
                        if in_header[sl.index(fi)] == False and index >=0:
                                print 'for ' + str(sl.index(fi)) 
                                in_header[sl.index(fi)] = True
                                stra = data[index+4:]
                
                        fx[sl.index(fi)].write(stra)
                else: 
                        fi.close()
                        print 'removing ' + str(sl.index(fi)) 
                        input.remove(fi)
                
        if input == []:
                running = 0

print "Closing files and sockets now"

print datetime.datetime.now() - startTime

for f in fx:
        f.close()
