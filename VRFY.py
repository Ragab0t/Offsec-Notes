#!/usr/bin/python 
import socket 
import sys 
# Create a Socket  
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
# Connect to the Server 
connect=s.connect((sys.argv[1],25))  
print "Checking host: " + sys.argv[1] 
# Receive the banner 
banner=s.recv(1024) 
print banner 
# VRFY a user
s.send('HELO thinc.local' '\r\n')  
result=s.recv(1024) 
s.send('VRFY ' + sys.argv[2] + '\r\n')  
result=s.recv(1024) 
print result 
# Close the socket 
s.close()
