# Author Kanishkar Thirunavukkarasu
# Assignment 3  - Secure Systems - Bitcoin Tracker
# Student No: D23124630

import binascii
import socket
import time
import random
import struct
import hashlib

# Mostly in bitcoin node the port will be 8333
PORT= 8333

# Below version payload is exracted from  https://en.bitcoin.it/wiki/Protocol_documentation#version
# peer_ip_address is the bitcoin node 
def version_payload(peer_ip_address):
    
    version = 60002
    services = 1
    timestamp = int(time.time()) #Unix timestamp
    
    addr_local = struct.pack('>8s16sH', b'\x01', 
        bytearray.fromhex("00000000000000000000ffff") + socket.inet_aton(peer_ip_address), PORT)
    addr_peer = struct.pack('>8s16sH', b'\x01', 
        bytearray.fromhex("00000000000000000000ffff") + socket.inet_aton("127.0.0.1"), PORT)
    nonce = random.getrandbits(64)
    start_height = 843638
    
    # The below <LQQ26s26sQ16sL indicates the format of binary data. '<' indicates the little-endian byte order.
    # '26s' represents a string of 26 bytes similarly for all the numbers followed by symbol represents the type with that many bytes
    # documentation reference : https://docs.python.org/3/library/struct.html
    # The below sub_version is derived from version message sample in the link : https://en.bitcoin.it/wiki/Protocol_documentation#version
    
    payload = struct.pack('<LQQ26s26sQ16sL', version, services, timestamp,
                          addr_local,addr_peer, nonce, b'\x0F' + "/Satoshi:0.7.2/".encode(), start_height)
    return(payload)

# This function is responsible to add necessary header with magic Number, type of the message(version/getData), payload length, payload checksum
# At the end, payload is appended with the header
def payload_message(magicNumber, command, payload):
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    return(struct.pack('L12sL4s', magicNumber, command.encode(), len(payload), checksum) + payload)



# below is the starting point for the program
if __name__ == '__main__':
    
    # constant values 
    magic_value = 0xd9b4bef9
    peer_ip_address = '198.154.93.110' # derived from https://bitnodes.io/api/v1/nodes/leaderboard/?limit=100&page=1 
    buffer_size = 1024

    # Establish Socket TCP Connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip_address, PORT))
  
    #The 'payload' variable will hold the byte array of the body
    payload = version_payload(peer_ip_address)
    
    #The 'version_message' variable will have the complete header + payload
    version_message = payload_message(magic_value, 'version', payload)
    
    # 1. Start the handshake with bitcoin node with "version"
    s.send(version_message)
    response_data = s.recv(buffer_size)
    

    print("Request:")
    print((binascii.hexlify(version_message)))
    print("Response:")
    print(binascii.hexlify(response_data))
   
    # Close the TCP connection
    s.close()

 