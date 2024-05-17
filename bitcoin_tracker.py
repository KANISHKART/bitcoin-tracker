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

# Below version payload values is exracted from  https://en.bitcoin.it/wiki/Protocol_documentation#version
# peer_ip_address is the bitcoin node 
def version_payload(peer_ip_address):
    
    version = 60002 # https://developer.bitcoin.org/reference/p2p_networking.html
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

# Below verack payload values is exracted from  https://en.bitcoin.it/wiki/Protocol_documentation#verack
# This is sent in reply to version from node
# this message consist only message header(Magic Number, "verack", payload=0,checksum)
# so the value is retun as is
def verack_message():
    return bytearray.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")
              

def getaddr_message():
    # The payload for getaddr is empty
    return b''

def safe_utf8_decode(byte_sequence):
    try:
        decoded_text = byte_sequence.decode('utf-8')
        return decoded_text
    except UnicodeDecodeError:
        # If decoding fails, return the original byte sequence
        return byte_sequence
    
# below is the starting point for the program
if __name__ == '__main__':
    
    # constant values 
    magic_value = 0xd9b4bef9
    peer_ip_address = '185.26.99.171' # derived from https://bitnodes.io/api/v1/nodes/leaderboard/?limit=100&page=1 
    buffer_size = 1024

    # Establish Socket TCP Connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip_address, PORT))
    
    print("\nInitiaiting protocol handshake...")
  
    #The 'payload' variable will hold the byte array of the body
    payload = version_payload(peer_ip_address)
    
    #The 'version_message' variable will have the complete header + payload
    version_message = payload_message(magic_value,'version', payload)
    
    # 1. Start the handshake with bitcoin node with "version"
    s.send(version_message)
    response_data = s.recv(buffer_size) #max amount of data to be recived with thissingle call. so there won't be any big message recieved
 
    print("Version recieved from Bitcoin network")
    
    # 2. Send verack after version
    s.send(verack_message())
    response_verack=s.recv(buffer_size)
    
    print("Verack recieved from Bitcoin network")
    
    # 3. 'get_addr' after verack
    getAddr_message= payload_message(magic_value,'pong', getaddr_message())
    s.send(getAddr_message)
    
    print("Handshake Successful")
    
    print("Listening to inventory messages in bitcoin network...\n")
    
    print("---------------------------------------------------------------------------------------------------------")
    while(True):
        response_addr=s.recv(3072) # increased to accomodate more message from bitcoin network
        magic_number, command, payload_length, checksum = struct.unpack('<L12sL4s', response_addr[:24])

        # filtering command type
        command_type= safe_utf8_decode(command)
       
        if('inv' in command_type):
            # Print the decoded header fields
            
           
            print("Packet Magic         :", hex(magic_number))
            print("Command name         :", command_type)
            print("Payload Length       :", payload_length)
            print("Payload Checksum     :", checksum.hex())
            
            # Print the inventory payloads
            inv_payload= response_addr[24:]
            
            print("Inventory Details:",response_addr[24:],"\n")
            
            # Extract the count
            count = struct.unpack('<B', inv_payload[:1])[0]  # '<B' is little-endian unsigned char
            print(f'Count: {count}')
            
            # Initialize list to hold inventory vectors
            inventory_vectors = []

            # Offset to start of inventory vectors
            offset = 1

            # Each inventory vector is 36 bytes
            vector_size = 36

            for i in range(count):
                # Extract type (4 bytes) and hash (32 bytes)
                vector_data = inv_payload[offset:offset + vector_size]
                vector_type = struct.unpack('<I', vector_data[:4])[0]  # '<I' is little-endian unsigned int
                vector_hash = vector_data[4:]
                
                # Append to list
                inventory_vectors.append((vector_type, vector_hash.hex()))
                
                # Update offset
                offset += vector_size

            # Print the inventory vectors
            for idx, (vector_type, vector_hash) in enumerate(inventory_vectors):
                print(f'Inventory Vector {idx + 1}:')
                print(f'  Type: {vector_type}')
                print(f'  Hash: {vector_hash}')
                
            print("---------------------------------------------------------------------------------------------------------")
    s.close()

 