# Author Kanishkar Thirunavukkarasu
# Assignment 3  - Secure Systems - Bitcoin Tracker
# Student No: D23124630

import binascii
import datetime
import socket
import time
import random
import struct
import hashlib


import logging
 
# Configure logging to save to a file
logging.basicConfig(filename='output.log', level=logging.INFO)

# Mostly in bitcoin node the port will be 8333
PORT= 8333

# constant values 
MAGIC_NUMBER = 0xd9b4bef9


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
    
    start_height = 844006 # BITCOIN block id 
    
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
              
# This is used to parse the command type in header messages
def safe_utf8_decode(byte_sequence):
    try:
        decoded_text = byte_sequence.decode('utf-8')
        return decoded_text
    except UnicodeDecodeError:
        # If decoding fails, return the original byte sequence
        return byte_sequence

# Function to convert Unix timestamp to human-readable datetime
def unix_timestamp_to_datetime(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime('%d %B %Y at %H:%M')

# Function to parse the block data and extract information
def parse_block_data(block_data):
    version = struct.unpack('<I', block_data[:4])[0]
    prev_block_hash = block_data[4:36].hex()
    merkle_root = block_data[36:68].hex()
    print("original payload::",block_data[36:68])
    timestamp = unix_timestamp_to_datetime(struct.unpack('<I', block_data[68:72])[0])
    bits = struct.unpack('<I', block_data[72:76])[0]
    nonce = struct.unpack('<I', block_data[76:80])[0]
    txn_count = struct.unpack('<B', block_data[80:81])[0]
    # transactions = []
    txn_start = 81
    # for _ in range(txn_count):
    #     txn_value = struct.unpack('<Q', block_data[txn_start + 8:txn_start + 16])[0] / 10**8
    #     transactions.append(txn_value)
    #     txn_start += 64
    return version, prev_block_hash, merkle_root, timestamp, bits, nonce, txn_count

def padded_block_hash(original_hash):
    reversed_bytes = bytes.fromhex(original_hash)[::-1] # Reverse byte order
    padded_hex = reversed_bytes.hex().rjust(64, "0")    # Convert to hexadecimal with leading zeros
    return padded_hex
    
# Function to create message payload
def create_message_payload(command, payload=b''):
    magic = struct.pack('<L', MAGIC_NUMBER)
    command = command.ljust(12, b'\x00')
    length = struct.pack('<L', len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return magic + command + length + checksum + payload

# Function to calculate the hash of the block data
def calculate_block_hash(block_data):
    block_hash = hashlib.sha256(hashlib.sha256(block_data).digest()).digest()
    return block_hash[::-1].hex()

# Read "tx" and "block messages"
def read_tx_block_messages(sock, expected_tx_count, hash):
    buffer = b""
    received_tx_count = 0

    while received_tx_count < expected_tx_count:
        data = sock.recv(100024)
        buffer += data

        while len(buffer) >= 24:  # Minimum size of a message header
            # Extract the header
            g_magic_number, g_command, g_payload_length, g_checksum = struct.unpack('<L12sL4s', buffer[:24])
            command_name = safe_utf8_decode(g_command)
            total_message_length = 24 + g_payload_length

            if "tx" in str(command_name):
                print("\nPacket Magic     :", hex(g_magic_number))
                print("Command name       :", command_name)
                print("Payload Length     :", g_payload_length)
                print("Payload Checksum   :", g_checksum.hex())
                
            elif "block" in str(command_name):
                print("##################### block details ##########################")
                logging.info("##################### block details ##########################")
                 # Parse the message header
                magic_number, command, payload_length, checksum = struct.unpack('<L12sL4s', buffer[:24])

                # Parse the message header
                magic_number, command, payload_length, checksum = struct.unpack('<L12sL4s', buffer[:24])

                print("Packet Magic         :", hex(magic_number))
                print("Command name         :", command)
                print("Payload Length       :", payload_length)
                print("Payload Checksum     :", checksum.hex())
                        
                logging.info("Packet Magic         :%s", hex(magic_number))
                logging.info("Command name         : block",)
                logging.info("Payload Length       :%s", payload_length)
                logging.info("Payload Checksum     :%s", checksum.hex())
                
                # Parse block data
                version, prev_block_hash, merkle_root, timestamp, bits, nonce, txn_count = parse_block_data(buffer[24:])
                
                logging.info("Block Version         :%s", hex(version))
                logging.info("Block Previous Hash   :%s", bytes.fromhex(prev_block_hash)[::-1].hex())
                logging.info("Merkle Root       :%s", bytes.fromhex(merkle_root)[::-1].hex())
                logging.info("Block timestamp     :%s", timestamp)
                logging.info("Nonce     :%s", bits)
                logging.info("Nonce     :%s", nonce)
                
                ############ Main Print statements #################
                
                # Block created date (e.g. 1st April 2024 at 20:40)
                # The nonce that was used to successfully hash the block, and the difficulty level
                
                
                print("Block Version         :", hex(version))
                print("Block Previous Hash   :", bytes.fromhex(prev_block_hash)[::-1].hex())
                print("Merkle Root       :", bytes.fromhex(merkle_root)[::-1].hex())
                print("Block timestamp    :", timestamp)
                print("Bits     :", bits)
                print("Nonce     :", nonce)
                
                # hash verification
                
                #converting the hash to block hash
                hash= padded_block_hash(str(hash))
                
                logging.info("Block Hash      :%s", hash)
                
                print("Block Hash : ",hash)
                
                logging.info("##################### ##########################\n")
                # if calculated_hash == hash:
                #     print("Hashes Match! Block is Valid.")
                # else:
                #     print("Hashes Do Not Match! Block is Invalid.")
                
            received_tx_count += 1
            
            # Remove the processed message from the buffer
            buffer = buffer[total_message_length:]

    
# below is the starting point for the program
if __name__ == '__main__':
    
    
    peer_ip_address = '185.26.99.171' # derived from https://bitnodes.io/api/v1/nodes/leaderboard/?limit=100&page=1 
    buffer_size = 1024
    
    block_height=input("Enter block hash : ")

    # Establish Socket TCP Connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip_address, PORT))
    
    print("\nInitiaiting protocol handshake...")
    logging.info("\nInitiaiting protocol handshake...")
  
    #The 'payload' variable will hold the byte array of the body
    payload = version_payload(peer_ip_address)
    
    #The 'version_message' variable will have the complete header + payload
    version_message = payload_message(MAGIC_NUMBER,'version', payload)
    
    # 1. Start the handshake with bitcoin node with "version"
    s.send(version_message)
    response_data = s.recv(buffer_size) #max amount of data to be recived with thissingle call. so there won't be any big message recieved
 
    print("Version recieved from Bitcoin network")
    logging.info("Version recieved from Bitcoin network")
    
    # 2. Send verack after version
    s.send(verack_message())
    response_verack=s.recv(buffer_size)
    
    print("Verack recieved from Bitcoin network")
    logging.info("Verack recieved from Bitcoin network")
    
    # # 3. 'get_addr' after verack
    
    getdata_payload = create_message_payload(b'getdata', struct.pack('<I', 1) + b'\x02' + bytes.fromhex(block_height)[::-1])
    s.sendall(getdata_payload)
        
        
    # getAddr_message= payload_message(magic_value,'getdata', b'')
    # s.send(getAddr_message)
    print("Handshake Successful")
    logging.info("Handshake Successful")
    
    print("Listening to inventory vectors to get transaction & block details in bitcoin network...\n")
    logging.info("Listening to inventory vectors to get transaction & block details in bitcoin network...\n")
       
    print("---------------------------------------------------------------------------------------------------------")
    logging.info("---------------------------------------------------------------------------------------------------------\n")
    logging.info("Waiting for blocks to arrive.....")
 
    while(True):
        response_addr=s.recv(3072) # increased to accomodate more message from bitcoin network
        if(len(response_addr)>24):
            MAGIC_NUMBER, command, payload_length, checksum = struct.unpack('<L12sL4s', response_addr[:24])

            # filtering command type
            command_type= safe_utf8_decode(command)
            
            if('inv' in str(command_type) or 'block' in str(command)):
                # Print the decoded header fields
            
                print("Packet Magic         :", hex(MAGIC_NUMBER))
                print("Command name         :", command_type)
                print("Payload Length       :", payload_length)
                print("Payload Checksum     :", checksum.hex())
                
                # logging.info("Packet Magic         :%s", hex(magic_number))
                # logging.info("Command name         : inv",)
                # logging.info("Payload Length       :%s", payload_length)
                # logging.info("Payload Checksum     :%s", checksum.hex())
                
                
                # Print the inventory payloads
                inv_payload= response_addr[24:]
                
                # print("Inventory Details:",response_addr[24:],"\n")
                
                print("Inventory Details: \n")
               
                
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
                    if(vector_type==2 or vector_type=='2'):
                        logging.info("Inventory Details: \n")
                        logging.info(f'Count: {count}')
                        logging.info(f'Inventory Vector {idx + 1}:')
                        logging.info(f'  Type: {vector_type}')
                        logging.info(f'  Hash: {vector_hash}')
                    # to get transaction details for the inv vectors
                s.send(payload_message(MAGIC_NUMBER, 'getdata', inv_payload))
                read_tx_block_messages(s, count, vector_hash)
               # logging.info("---------------------------------------------------------------------------------------------------------")
                print("---------------------------------------------------------------------------------------------------------")
        else:
            print("######################## Skipped ##########################")
            logging.info("######################## Skipped ##########################")
            print(response_addr)
            logging.info(response_addr)
    s.close()


 