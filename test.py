import struct
import hashlib

# Byte string representing the received message
received_message = b'62ea00000100000000000000d202466600000000010000000000000000000000000000000000ffffc69a5d6e208d010000000000000000000000000000000000ffff7f000001208d343c493a1ba5ef860f2f5361746f7368693a302e372e322f76df0c00'

# Extracting components of the message
magic_number = received_message[:4]
print(magic_number)
command = received_message[4:16].decode('ascii').strip('\x00')  # Strip null bytes
payload_length = struct.unpack('<I', received_message[16:20])[0]
checksum = received_message[20:24]
payload = received_message[24:]

# Calculate the checksum of the payload
calculated_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

# Verify checksum
if checksum == calculated_checksum:
    print("Checksum is valid.")
else:
    print("Checksum is not valid.")

# Parse inventory vectors
num_vectors = len(payload) // 36
inventory_vectors = []
for i in range(num_vectors):
    start_idx = i * 36
    end_idx = start_idx + 36
    vector_type = struct.unpack('<I', payload[start_idx:start_idx + 4])[0]
    hash_value = payload[start_idx + 4:end_idx]
    inventory_vectors.append((vector_type, hash_value))

# Print inventory vectors
print("Inventory Vectors:")
for vector_type, hash_value in inventory_vectors:
    print("Type:", vector_type)
    print("Hash:", hash_value.hex())
    print()