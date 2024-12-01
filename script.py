from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Function to encrypt the message
def encrypt_aes(message: str, key: bytes) -> str:
# Create a new AES cipher object
cipher = AES.new(key, AES.MODE_CBC)

# Pad the message to be a multiple of 16 bytes
ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))

# Combine IV and ciphertext for transmission/storage
 
iv = cipher.iv
encrypted_message = base64.b64encode(iv + ct_bytes).decode('utf-8')

return encrypted_message

# Function to decrypt the message
def decrypt_aes(encrypted_message: str, key: bytes) -> str:
# Decode the base64 message
encrypted_message = base64.b64decode(encrypted_message)

# Extract IV and ciphertext
iv = encrypted_message[:16]
ct = encrypted_message[16:]

# Create a new AES cipher object with the same key and IV
cipher = AES.new(key, AES.MODE_CBC, iv)

# Decrypt and unpad the message
decrypted_message = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

return decrypted_message

# Example usage
 
if   name	== "  main  ":
# A random 16-byte key for AES-128
key = get_random_bytes(16)

original_message = "This is a secret message."
print("Original Message:", original_message)

encrypted_message = encrypt_aes(original_message, key)
print("Encrypted Message:", encrypted_message)

decrypted_message = decrypt_aes(encrypted_message, key)
print("Decrypted Message:", decrypted_message)
