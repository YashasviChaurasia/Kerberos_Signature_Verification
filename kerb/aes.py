from Crypto.Cipher import AES
import base64

# Key and IV should be generated with a secure random generator
def aes_enc(session_key,plaintext):
    key = session_key.encode()#b'secretkey1234567' # 16, 24, or 32 bytes long
    iv = b'1234567890123456' # 16 bytes long

    # The message you want to encrypt
    message = plaintext.encode()
    # Pad the message to be a multiple of 16 bytes
    pad = b' ' * (16 - len(message) % 16)
    message += pad

    # Create the AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt the message
    encrypted_message = cipher.encrypt(message)

    # Encode the encrypted message in base64 for transmission/storage
    encoded_message = base64.b64encode(encrypted_message)
    return encoded_message

def aes_dec(session_key,encoded_message):

    key = session_key.encode()#b'secretkey1234567' # 16, 24, or 32 bytes long
    iv = b'1234567890123456' # 16 bytes long
    # Decode the base64-encoded message
    decoded_message = base64.b64decode(encoded_message)
    
    # Create a new AES cipher object for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the message
    decrypted_message = cipher.decrypt(decoded_message)

    # Remove the padding from the decrypted message
    decrypted_message = decrypted_message.rstrip()

    return decrypted_message.decode()

# print(aes_dec("secretkey1234567",aes_enc("secretkey1234567","dfghjk")))
# print(b'hi')
# print(base64.b64encode('hi'))