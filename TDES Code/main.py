from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

while True:
    try:
        key = DES3.adjust_key_parity(get_random_bytes(24))
        break
    except ValueError:
        pass

def encrypt(data):
    cipher = DES3.new(key, DES3.MODE_EAX)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(data.encode('ascii'))
    return nonce, ciphertext

def decrypt(nonce, ciphertext):
    cipher = DES3.new(key, DES3.MODE_EAX, nonce = nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('ascii')

def main():
    nonce, ciphertext = encrypt(input("please input text to be modified\n> "))
    plaintext = decrypt(nonce, ciphertext)  
    print(f"Cipher Text: {ciphertext}")
    print(f"Plain Text: {plaintext}")

main()