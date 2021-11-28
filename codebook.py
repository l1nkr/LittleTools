import base64
import hashlib
import json
import sys
import getopt
import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad



def encrypt(dir, key):
    file = open(dir, "r")

    passwd = json.load(file, strict=False)

    cipher = AES.new(key=key, mode=AES.MODE_CBC)
    passwd['iv'] = base64.b64encode(cipher.iv).decode('utf-8')

    for key, value in passwd.items():
        if key == 'iv':
            continue
        else:
            # encrypt
            value = value.strip("\n").encode('utf-8')
            ct_bytes = cipher.encrypt(pad(value, AES.block_size))
            passwd[key] = base64.b64encode(ct_bytes).decode('utf-8')

    file.close()
    file = open(dir, "w")
    json.dump(passwd, file, indent=4, sort_keys=True)
    file.close() 
    
def decrypt(dir, key):
    file = open(dir, "r")
    passwd = json.load(file, strict=False)
    iv = base64.b64decode(passwd['iv'])
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)

    for key, _ in passwd.items():
        if key == 'iv':
            continue
        else:
            plaintext = unpad(cipher.decrypt(base64.b64decode(passwd[key])), AES.block_size)
            # print(plaintext)
            passwd[key] = plaintext.decode('utf-8')
    file.close()
    file = open(dir, "w")
    json.dump(passwd, file, indent=4, sort_keys=True)
    file.close()

if __name__ == "__main__":
    
    argv = sys.argv[1:]
    dir = ''
    mode = ''

    try:
        opts, args = getopt.getopt(argv,"hc:d:k:")
    except getopt.GetoptError:
        print('usage: codebook.py -c <encrypt|decrypt> -d <dir of codebook>')
        sys.exit()

    for opt, arg in opts:
        if opt == '-h':
            print('usage: codebook.py -c <encrypt|decrypt> -d <dir of codebook>')
            sys.exit()
        elif opt == '-c':
            mode = arg
        elif opt == '-d':
            dir = arg

    if dir == '' or mode == '':
        print('usage: codebook.py -c <encrypt|decrypt> -d <dir of codebook>')
        sys.exit()
    
    key = getpass.getpass("Please input key:  ")
    key = hashlib.sha256(key.encode()).digest()
    # encrypt or decrypt

    if mode == 'encrypt':
        encrypt(dir, key)
    elif mode == 'decrypt':
        decrypt(dir, key)
    else:
        print("Input error")
        sys.exit()
