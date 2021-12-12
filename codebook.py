import os
import struct
import getopt
import sys
from Crypto.Cipher import AES

try:
    from Crypto.Util.Padding import pad, unpad
    
except ImportError:
    from Crypto.Util.py3compat import bchr, bord
    
    def pad(data_to_pad, block_size):
        padding_len = block_size-len(data_to_pad)%block_size
        padding = bchr(padding_len)*padding_len
        return data_to_pad + padding
    
    def unpad(padded_data, block_size):
        pdata_len = len(padded_data)
        if pdata_len % block_size:
            raise ValueError("Input data is not padded")
        padding_len = bord(padded_data[-1])
        if padding_len<1 or padding_len>min(block_size, pdata_len):
            raise ValueError("Padding is incorrect.")
        if padded_data[-padding_len:]!=bchr(padding_len)*padding_len:
            raise ValueError("PKCS#7 padding is incorrect.")
        return padded_data[:-padding_len]
    
    
def encrypt_file(key, in_filename, out_filename, chunksize=64*1024):

    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)
    
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)
            pos = 0
            while pos < filesize:
                chunk = infile.read(chunksize)
                pos += len(chunk)
                if pos == filesize:
                    chunk = pad(chunk, AES.block_size)
                outfile.write(encryptor.encrypt(chunk))
                
    os.remove(in_filename)
                
                
def decrypt_file(key, in_filename, out_filename, chunksize=64*1024):

    with open(in_filename, 'rb') as infile:
        iv = infile.read(16)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        
        with open(out_filename, 'wb') as outfile:
            encrypted_filesize = os.path.getsize(in_filename)
            pos = 8 + 16 # the filesize and IV.
            while pos < encrypted_filesize:
                chunk = infile.read(chunksize)
                pos += len(chunk)
                chunk = encryptor.decrypt(chunk)
                if pos == encrypted_filesize:
                    chunk = unpad(chunk, AES.block_size)
                outfile.write(chunk) 
                
    os.remove(in_filename)


if __name__=='__main__':
    
    argv = sys.argv[1:]
    mode = ''

    try:
        opts, args = getopt.getopt(argv, "hc:")
    except getopt.GetoptError:
        print('usage: codebook.py -c <en|de>')
        sys.exit()

    for opt, arg in opts:
        if opt == '-h':
            print('usage: codebook.py -c <en|de>')
            sys.exit()
        elif opt == '-c':
            mode = arg

    if mode == '':
        print('usage: codebook.py -c <en|de>')
        sys.exit()

    key = input("Please input key:  ")

    # encrypt or decrypt

    if mode == 'en':
        encrypt_file(key.encode('utf-8'),"./plain", "./cipher")
    elif mode == 'de':
        decrypt_file(key.encode('utf-8'), "./cipher", "./plain")
    else:
        print("Input error")
        sys.exit()
    