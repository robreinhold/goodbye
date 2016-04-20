#!/usr/bin/python

from Crypto import Random
from Crypto.Cipher import AES

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".enc", 'wb') as fo:
        fo.write(enc)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    return decrypt(ciphertext, key)

def tokenize_and_index(payload, token_list, payload_list):
    for line in payload.splitlines():
        for word in line.split():
            word = word.replace("(", "").replace(")","")
            if(word not in token_list):
                token_list.append(word)
    token_list.sort()
    token_list.reverse()
    token_list.insert(0,"")

    for line in payload.splitlines():
        word_list = []
        for word in line.split():
            word = word.replace("(", "").replace(")","")
            word_list.append(token_list.index(word))
        payload_list.append(word_list)


def print_tokenized_payload(token_list, payload_list):
    for line in payload_list:
        output = ""
        for word in line:
            output = output + " " + token_list[word]
        print output

def print_golang_datastructs(token_list, payload_list):
    print "\tvar token_list [{}]string".format(len(token_list))
    for idx, token in enumerate(token_list):
        print "\ttoken_list[{}] = \"{}\"".format(idx, token)
    print "\n\tvar payload_list [{}][{}]int".format(len(payload_list),10)
    for line_idx, line_elements in enumerate(payload_list):
        for element_idx, element in enumerate(line_elements):
            print "\tpayload_list[{}][{}] = {}".format(line_idx, element_idx, element)

key = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'
payload = decrypt_file("./payload.enc", key)
token_list = []
payload_list = []

tokenize_and_index(payload, token_list, payload_list)
print_golang_datastructs(token_list, payload_list)
print_tokenized_payload(token_list, payload_list)