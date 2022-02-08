from socket import *
from Crypto.Cipher import PKCS1_v1_5,AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pss
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def mac_then_encrypt(txt,sym_key):
    cipher = AES.new(sym_key, AES.MODE_ECB)
    h=HMAC.new(sym_key, digestmod=SHA256)
    h.update(txt)
    mac=h.hexdigest()
    rand=get_random_bytes(6)

    new_msg=txt+mac+rand
    c_msg=cipher.encrypt(pad(new_msg,32))
    new_key= sym_key[:-6]+rand
    
    return c_msg,new_key

def mac_decrypt(ctxt,sym_key):
    cipher = AES.new(sym_key, AES.MODE_ECB)
    h=HMAC.new(sym_key, digestmod=SHA256)
    msg=unpad(cipher.decrypt(ctxt), 32)

    txt=msg[:-70]
    mac=msg[-70:-6]
    rand=msg[-6:]
    h.update(txt)

    new_key= sym_key[:-6]+rand
    
    try:
        h.hexverify(mac)
        print("MAC authenticated")
        return txt,new_key
    except ValueError:
        print("MAC NOT authenticated")
        return "ERROR",new_key  

serverport=8000
Cip="127.0.0.1"
Cport=9000

#creating private-public key
print("key generation ...\n")
key = RSA.generate(2048)
private_key = key.export_key()

public_key = key.publickey().export_key()

file=open("public_C.pem","r")
C_public_key=file.read()
file.close()

#send my public key to C
print("Sending public key to C...\n")
c_sock=socket(AF_INET, SOCK_STREAM)
c_sock.connect((Cip,Cport))
c_sock.send("S"+public_key)

rcvd=c_sock.recv(1024)

print(rcvd)
c_sock.close()

#listening for incoming connections

serversock=socket(AF_INET, SOCK_STREAM)
serversock.bind(('',serverport))

serversock.listen(1)
print("The server is listening on port 8000")

while(1):
    connectionsock, addr = serversock.accept()
    print("Connected with: "+str(addr[0])+" on port: "+str(addr[1]))

    enc_msg=connectionsock.recv(1024)
    key=RSA.import_key(private_key)
    rsa_cipher = PKCS1_v1_5.new(key)
    msg=rsa_cipher.decrypt(enc_msg,"")
    client_id=msg[-1]
    c_nonce=msg[:-1]
    print("Received client nonce\n")

    #I ask C the public key of Client
    print("Asking public key of Client to C...\n")
    c_sock=socket(AF_INET, SOCK_STREAM)
    c_sock.connect((Cip,Cport))       
    c_sock.send("S,"+client_id)

    rcvd=c_sock.recv(3000)
    c_sock.close()

    sign=rcvd[-256:]
    C_pubkey=rcvd[1:-256]

    #i verify the signature using C pub key
    key=RSA.import_key(C_public_key)
    hash_m=C_pubkey+client_id
    h=SHA256.new(hash_m)
    verifier=pss.new(key)
    try:
        verifier.verify(h,sign)
        print("Authentic signature")
    except(ValueError, TypeError):
        connectionsock.send("ERROR")
        print("signature NOT Authentic")
        continue
        
    new_nonce=get_random_bytes(16)
    sentence='S'+c_nonce+new_nonce

    key=RSA.import_key(C_pubkey)
    rsa_cipherC = PKCS1_v1_5.new(key)
    ciphertext=rsa_cipherC.encrypt(sentence)

    print("Sending new nonce to C encrypted with C pub_key")
    connectionsock.send(ciphertext)

    enc_msg=connectionsock.recv(1024)
    msg=rsa_cipher.decrypt(enc_msg,"")
    print("Verifying the nonce...\n")
    if(new_nonce==msg):
        print("Nonce Verified")
    else:
        print("Invalid nonce")
        connectionsock.send("ERROR")
        continue

    print("Connection Verified")
    print("Creating symmetric key...\n")
    sym_key=get_random_bytes(32)
    ciphertext=rsa_cipherC.encrypt(sym_key)

    print("Sending symm key to C encrypted with C pub_key")
    connectionsock.send(ciphertext)
    
    rcvd=connectionsock.recv(1024)
    #aes_cipher=AES.new(sym_key, AES.MODE_ECB)
    #h=HMAC.new(sym_key, digestmod=SHA256)
    plaintext,sym_key =mac_decrypt(rcvd,sym_key)
    print("client: "+plaintext)

    msg="HI, i'm the server S"
    print("server: "+msg)
    ciphertext,sym_key=mac_then_encrypt(msg,sym_key)
    connectionsock.send(ciphertext)

    plaintext=""
    while(1):
        rcvd=connectionsock.recv(1024)
        plaintext,sym_key=mac_decrypt(rcvd,sym_key)
        print("client: "+plaintext)
        if(plaintext=="exit"):
            break

        msg=raw_input('insert the message: ')
        print("server: "+msg)
        ciphertext,sym_key=mac_then_encrypt(msg,sym_key)
        connectionsock.send(ciphertext)

    print("connection closed\n")
        
    
