from socket import *
from Crypto.Cipher import PKCS1_v1_5, AES
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

#MAIN
serverip="127.0.0.1"
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
c_sock.send("C"+public_key)

rcvd=c_sock.recv(1024)

print(rcvd)
c_sock.close()

#I ask C the public key of Server
print("Asking public key of Server to C...\n")
c_sock=socket(AF_INET, SOCK_STREAM)
c_sock.connect((Cip,Cport))       
c_sock.send("C,S")

rcvd=c_sock.recv(3000)
c_sock.close()

sign=rcvd[-256:]
S_pubkey=rcvd[1:-256]

#i verify the signature using C pub key
key=RSA.import_key(C_public_key)
hash_m=S_pubkey+"S"
h=SHA256.new(hash_m)
verifier=pss.new(key)
try:
    verifier.verify(h,sign)
    print("Authentic signature")
except(ValueError, TypeError):
    print("signature NOT Authentic")
    exit(1)

#starting connection with server
print("Sending nonce to S encrypted with S pub_key")
nonce=get_random_bytes(16)
key=RSA.import_key(S_pubkey)
rsa_cipherS = PKCS1_v1_5.new(key)
ciphertext=rsa_cipherS.encrypt(nonce+"C")

clientsock=socket(AF_INET, SOCK_STREAM)
clientsock.connect((serverip,serverport))

clientsock.send(ciphertext)

rcvd=clientsock.recv(1024)
if(rcvd=="ERROR"):
    print("Connection NOT verified")
    clientsock.close()
    exit(1)

key=RSA.import_key(private_key)
rsa_cipher = PKCS1_v1_5.new(key)
msg=rsa_cipher.decrypt(rcvd,"")

print("Verifying the nonce...\n")
if(nonce==msg[1:17] and msg[0]=='S'):
    print("Nonce Verified")
else:
    print("Invalid nonce")
    clientsock.close()
    exit(1)

ciphertext=rsa_cipherS.encrypt(msg[17:])
clientsock.send(ciphertext)

rcvd=clientsock.recv(1024)

if(rcvd=="ERROR"):
    print("Connection NOT verified")
    clientsock.close()
    exit(1)

print("Connection verified")

sym_key=rsa_cipher.decrypt(rcvd,"")

print("Received symmetric key... now i can start real communication ['exit' to leave] \n")

msg="HI, i'm the client C"
print("client: "+msg)
#aes_cipher = AES.new(sym_key, AES.MODE_ECB)
#h=HMAC.new(sym_key, digestmod=SHA256)
ciphertext,sym_key=mac_then_encrypt(msg,sym_key)
clientsock.send(ciphertext)

rcvd=clientsock.recv(1024)
plaintext,sym_key=mac_decrypt(rcvd,sym_key)
if(plaintext=="ERROR"):
    print("ERROR in MAC")
    clientsock.close()
    print("connection closed\n")
    exit(1)

print("server: "+plaintext)

msg=""
while(1):
    msg=raw_input('insert the message: ')
    print("client: "+msg)
    ciphertext,sym_key=mac_then_encrypt(msg,sym_key)
    clientsock.send(ciphertext)
    if(msg=="exit"):
        break
    rcvd=clientsock.recv(1024)
    plaintext,sym_key=mac_decrypt(rcvd,sym_key)
    if(plaintext=="ERROR"):
        print("ERROR in MAC")
        clientsock.close()
        print("connection closed\n")
        exit(1)

    print("server: "+plaintext)
    
clientsock.close()
print("connection closed\n")

