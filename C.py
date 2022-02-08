from socket import *
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import threading

def do(connectionsock, addr):
    global client_pub
    global server_pub
    print("Connected with: "+str(addr[0])+" on port: "+str(addr[1]))
    
    s.acquire()

    msg=connectionsock.recv(1024)
    if(msg[0]=="C"):
        #msg from the Client
        if(msg=="C,S"):
            #send to client K pub of Server: S,Kpubs,Sign(Kpubs,S)
            print("Sending to client S,Kpub,Sign(Kpub,S)\n")
            hash_k=SHA256.new(server_pub+"S")
            key=RSA.import_key(private_key)
            sign=pss.new(key).sign(hash_k)
            sentence="S"+server_pub+sign
            connectionsock.send(sentence)
        else:
            #saving or updating K pub of Client
            client_pub=msg[1:]
            sentence="Public key received"
            connectionsock.send(sentence)
            print("Received C public key\n")
    elif(msg[0]=="S"):
        #msg from the Server
        if(server_pub==""):
            server_pub=msg[1:]
            sentence="Public key received"
            connectionsock.send(sentence)
            print("Received S public key\n")
        else:
            #msg=S,C
            #send to Server K pub of Client: C,Kpubc,Sign(Kpubc,C)
            print("Sending to Server C,Kpubc,Sign(Kpubc,C)\n")
            hash_k=SHA256.new(client_pub+"C")
            key=RSA.import_key(private_key)
            sign=pss.new(key).sign(hash_k)
            sentence="C"+client_pub+sign
            connectionsock.send(sentence)

    s.release()

#MAIN     
s=threading.Semaphore(1)

serverport=9000
client_pub=""
server_pub=""

#creating private-public key
print("key generation ...\n")
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()
file_pub = open("public_C.pem", "wb")
file_pub.write(public_key)
file_pub.close()

#receive client pub key
serversock=socket(AF_INET, SOCK_STREAM)

serversock.bind(('',serverport))

serversock.listen(1)
print("C is listening on port 9000\n")

while(1):
    connectionsock, addr = serversock.accept()
    threading.Thread(target=do, args=(connectionsock,addr)).start()


        
