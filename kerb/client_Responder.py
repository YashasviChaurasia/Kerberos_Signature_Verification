import socket
from rsa import *
from datetime import datetime
import json
import ast
import random
from aes import *
# def send_msgs(sock):
    
#     data_recv = sock.recv(1024).decode()
#     data_recv = decrypt(ast.literal_eval(data_recv),private_key)
#     data_recv = json.loads(data_recv)
#     print(data_recv['Message'])

#     data_recv['N1']+=1
#     data_recv['time'] = str(datetime.now())
#     data_recv['id'] = 'B'
#     sock.send(str(encrypt(json.dumps(data_recv),public_key_A)).encode())

#     data_recv = sock.recv(1024).decode()
#     data_recv = decrypt(ast.literal_eval(data_recv),private_key)
#     data_recv = json.loads(data_recv)
#     print(data_recv['Message'])

#     data_recv['N1']+=1
#     data_recv['time'] = str(datetime.now())
#     data_recv['id'] = 'B'
#     sock.send(str(encrypt(json.dumps(data_recv),public_key_A)).encode())

#     data_recv = sock.recv(1024).decode()
#     data_recv = decrypt(ast.literal_eval(data_recv),private_key)
#     data_recv = json.loads(data_recv)
#     print(data_recv['Message'])

#     data_recv['N1']+=1
#     data_recv['time'] = str(datetime.now())
#     data_recv['id'] = 'B'
#     sock.send(str(encrypt(json.dumps(data_recv),public_key_A)).encode())


# Responder
# pkda_public_key = (1313,289)#(209897, 163151)


# generating keys and commenting that part
# later if needed we can use it
# key = gen_keys(generate_primes(10),generate_primes(10))
# print(key)
# # ((1003643, 872779), (1003643, 117979))
# public_key = key[0]
# private_key = key[1]
public_key = (1111,573)#(1003643, 872779)
private_key = (1111,637)#(1003643, 117979)

server = socket.socket()
# creating a socket
server.bind((socket.gethostname(),2002))
# this is basically our master socket 
# binding that server to the host ip address and port 2000
server.listen(1)
# setting our responder such that it can listen to 1just 1 client
# initiator
sock, conn_from = server.accept()
data_recv = ast.literal_eval(sock.recv(1024).decode())
data_recv = json.loads(data_recv)
# print("Data received "+str(data_recv))
recv_tkt=data_recv["ticket"]
recv_auth=data_recv["authenticator"]
session_key_cv="secretkey123458V"
recv = ast.literal_eval(decrypt(ast.literal_eval(recv_tkt),private_key))
print(recv)
recv_auth=ast.literal_eval(aes_dec(session_key_cv,ast.literal_eval(recv_auth)))
print(recv_auth)
if(recv_auth["self_id"]==recv["self_id"]):
    # print("yeah")
    ret_resp={"timestamp":recv_auth["timestamp"]}#I have returned the same timestamp as auth for now
    sock.send(str(aes_enc(session_key_cv,json.dumps(ret_resp))).encode())
    print("Final Auth Msg Sent!")


# client = socket.socket() 
# # creating an instance of the socket 
# client.connect((socket.gethostname(), 2000))  

# # since we are running the clients and the pkda on the same system
# # therefore we can use get gethostname for the ip address to
# # connect to the server
# request_pkda = {'time':str(datetime.now()),'id':'A',"Duration":5,'nonce':random.randint(0,1000),'self_id':'B'}
# # here id denotes the id of the entity whose key we want
# request_pkda = json.dumps(request_pkda)
# client.send(request_pkda.encode())
# data_recv_from_pkda = client.recv(1024).decode()
# data_recv_from_pkda = decrypt(ast.literal_eval(data_recv_from_pkda),pkda_public_key)
# # print("Data received "+str(data_recv_from_pkda))
# data_recv_from_pkda = json.loads(data_recv_from_pkda)
# if data_recv_from_pkda['nonce']==json.loads(request_pkda)['nonce']+1:

#     data_recv_from_pkda['publicKey'] = eval(data_recv_from_pkda['publicKey'])
#     public_key_A = data_recv_from_pkda['publicKey']
#     print("Data received from pkda "+str(data_recv_from_pkda))
#     client.close()

#     nonce = json.loads(data_recv)['nonce']
#     request = {'id':'B','N1':nonce+1,'N2':random.randint(0,1000),"Duration":5,'time':str(datetime.now())}

#     request_to_send = encrypt(json.dumps(request),public_key_A)
#     sock.send(str(request_to_send).encode())
#     # request = json.loads(request)
#     data_recv = decrypt(ast.literal_eval(sock.recv(1024).decode()),private_key)
#     data_recv = json.loads(data_recv)
#     # print(data_recv)
#     # print(type(data_recv))
#     # print(request)
#     # print(type(request))
#     if data_recv['N2']!= request['N2']+1:
#         print("Incorrect Nonce")
#     else:
#         print("Nonce received")
#         send_msgs(sock)

sock.close()