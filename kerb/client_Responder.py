import socket
from rsa import *
from datetime import datetime
import json
import ast
import random
from aes import *

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

server.bind((socket.gethostname(),2002))

server.listen(1)

sock, conn_from = server.accept()
data_recv = ast.literal_eval(sock.recv(1024).decode())
data_recv = json.loads(data_recv)

recv_tkt=data_recv["ticket"]
recv_auth=data_recv["authenticator"]

recv = ast.literal_eval(decrypt(ast.literal_eval(recv_tkt),private_key))
session_key_cv=recv["session_key"]
print(recv)
recv_auth=ast.literal_eval(aes_dec(session_key_cv,ast.literal_eval(recv_auth)))
print(recv_auth)
if(recv_auth["self_id"]==recv["self_id"]):

    ret_resp={"timestamp":recv_auth["timestamp"]}#I have returned the same timestamp as auth for now
    sock.send(str(aes_enc(session_key_cv,json.dumps(ret_resp))).encode())
    print("Final Auth Msg Sent!")


sock.close()