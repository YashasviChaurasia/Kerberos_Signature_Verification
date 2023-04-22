import socket
from rsa import *
from datetime import datetime
import json
import ast
import random
from aes import *

def gen_ticket(sess_key,self_id,network_address,rid,ts,dur):
    ticket={"session_key":sess_key,"self_id":self_id,"address":network_address,"id":rid,"timestamp":ts,"duration":dur}
    ticket=json.dumps(ticket)
    enc_tkt=(str(encrypt(ticket,public_key_B)).encode())#tkt encrypted with public key of tgs for only tgs
    return enc_tkt.decode()#tkt is in byte string

AS_public_key = (1313,289)#(209897, 163151)


# generating keys and commenting that part
# later if needed we can use it
# key = gen_keys(generate_primes(10),generate_primes(10))
# print(key)
# # ((1003643, 872779), (1003643, 117979))
# public_key = key[0]
# private_key = key[1]


public_key_B = (1111,573)#(1003643, 872779)
# private_key = (1111,637)#(1003643, 117979)

public_key=(6283,4663)
private_key=(6283,4087)

server = socket.socket()

server.bind((socket.gethostname(),2001))

server.listen(1)

sock, conn_from = server.accept()

data_recv = ast.literal_eval(sock.recv(10240).decode())
data_recv = json.loads(data_recv)


recv_tkt=data_recv["ticket"]
recv_auth=data_recv["authenticator"]
recv = ast.literal_eval(decrypt(ast.literal_eval(recv_tkt),private_key))

ts=str(datetime.now())
dur=5
sess_key="secretkey123458V"
ret_tkt=gen_ticket(sess_key,recv["self_id"],"net",data_recv['id'],ts,dur)

session_key_C=recv["session_key"]
authn=ast.literal_eval(aes_dec(session_key_C,data_recv["authenticator"][2:-1]))
# print(authn)
if(authn["self_id"]==recv["self_id"]):
    resp={"session_key":sess_key,"id":data_recv['id'],"timestamp":str(datetime.now()),"ticket":ret_tkt}#resp ticket
    resp=json.dumps(resp)
    sock.send(str(aes_enc(session_key_C,resp)).encode())
    print("Ticket Sent!")

sock.close()