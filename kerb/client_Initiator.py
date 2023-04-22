import socket
from rsa import *
from datetime import datetime
import json
import ast
import random
from aes import *

def get_auth(self_id,network_address,ts,session_key):
    auth={"self_id":self_id,"address":network_address,"timestamp":ts}
    auth=json.dumps(auth)
    enc_auth=(str(aes_enc(session_key,auth)).encode())#tkt encrypted with public key of tgs for only tgs
    return enc_auth.decode()#tkt is in byte string

as_public_key = (1313,289)#(209897, 163151)

# generating keys and commenting that part
# later if needed we can use it
# key = gen_keys(generate_primes(10),generate_primes(10))
# print(key)
# ((625967, 105343), (625967, 472447))
# public_key = key[0]
# private_key = key[1].

public_key = (6077,3437)#(625967, 105343)
private_key = (6077,4613)#(625967, 472447)


request = {'self_id':'A','id':'TGS','time':str(datetime.now()),"Duration":5}
request = json.dumps(request)

client = socket.socket() 
client.connect((socket.gethostname(), 2000)) #port 2000 for AS 
client.send(request.encode())
data_recv = client.recv(10240).decode()
data_recv = decrypt(ast.literal_eval(data_recv),private_key)
data_recv = json.loads(data_recv)
session_key_TGS=data_recv["session_key"]
client.close()

client = socket.socket() 
client.connect((socket.gethostname(), 2001))  
ts=str(datetime.now())
request = {'id':'B','ticket':data_recv["TGS_ticket"],"authenticator":get_auth("A","network_address",ts,session_key_TGS)}
request_to_send = json.dumps(request)
client.send(str(json.dumps(request_to_send)).encode())
data_recv = client.recv(10240).decode()
data_recv = ast.literal_eval(aes_dec(session_key_TGS,ast.literal_eval(data_recv)))
client.close()

session_key_V=data_recv["session_key"]

vrequest={"ticket":data_recv["ticket"],"authenticator":get_auth("A","network_address",ts,session_key_V)}
client = socket.socket() 
client.connect((socket.gethostname(), 2002))
request_to_send = json.dumps(vrequest)
client.send(str(json.dumps(request_to_send)).encode())
data_recv = client.recv(10240).decode()

final_auth=ast.literal_eval(aes_dec(session_key_V,data_recv[2:-1]))

if(final_auth["timestamp"]==ts):
    print("Authentication Success!!")

client.close()