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

    # drivers_license={'Driver_number':'UP1520022020113','Name':'Shivaansh Mital','Date Of Issue':str(datetime.now()),"Validity":5,'Signature':'[301, 980, 619, 109, 909, 1056, 980, 405, 120, 909, 1056, 1056, 407, 301, 619, 436, 510, 415, 189, 709, 292, 407, 510, 109, 109, 301, 415, 619, 619, 120, 407, 189, 120, 619, 909, 909, 407, 980, 109, 301, 405, 709, 1056, 619, 120, 189, 415, 909, 619, 980, 980, 909, 1056, 109, 109, 189, 407, 100, 980, 189, 1056, 709, 189, 709]'}
    drivers_license={'Driver_number':'UP1520022020113','Name':'Shivaansh Mital','Date Of Issue':'2023-04-22 12:38:31.505746',"Validity":5,'Signature':'[909, 189, 405, 109, 100, 292, 709, 436, 100, 292, 189, 436, 619, 100, 909, 436, 120, 415, 909, 189, 980, 301, 619, 189, 980, 510, 980, 980, 436, 415, 415, 189, 120, 100, 189, 909, 109, 510, 189, 301, 120, 292, 292, 189, 415, 436, 292, 619, 619, 292, 109, 407, 436, 301, 510, 415, 100, 415, 407, 100, 709, 415, 109, 619]'}

    # client.send(str(aes_enc(session_key_V,json.dumps(drivers_license))).encode())
    client.send(str(aes_enc(session_key_V,json.dumps(drivers_license))).encode())

    status = client.recv(1024).decode()
    status = aes_dec(session_key_V,status[2:-1])
    status = json.loads(status)
    print("Verification Status "+status['VerificationStatus'])
client.close()