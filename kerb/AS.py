# reference for socket program https://www.digitalocean.com/community/tutorials/python-socket-programming-server-client
import socket
from rsa import *
from datetime import datetime
import json
from aes import *
def gen_ticket(sess_key,self_id,network_address,rid,ts,dur):
    ticket={"session_key":sess_key,"self_id":self_id,"address":network_address,"id":rid,"timestamp":ts,"duration":dur}
    ticket=json.dumps(ticket)
    enc_tkt=(str(encrypt(ticket,TGS_public_key)).encode())#tkt encrypted with public key of tgs for only tgs
    return enc_tkt.decode()#tkt is in byte string

def req_handler(data_recv,sock):
    request_recv = json.loads(data_recv)
    ts=str(datetime.now())
    dur=5
    sess_key="secretkey1234567";
    resp={"session_key":sess_key,"id":request_recv["id"],"timestamp":ts,"duration":dur,"TGS_ticket":gen_ticket(sess_key,request_recv['self_id'],"network_addr",request_recv['id'],ts,dur)}
    response = encrypt(json.dumps(resp),server_pub_keys[request_recv["self_id"]])#enc with public key of client
    sock.send(str(response).encode())
    

# generating keys and commenting that part
# later if needed we can use it
# key = gen_keys(generate_primes(10),generate_primes(10))
# print(key)
# ((209897, 163151), (209897, 34811))
# public_key = key[0]
# private_key = key[1]
#

TGS_public_key=(6283,4663)
public_key = (1313,289)#(209897, 163151)
private_key = (1313,1009)#(209897, 34811)
keys_dict = {'B':'(1111,573)','A':'(6077,3437)'}
server_pub_keys={'A':(6077,3437),'B':(1111,573)}
server = socket.socket()
server.bind((socket.gethostname(),2000))
server.listen(10)

while(1):
    sock, conn_from = server.accept()
    data_recv = sock.recv(1024).decode()
    print("Data received "+str(data_recv))
    req_handler(data_recv,sock)
    sock.close()

