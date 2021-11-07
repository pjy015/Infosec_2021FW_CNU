from os import error
import socket
import threading
import base64
import sys
from time import sleep
from Crypto import Cipher
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# 서버 연결정보; 자체 서버 실행시 변경 가능
SERVER_HOST = "homework.islab.work"
SERVER_PORT = 8080

PROTOCOL = '3EPROTO'
TIMEOUT = 30
BLOCK_SIZE = 16

# Client Method #
CONNECT = 'CONNECT'
DISCONNECT = 'DISCONNECT'
KEYXCHG = 'KEYXCHG'
KEYXCHGRST = 'KEYXCHGRST'
MSGSEND = 'MSGSEND'

# Server Method #
ACCEPT = 'ACCEPT'
BYE = 'BYE'
DENY = 'DENY'
RELAYOK = 'RELAYOK'
KEYXCHGOK = 'KEYXCHGOK'
KEYXCHGFAIL = 'KEYXCHGFAIL'
MSGSENDOK = 'MSGSENDOK'
MSGRECV = 'MSGRECV'


connectSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connectSocket.connect((SERVER_HOST, SERVER_PORT))

class User :
    def __init__(self):
        self.__user_credential = None
        self.__rsa = RSA.generate(1024)
        self.__private = self.__rsa.export_key()
        self.__public = self.__rsa.public_key().export_key()
        
        
    def setUserCredential(self,_val) :
        self.__user_credential = _val
    def getUserCredential(self) :
        return self.__user_credential
    def getPublicKey(self):
        return self.__public
    def getPrivateKey(self):
        return self.__private  

class Opponent :
    def __init__(self) -> None:
        self.credential = None
        self.public = None
        self.aes_key = None
        self.iv = None
    
    def setCredential(self,_val) :
        self.credential = _val
    def getCredential(self) :
        return self.credential
    
    def setPublicKey(self,_public_key) :
        self.public = _public_key
    def getPublicKey(self) :
        return self.public
    
    def setAESKey(self,_aes_key) :
        self.aes_key = _aes_key
    def getAESKey(self) :
        return self.aes_key
    
    def setIV(self,_iv):
        self.iv = _iv
    def getIV(self):
        return self.iv
    
    def readyToChat(self) :
        if (self.credential == None) | (self.public == None) | (self.aes_key == None) | (self.iv == None) :
            return True
        else :
            return False

user = User()
opponent = Opponent()


def socket_read():
    while True:
        readbuff = connectSocket.recv(2048)
        
        if len(readbuff) == 0:
            continue

        #recv_payload = readbuff.decode('utf-8')
        parse_payload(readbuff)

def socket_send():
    while True:
        if user.getUserCredential() == None :
            _id = input(":: user name >> ")
            if _id == '' :
                print("[sys] no input. try again.")
                continue
            else:
                send_request(CONNECT, _id) 

        elif opponent.getCredential() == None :
            print('(if you want [logout : \':OUT\'/ wait : \':WAIT\'])')
            opp_in = input(":: Insert opponent name >>")
            if opp_in == ':OUT' :
                send_request(DISCONNECT, user.getUserCredential())
            elif opp_in == ':WAIT' :
                for i in range(TIMEOUT) :
                    if opponent.getCredential() != None :
                        break
                    print('...Wait for other user contact...('+str(i)+'/'+str(TIMEOUT)+')')
                    sleep(1)
                while not (opponent.readyToChat()) :
                    sleep(1)
                continue
            elif opp_in == ':KEYRST' :
                target = input('[KEY RESET] Put opponet name >> ')
                send_request(KEYXCHGRST,target)
            else :
                opponent.setCredential(opp_in)
                send_request(KEYXCHG, opp_in, opt='public') # 공개키 보내고
                for i in range(TIMEOUT) :
                    if opponent.getPublicKey() != None : # 공개키 답장 받으면
                        send_request(KEYXCHG,opp_in, opt = 'aes') # 받은 공개키로 AES 키 교환 요청 전송
                        break
                    sleep(1)    
        else: #opponent.readyToChat() :
            _in = input(':: '+user.getUserCredential() + "(you) >> ")
            if _in == ':OUT' :
                send_request(DISCONNECT, user.getUserCredential())
            elif _in == ':INFO' :
                print()
            else :
                send_request(MSGSEND, _in)

        sleep(0.2)


def send_request(_method, _value,**kwargs):
    msg_args = {
        'Method' : None, 
        'Algo' : None,      'Credential' : None, 
        'Timestamp' : None, 'Nonce' : None,
        'From' : None,      'To' : None,
        'Body':None
    }

    if _method == CONNECT :
        msg_args['Method'] = CONNECT
        msg_args['Credential'] = _value   
        
    elif _method == DISCONNECT :
        msg_args['Method'] = DISCONNECT
        msg_args['Credential'] = _value
        
    elif _method == KEYXCHG :
        msg_args['Method'] = KEYXCHG
        msg_args['From'] = user.getUserCredential()
        msg_args['To'] = _value
        if kwargs['opt'] == 'public' :
            msg_args['Algo'] = '-'
            msg_args['Body'] = user.getPublicKey()
            
        elif kwargs['opt']  == 'aes' :
            opponent.setAESKey(get_random_bytes(32))
            opponent.setIV(get_random_bytes(16))
            data = opponent.getAESKey()+'\n'.encode('utf-8')+opponent.getIV()
            key_encrypted = encrypt_RSA(data,opponent.getPublicKey())
            
            msg_args['Algo'] = 'RSA'
            msg_args['Body'] = key_encrypted

    elif _method == KEYXCHGOK :
        msg_args['Method'] = KEYXCHGOK
        msg_args['Algo'] = '-'
        msg_args['From'] = user.getUserCredential()
        msg_args['To'] = opponent.getCredential()
        msg_args['Body'] = user.getPublicKey()

    elif _method == KEYXCHGRST :
        msg_args['Method'] = KEYXCHGRST
        msg_args['From'] = user.getUserCredential()
        msg_args['To'] = _value
        opponent.setAESKey(get_random_bytes(32))
        opponent.setIV(get_random_bytes(16))
        data = opponent.getAESKey()+'\n'.encode('utf-8')+opponent.getIV()
        key_encrypted = encrypt_RSA(data,opponent.getPublicKey())
        msg_args['Algo'] = 'RSA'
        msg_args['Body'] = key_encrypted

    elif _method == MSGSEND :
        msg_args['Method'] = MSGSEND
        msg_args['Algo'] = 'AES-256-CBC'
        msg_args['From'] = user.getUserCredential()
        msg_args['To'] = opponent.getCredential()
        msg_args['Body'] = encrypt_AES(_value.encode('utf-8'), opponent.getAESKey(),opponent.getIV())

    request = build_msg_from_args(msg_args)
    connectSocket.sendall(request)




def parse_payload(readbuff:bytes):
    #print(readbuff.decode('utf-8'))
    msg_args = {
        'Method' : None, 
        'Algo' : None,      'Credential' : None, 
        'Timestamp' : None, 'Nonce' : None,
        'From' : None,      'To' : None,
        'Body':None
    }
    # Divide header & body
    if readbuff.find('\n\n'.encode('utf-8')) != -1 :
        head, body = readbuff.split('\n\n'.encode('utf-8'))
    else :
        head = readbuff
    # Decode & parse header
    head_decoded_split = head.decode('utf-8').split('\n')
    msg_args['Method'] = head_decoded_split.pop(0).split()[1]
    for h in head_decoded_split :
        divider_idx = h.find(':')
        attr = h[:divider_idx].rstrip()
        val = h[divider_idx+1:].lstrip() 
        msg_args[attr] = val

    # Decode body by Method
    if msg_args['Method'] == ACCEPT :
        body_decoded = body.decode('utf-8')
        user.setUserCredential(body_decoded)
        print("[sys] Connected to Server. Register user name : "+user.getUserCredential())
    elif msg_args['Method'] == DENY :
        body_decoded = body.decode('utf-8')
        print('[sys] '+ body_decoded)
    elif msg_args['Method'] == BYE :
        user.setUserCredential(None)
        print('[sys] Log out success ('+msg_args['Timestamp']+')')
    elif msg_args['Method'] == RELAYOK :
        #body_decoded = body.decode('utf-8')
        #opponent.setCredential(body_decoded)
        #print('[sys] request sent')
        pass
    elif msg_args['Method'] == KEYXCHG :
        # CASE : Received Public Key exchange request
        # print('[sys]Got a Keyxchng request')
        if msg_args['Algo'] == '-': 
            opponent.setCredential(msg_args['From'])
            opponent.setPublicKey(body)
            # print('[sys] Respond KEYCHGOK to '+opponent.getCredential())
            send_request(KEYXCHGOK,opponent.getCredential(),opt = 'public')
            
        # CASE : Exchange AES Key
        elif msg_args['Algo'] == 'RSA' :
            body_decoded = decrypt_RSA(body,user.getPrivateKey())
            #print(body_decoded)
            #key , iv = body_decoded.split('\n'.encode('utf-8'))
            key = body_decoded[:32]
            iv = body_decoded[-16:]
            opponent.setAESKey(key)
            opponent.setIV(iv)
            #print('[sys] Got AES Key from '+opponent.getCredential())
            #print(opponent.getAESKey())
            #print(opponent.getIV())

    elif msg_args['Method'] == KEYXCHGOK :
        opponent.setPublicKey(body)
        #print('[sys] Received Reply public key from '+opponent.getCredential())
    elif msg_args['Method'] == KEYXCHGRST :
        body_decoded = decrypt_RSA(body,user.getPrivateKey())
        key = body_decoded[:32]
        iv = body_decoded[-16:]
        opponent.setAESKey(key)
        opponent.setIV(iv)
        
    elif msg_args['Method'] == MSGRECV :
        body_decoded = decrypt_AES(body,opponent.getAESKey(),opponent.getIV())
        text = body_decoded.decode('utf-8')
        print(':: '+opponent.getCredential()+'>> '+ text)
        
    elif msg_args['Method'] == MSGSENDOK :
        pass  
    sleep(0.5)  
            

def build_msg_from_args (_args:dict) :
    preamble = PROTOCOL+' '+_args.pop('Method')
    header_list = []
    body = None
    for key,value in _args.items() :
        if value == None:
            continue
        elif key =='Body' :
            body = value
        else :
            header_list.append(key+':'+value) 
    header = '\n'.join(header_list)

    result = preamble + '\n' + header
    result = result.encode('utf-8')
    if body != None : result += ('\n\n'.encode('utf-8') + body)
    return result  

# def search_from_history( _credential):
#     return next((info for info in history_list if info['Credential'] == _credential),False)

def encrypt_AES(_raw : bytes, _key, _iv) :
    cipher_aes = AES.new(_key,AES.MODE_CBC,_iv)
    ciphertext = cipher_aes.encrypt(pad(_raw,BLOCK_SIZE)) 
    return  base64.b64encode(ciphertext) 

def decrypt_AES(_cipheredtext : bytes, _key, _iv) :
    cipher_aes = AES.new(_key,AES.MODE_CBC,_iv)
    decrypt_txt = cipher_aes.decrypt(base64.b64decode(_cipheredtext)) 
    unpaded = unpad(decrypt_txt,BLOCK_SIZE)
    return unpaded

def encrypt_RSA (_raw : bytes, key ):
    rkey = RSA.import_key(key)
    cipher_rsa = PKCS1_OAEP.new(rkey)
    enc_txt = cipher_rsa.encrypt(_raw)
    return base64.b64encode(enc_txt)

def decrypt_RSA(_cipheredtext, key) :
    rkey = RSA.import_key(key)
    cipher_rsa = PKCS1_OAEP.new(rkey)
    dec_txt = cipher_rsa.decrypt(base64.b64decode(_cipheredtext))
    return dec_txt

reading_thread = threading.Thread(target=socket_read)
sending_thread = threading.Thread(target=socket_send)

reading_thread.start()
sending_thread.start()

reading_thread.join()
sending_thread.join()