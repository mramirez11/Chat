#!/usr/bin/env python
import socket
import sys
import os, hashlib

from Crypto.Cipher import AES

# Importacion para cifrado asimetrico
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Parametros para cifrado simetrico
SALT_SIZE = 16  # This size is arbitrary
password = b'highly secure encryption password'
IV_SIZE = 16    # 128 bit, fixed for the AES algorithm    
KEY_SIZE="16" # Inicializamos variable del tipo de cifrado
# Cifrado Simetrico
def cifradoSimetrico(tipo, mensaje):
    KEY_SIZE = tipo   # 256 bit meaning AES-256, can also be 128 or 192 bits
    #print("Cifrado de " + str(KEY_SIZE) +" bits")
    #cleartext = bytes(mensaje)
    #print(cleartext)
    salt = os.urandom(SALT_SIZE)
    derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
                                dklen=IV_SIZE + int(KEY_SIZE))
    iv = derived[0:IV_SIZE]
    key = derived[IV_SIZE:]

    encrypted = salt + AES.new(key, AES.MODE_CFB, iv).encrypt(mensaje.encode('utf8'))
    #print("Mensaje Encriptado: "+ str(encrypted))
    #print(encrypted)
    return encrypted

# Descifrado simetrico
def descifradoSimetrico(tipo,encriptado):
    salt = encriptado[0:SALT_SIZE]
    KEY_SIZE=tipo
    #print("Cifrado de " + str(KEY_SIZE) +" bits")
    derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
                                dklen=IV_SIZE + int(KEY_SIZE))
    iv = derived[0:IV_SIZE]
    key = derived[IV_SIZE:]
    cleartext = AES.new(key, AES.MODE_CFB, iv).decrypt(encriptado[SALT_SIZE:])
    #print("Mensaje desencriptado: " +str(cleartext))
    #print(cleartext)
    return cleartext

# Parametros para cifrado asimetrico
random_generator = Crypto.Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()

public_key_server=""

# Cifrado Asimetrico
def cifradoAsimetrico(message):
    message = message.encode()
    cipher = PKCS1_OAEP.new(public_key_server)
    encrypted_message  = cipher.encrypt(message)
    #print(encrypted_message)
    return encrypted_message
# Descifrado Asimetrico
def descifradoAsimetrico(encrypted_message):
    cipher = PKCS1_OAEP.new(private_key)
    message = cipher.decrypt(encrypted_message)
    #print(message)
    return message


# Creamos socket TCP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Socket con puerto en escucha
msg=input("Ingrese direccion del servidor\n")
server_address = (msg, 10000)
print('Conectado a {} puerto {}'.format(*server_address))
sock.connect(server_address)
condConexion=True
condCifrado=True
condSimetrico=False
condAsimetrico=False
while True:
    #Validamos que el tipo de cifrado se escoja una sola vez
    if(condCifrado):
        message= input("Que tipo de cifrado quiere \n[0] Simetrico \n[1] Asimetrico\n")
        if(message=="0"): # Simetrico
            condCifrado=False
            condSimetrico=True
            sock.send(message.encode('ascii'))
            message=sock.recv(1024)
            print(message)
            while(True):
                message = input('>> Que tipo de cifrado simetrico quiere? \n[128] AES 128 Bit \n[256] AES 256 Bit\n')
                if(message=="128"):
                    KEY_SIZE=16
                    break
                if(message=="256"):
                    KEY_SIZE=32
                    break
            #print("Mensaje sera cifrado simetricamente con AES "+ message )
            sock.send(message.encode('ascii'))
            message=sock.recv(1024)
            message=descifradoSimetrico(KEY_SIZE,message)
            print("Servidor: %s" % message)
        if(message=="1"): # Asimetrico
            condCifrado=False
            condAsimetrico=True
            sock.send(message.encode('ascii'))
            print("-----------------------------------Clave publica server----------------------------------")
            public_key_server=sock.recv(4096) # Recibimos la public key del server
            public_key_server=RSA.importKey(binascii.unhexlify(public_key_server)) # Convertimos de utf8 a RSA
            print(public_key_server) # Mostramos la public_key del server
            print("-----------------------------------Clave publica client----------------------------------")
            public_key = public_key.exportKey(format='DER') # Exportamos la key a otro formato 
            public_key = binascii.hexlify(public_key).decode('utf8') # Exportamos la key a utf8 para su envio
            print(public_key)
            sock.send(public_key.encode('utf8')) # Enviamos nuestra public key
        continue # Finalizamos el bucle
    # Validamos que la conexion se escoja una sola vez
    message==''
    if(condConexion):
        message = input('>> Que tipo de Conexion quiere? [0] TCP  [1] UDP\n')
        if(condSimetrico and (message=="0" or message=="1")):
            condConexion=False # Cambiamos la condicion para que no se vuelva a entrar
            message=cifradoSimetrico(KEY_SIZE,message) # Ciframos el mensaje a enviar
            sock.send(message) # Enviamos el mensaje cifrado
            #print("Cliente: "+str(message))
            data = sock.recv(1024) #Recibimos el mensaje cifrado
            #print("Mensaje recibido: "+ str(data))
            data=descifradoSimetrico(KEY_SIZE,data)
        if(condAsimetrico and (message=="0" or message=="1")):
            condConexion=False # Cambiamos la condicion para que no se vuelva a entrar
            data=cifradoAsimetrico(message)
            sock.send(data)
            data=sock.recv(1024)
            data=descifradoAsimetrico(data)
        continue
    print("Servidor: %s" % data)
    print("-------¡Estamos listos para iniciar el chat!-------")
        
    if(condSimetrico):
        while(True):
            # Si enviamos la 'ñ' no se logra descifrar correctamente el mensaje
            #print("AQUII")
            # Enviamos el mensaje
            newdata= input(">")
            newdata=cifradoSimetrico(KEY_SIZE,newdata)
            #sock.send(data.encode('ascii'))
            sock.send(newdata)
            # Mostramos el mensaje
            newdata = sock.recv(4096)
            #print(newdata)
            newdata=descifradoSimetrico(KEY_SIZE,newdata)
            #print(data)
            print("Servidor: %s" % newdata)
            
    if(condAsimetrico):
        while(True):
            # Escribimos mensaje y lo enviamos
            newdata = input(">>")
            newdata=cifradoAsimetrico(newdata)
            sock.send(newdata)
            newdata=sock.recv(1024)
            newdata=descifradoAsimetrico(newdata)
            print("Servidor: %s" % newdata)
        
        

