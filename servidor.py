#!/usr/bin/env python
import socket
import sys
import os, hashlib
# Importacion para cifrado simetrico
from Crypto.Cipher import AES

# Importacion para cifrado asimetrico
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

random_generator = Crypto.Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()
public_key_client=""

def cifradoAsimetrico(message):
    #message = 'Hola mundo, soy un mensaje en texto plano, todo el mundo puede leerme.'
    message = message.encode()
    cipher = PKCS1_OAEP.new(public_key_client)
    encrypted_message  = cipher.encrypt(message)
    #print(encrypted_message)
    return encrypted_message

def descifradoAsimetrico(encrypted_message):
    cipher = PKCS1_OAEP.new(private_key)
    message = cipher.decrypt(encrypted_message)
    #print(message)
    return message


condCifrado=True
condConexion=True
condSimetrico=False
condAsimetrico=False

SALT_SIZE = 16  # This size is arbitrary
password = b'highly secure encryption password'
IV_SIZE = 16    # 128 bit, fixed for the AES algorithm
KEY_SIZE=16 # Inicializamos variable del tipo de cifrado
# Cifrado
def cifradoSimetrico(tipo, mensaje):
    KEY_SIZE = tipo   # 256 bit meaning AES-256, can also be 128 or 192 bits
    #cleartext = b'mensaje'
    salt = os.urandom(SALT_SIZE)
    derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
                                dklen=IV_SIZE + int(KEY_SIZE))
    iv = derived[0:IV_SIZE]
    key = derived[IV_SIZE:]

    encrypted = salt + AES.new(key, AES.MODE_CFB, iv).encrypt(mensaje.encode('utf8'))
    #print("Mensaje Encriptado: "+ str(encrypted))
    #print(encrypted)
    return encrypted

# Decifrado
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
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('localhost', 10000)
print('conectando a {} puerto {}'.format(*server_address))
sock.bind(server_address)
# Listen for incoming connections
sock.listen(10)
# Wait for a connection
while True:
    print('Esperando conexion')
    connection, client_address = sock.accept()
    print('Conexion TCP desde', client_address)
    try:
        while True:
            data = connection.recv(1024) # Recibimos el mensaje
            if(condCifrado): # Verificamos que se eliga solo una vez el cifrado
                condCifrado=False
                if(data==b'0'): # Cifrado simetrico
                    condSimetrico=True # Cambiamos a True para entrar a los metodos simetricos
                    message="Cifrado simetrico"
                    connection.send(message.encode('ascii'))
                    message=connection.recv(1024)
                    #print(message)
                    if(message==b'128'):
                        #data=descifradoSimetrico(16,data) # Desciframos el mensaje recibido
                        message="Cifrado simetrico con 128 bits"
                        KEY_SIZE=16
                    if(message==b'256'):
                        message="Cifrado simetrico con 256 bits"
                        KEY_SIZE=32
                    print(message)
                    message=cifradoSimetrico(KEY_SIZE,message)
                    connection.send(message)                   
                if(data==b'1'): # Cifrado Asimetrico
                    condAsimetrico=True # Cambiamos a True para entrar a los metodos asimetricos
                    print("-----------------------------------Clave publica server----------------------------------")
                    public_key = public_key.exportKey(format='DER') # Exportamos la key a otro formato
                    public_key = binascii.hexlify(public_key).decode('utf8') # Exportamos la key a utf8 para enviarlas
                    print(public_key) #Mostramos nuestra public key
                    connection.send(public_key.encode('utf8')) # Enviamos nuestra Public Key
                    #public_key = RSA.importKey(binascii.unhexlify(public_key)) # Volvemos la public key a RSA
                    print("-----------------------------------Clave publica client----------------------------------")
                    public_key_client=connection.recv(4096) # Recibimos la public key del client
                    public_key_client=RSA.importKey(binascii.unhexlify(public_key_client)) # Convertimos de utf8 a RSA
                    print(public_key_client) # Mostramos la Public Key del client
                    
                    #connection.send(data)
                continue
            # Verificamos que se eliga la conexion solo una vez
            if(condConexion):
                condConexion=False
                # Condicionales para cambiar el socket
                if(condSimetrico):
                    data=descifradoSimetrico(KEY_SIZE,data)
                    if(data == b'0'):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        data = ("La conexion ahora es: TCP " + str(sock.type))
                        #connection.send(data.encode('ascii')) # Forma antigua de enviar datos
                    if(data == b'1'):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        data = ("La conexion ahora es: UDP " + str(sock.type))
                    print(data)
                    #print(sock.type) # Mostramos el tipo de conexion
                    data=cifradoSimetrico(KEY_SIZE, data) # Ciframos el mensjae a enviar
                    connection.send(data) # Enviamos el mensaje cifrado
                if(condAsimetrico):
                    data=descifradoAsimetrico(data)
                    if(data==b'0'):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        data = ("La conexion ahora es: TCP " + str(sock.type))
                        print(data)
                    if(data== b'1'):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        data = ("La conexion ahora es: UDP " + str(sock.type))
                    data=cifradoAsimetrico(data)
                    connection.send(data)

            print("-------¡Estamos listos para iniciar el chat!-------")                    
            if(condSimetrico):
                while(True):
                    # Escribimos mensaje y lo enviamos
                    #print("ACA")
                    newdata=connection.recv(4096)
                    newdata=descifradoSimetrico(KEY_SIZE,newdata)
                    print("Cliente: %s" % newdata)
                    newdata = input(">>")
                    newdata=cifradoSimetrico(KEY_SIZE,newdata)
                    #print(newdata)
                    connection.send(newdata)
            if(condAsimetrico):
                while(True):
                    message=connection.recv(1024)
                    message=descifradoAsimetrico(message)
                    print("Cliente: %s" % message)
                    # Escribimos mensaje y lo enviamos
                    newdata = input(">>")
                    newdata=cifradoAsimetrico(newdata)
                    connection.send(newdata)
                    


                
    except ValueError:
        print("Error")



