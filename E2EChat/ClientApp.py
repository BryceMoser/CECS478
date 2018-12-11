import os
import sys
import requests
import json
from enc import RSAEnc
from Decryption import RSACipher_Decrypt



def main():
    print("Starting Chat Application\n")
    while(True):
        userInput = input("Select your option\n1.\tLogin\n2.\tRegister\nAny other key to quit\n")
        if(userInput == "1"):
            print("Login Selected\n")
            Login()
        elif(userInput == "2"):
            print("Registration Selected\n")
            Registration()
        else:
            print("Terminating application")
            break

def Login():
    email = input("\nPlease enter your email\n")
    password = input("Please enter your password\n")
    payload = {'email': email, 'password': password}
    r = requests.post(url = "https://supersecurebro.me/registration/login", data = payload)
    #r = requests.post("https://supersecurebros.me/registration/login", data = payload)
    if(r.status_code == 200):
        json_data = r.json()
        if(json_data['auth'] == False):
            print('Invalid credentials')
            return
        token = json_data['token']
        messaging(token)
    else:
        return
    


def Registration():
    email = input("\nPlease enter a new email\n")
    password = input("Please enter a new password\n")
    payload = {'email': email, 'password': password}
    r = requests.post(url='https://supersecurebro.me/registration', data=payload)
    if(r.status_code == 200):
        json_data = r.json()

        if(json_data['auth'] == False):
            print('Invalid credentials')
            return
        token = json_data['token']
        messaging(token)
    else:
        print('Invalid credentials')
        return


def messaging(token):
    while(1):
        userInput = input("\n\nWhat would you like to do:\n1.\tSend a message\n2.\tRecieve a message\nAny Other input to log off\n")
        if(userInput == "1"):
            reciever = input("Please enter the email of the person you wish to message\n")
            message = input("Please enter the message to " + reciever + "\n")

            msg = message.encode('utf-8')
            msg, tag, iv, RSACipher = RSAEnc(msg, ".\\RSA2048KeyPair\\rsaPubKey.pem")

            payload = {'reciever': reciever, 'message': msg, 'tag': tag, 'iv': iv, 'RSACipher': RSACipher}
            headers = {'x-access-token': token}
            r = requests.post(url='https://supersecurebro.me/message', data=payload, headers = headers)
            
        elif(userInput == "2"):
            print("Retrieving your messages:\n")
            headers = {'x-access-token': token}
            r = requests.get(url='https://supersecurebro.me/message', headers = headers)
            json_data = r.json()
            for i in json_data:
                sender = i['sender']
                ciphertext = i['message']
                iv = i['iv']
                tag = i['tag']
                RSACipher = i['RSACipher']

                message = RSACipher_Decrypt(ciphertext, tag, iv, RSACipher, ".\\RSA2048KeyPair\\rsaPrivKey.pem")
                print("\n" + sender + ": " + message)

        else:
            print("Logging you off")
            break

main()