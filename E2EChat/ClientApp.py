import os
import sys
import requests
import json


main()

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
    r = requests.post(url = "http://localhost:3000/registration/login", data = payload)
    #r = requests.post("https://supersecurebros.me/registration/login", data = {'email': userName, 'password': password})
    json_data = r.json()
    if(json_data['auth'] == False):
        print('Invalid credentials')
        main()
    token = json_data['token']
    messaging(token)
    


def Registration():
    email = input("\nPlease enter a new email\n")
    password = input("Please enter a new password\n")

    payload = {'email': email, 'password': password}
    r = requests.post(url='http://localhost:3000/registration', data=payload)
    json_data = r.json()

    if(json_data['auth'] == False):
        print('Invalid credentials')
        main()
    token = json_data['token']
    messaging(token)


def messaging(token):
    while(1):
        userInput = input("\n\nWhat would you like to do:\n1.\tSend a message\n2.\tRecieve a message\nAny Other input to log off\n")
        if(userInput == "1"):
            reciever = input("Please enter the email of the person you wish to message\n")
            message = input("Please enter the message to " + reciever + "\n")

            payload = {'reciever': reciever, 'message': message}
            headers = {'x-access-token': token}
            r = requests.post(url='http://localhost:3000/message', data=payload, headers = headers)
            print(r.text)
        elif(userInput == "2"):
            print("Retrieving your messages:\n")
            headers = {'x-access-token': token}
            r = requests.get(url='http://localhost:3000/message', headers = headers)
            print(r.text)
        else:
            print("Logging you off")
            break
    main()
