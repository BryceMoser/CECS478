import os
import sys
import requests

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
    userName = input("\nPlease enter your UserName\n")
    password = input("Please enter your password\n")
    r = requests.post("https://supersecurebros.me/registration/login", data = {'email': userName, 'password': password})
    print(r.text)
    

def Registration():
    userName = input("\nPlease enter a new UserName\n")
    password = input("Please enter a new password\n")
    r = requests.post("https://supersecurebros.me/registration/login", data = {'email': userName, 'password': password})
    return


main()