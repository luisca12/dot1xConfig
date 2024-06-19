import os
from commandsCLI import shErroDisable

def greetingString():
        os.system("CLS")
        print('  ----------------------------------------------------------------------- ')
        print("    Welcome to the automated Recovery of errDisabled interfaces  Program ")
        print('  ----------------------------------------------------------------------- ')

def menuString(deviceIP, username):
        os.system("CLS")
        print(f"Connected to: {deviceIP} as {username}\n")
        print('  -------------------------------------------------------------- ')
        print('\t\tMenu - Please choose an option')
        print('\t\t  Only numbers are accepted')
        print('  -------------------------------------------------------------- ')
        print('  >\t\t1. To run the following commands:\t       <')
        print(f'{shErroDisable} and recover errDisable interfaces\n')      
        print('  >\t\t\t2. Exit the program\t\t       <')
        print('  -------------------------------------------------------------- \n')

def inputErrorString():
        os.system("CLS")
        print('  ------------------------------------------------- ')  
        print('>      INPUT ERROR: Only numbers are allowed       <')
        print('  ------------------------------------------------- ')

def shRunString(validIPs):
        print('  ------------------------------------------------- ')  
        print(f'> Taking a show run of the device {validIPs} <')
        print('>\t   Please wait until it finishes\t  <')
        print('  ------------------------------------------------- ')
