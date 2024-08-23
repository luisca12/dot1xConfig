
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException
from functions import checkYNInput,validateIP,requestLogin,checkReachPort22
from strings import greetingString
from log import *
from log import invalidIPLog
import socket
import traceback
import csv
import os
import logging

username = ""
execPrivPassword = ""
netDevice = {}
validIPs = []

def Auth():
    global username, execPrivPassword, netDevice, validIPs

    manualInput = input("\nDo you want to choose a CSV file?(y/n):")

    while not checkYNInput(manualInput):
        print("Invalid input. Please enter 'y' or 'n'.\n")
        authLog.error(f"User tried to choose a CSV file but failed. Wrong option chosen: {manualInput}")
        manualInput = input("\nDo you want to choose a CSV file?(y/n):")

    if manualInput == "y":
        while True:
            csvFile = input("Please enter the path to the CSV file: ")
            authLog.info(f"User chose to input a CSV file. CSV File path: {csvFile}")
            try:
                with open(csvFile, "r") as deviceFile:
                    csvReader = csv.reader(deviceFile)
                    for row in csvReader:
                        for ip in row:
                            ip = ip.strip()
                            authLog.info(f"IP address found: {ip} in file: {csvFile}")
                            ipOut = validateIP(ip)
                            if ipOut is not None:
                                validIPs.append(ipOut)
                            else:
                                authLog.info(f"IP address {ip} is invalid or unreachable.")
                    if not validIPs:
                        print(f"No valid IP addresses found in the file path: {csvFile}\n")
                        authLog.error(f"No valid IP addresses found in the file path: {csvFile}")
                    else:
                        break
            except FileNotFoundError:
                print("File not found. Please check the file path and try again.")
                authLog.error(f"File not found in path {csvFile}")
                authLog.error(traceback.format_exc())
                continue

        validIPs, username, netDevice = requestLogin(validIPs)

        return validIPs,username,netDevice
    else:
        authLog.info(f"User decided to manually enter the IP Addresses.")
        os.system("CLS")
        greetingString()
        while True:
            deviceIPs = input("\nPlease enter the devices IPs separated by commas: ")
            deviceIPsList = deviceIPs.split(',')

            for ip in deviceIPsList:
                ip = ip.strip()
                ipOut = validateIP(ip)
                if ipOut is not None:
                    validIPs.append(ipOut)
                else:
                    authLog.info(f"IP address {ip} is invalid or unreachable.")
            if validIPs:
                break
        validIPs, username, netDevice = requestLogin(validIPs)

        return validIPs,username,netDevice