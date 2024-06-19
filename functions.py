from log import logConfiguration
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException

import socket
import getpass
import csv
import os
import traceback
import logging.config

logging.config.dictConfig(logConfiguration)
authLog = logging.getLogger('infoLog')

def checkIsDigit(input_str):
    try:
        authLog.info(f"String successfully validated selection number {input_str}, from checkIsDigit function.")
        return input_str.strip().isdigit()
    
    except Exception as error:
        authLog.error(f"Invalid option chosen: {input_str}, error: {error}")
        authLog.error(traceback.format_exc())
                
def validateIP(deviceIP):
    try:
        socket.inet_aton(deviceIP)
        authLog.info(f"IP successfully validated: {deviceIP}")
        return True
    except (socket.error, AttributeError):
        try:
            deviceIP = f'{deviceIP}.mgmt.internal.das'
            socket.gethostbyname(deviceIP)
            authLog.info(f"Hostname successfully validated: {deviceIP}")
            return True
        except (socket.gaierror, AttributeError):
            authLog.error(f"Not a valid IP address or hostname: {deviceIP}")
            authLog.error(f"Invalid IP address or hostname: {deviceIP}")
            # Append the invalid IP address or hostname to a CSV file
            with open('invalidDestinations.csv', mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([deviceIP])
            return False
        
def checkReachPort22(ip):
    try:
        if ip.count('.') == 3:  # Check if the input is an IP address
            ip = ip
        else:  # Assume it's a hostname and append the domain
            ip = f"{ip}.mgmt.internal.das"
        connTest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connTest.settimeout(3)
        connResult = connTest.connect_ex((ip, 22))
        if connResult == 0:
            print(f"Device {ip} is reachable on port TCP 22.")
            authLog.info(f"Device {ip} is reachable on port TCP 22.")
            return ip
        else:
            print(f"Device {ip} is not reachable on port TCP 22, will be skipped.")
            authLog.error(f"Device IP: {ip}, is not reachable on port TCP 22.")
            authLog.debug(traceback.format_exc())

    except Exception as error:
        print("Error occurred while checking device reachability:", error,"\n")
        authLog.error(f"Error occurred while checking device reachability for IP {ip}: {error}")
        authLog.debug(traceback.format_exc())
    
    finally:
        connTest.close()

def requestLogin(validIPs):
    while True:
        try:
            username = input("Please enter your username: ")
            password = getpass.getpass("Please enter your password: ")
            execPrivPassword = getpass.getpass("Please input your enable password: ")

            for deviceIP in validIPs:
                netDevice = {
                    'device_type': 'cisco_xe',
                    'ip': deviceIP,
                    'username': username,
                    'password': password,
                    'secret': execPrivPassword
                }
                # print(f"This is netDevice: {netDevice}\n")
                # print(f"This is deviceIP: {deviceIP}\n")

                # sshAccess = ConnectHandler(**netDevice)
                # print(f"Login successful! Logged to device {deviceIP} \n")
                authLog.info(f"Successful saved credentials for username: {username}")

            return validIPs, username, netDevice

        except NetMikoAuthenticationException:
            print("\n Login incorrect. Please check your username and password")
            print(" Retrying operation... \n")
            authLog.error(f"Failed to authenticate - remote device IP: {deviceIP}, Username: {username}")
            authLog.debug(traceback.format_exc())

        except NetMikoTimeoutException:
            print("\n Connection to the device timed out. Please check your network connectivity and try again.")
            print(" Retrying operation... \n")
            authLog.error(f"Connection timed out, device not reachable - remote device IP: {deviceIP}, Username: {username}")
            authLog.debug(traceback.format_exc())

        except socket.error:
            print("\n IP address is not reachable. Please check the IP address and try again.")
            print(" Retrying operation... \n")
            authLog.error(f"Remote device unreachable - remote device IP: {deviceIP}, Username: {username}")
            authLog.debug(traceback.format_exc())

def delStringFromFile(filePath, stringToDel):
    with open(filePath, "r") as file:
        file_content = file.read()

    updated_content = file_content.replace(stringToDel, "")

    with open(filePath, "w") as file:
        file.write(updated_content)

def checkYNInput(stringInput):
    return stringInput.lower() == 'y' or stringInput.lower() == 'n'

def readIPfromCSV(csvFile):
    try:
        with open(csvFile, "r") as deviceFile:
            csvReader = csv.reader(deviceFile)
            for row in csvReader:
                for ip in row:
                    ip = ip.strip()
                    ip = ip + ".mgmt.internal.das"
    except Exception as error:
        print("Error occurred while checking device reachability:", error,"\n")
        authLog.error(f"Error occurred while checking device reachability for IP {ip}: {error}")
        authLog.debug(traceback.format_exc())