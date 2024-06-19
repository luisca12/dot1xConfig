from netmiko import ConnectHandler
from log import logConfiguration
import logging.config

logging.config.dictConfig(logConfiguration)
authLog = logging.getLogger('infoLog')

import os
import traceback
import re

shErroDisable = "show interfaces status err-disabled"
shHostname = "show run | i hostname"
interface = ''
writeMem = 'do write'

errDisableIntPatt = r'[a-zA-Z]+\d+\/(?:\d+\/)*\d+'

recovInt = [
    f'int {interface}',
    'shut',
    'no shut'
]

intErrDisableList = []

def errDisable(validIPs, username, netDevice):
    # This function is to find and fix errDisable Intrfaces
    
    for validDeviceIP in validIPs:
        try:
            validDeviceIP = validDeviceIP.strip()
            currentNetDevice = {
                'device_type': 'cisco_xe',
                'ip': validDeviceIP,
                'username': username,
                'password': netDevice['password'],
                'secret': netDevice['secret'],
                'global_delay_factor': 2.0,
                'timeout': 120,
                'session_log': 'netmikoLog.txt',
                'verbose': True,
                'session_log_file_mode': 'append'
            }

            print(f"INFO: Connecting to device {validDeviceIP}...")
            with ConnectHandler(**currentNetDevice) as sshAccess:
                authLog.info(f"User {username} is now running commands at: {validDeviceIP}")
                sshAccess.enable()
                shHostnameOut = sshAccess.send_command(shHostname)
                authLog.info(f"User {username} successfully found the hostname {shHostnameOut}")
                shHostnameOut = shHostnameOut.replace('hostname', '')
                shHostnameOut = shHostnameOut.strip()
                shHostnameOut = shHostnameOut + "#"

                print(f"INFO: Searching and fixing errDisabled interfaces for device: {validDeviceIP}")
                authLog.info(f"Searching and fixing errDisabled interfaces for device: {validDeviceIP}")
                shErroDisableOut = sshAccess.send_command(shErroDisable)
                print(shErroDisableOut)
                authLog.info(f"{shHostnameOut}{shErroDisable}\n{shErroDisableOut}")
                shErroDisableOut = re.findall(errDisableIntPatt, shErroDisableOut)
                authLog.info(f"Found the following interfaces in error disable for device {validDeviceIP}: {shErroDisableOut}")
                if shErroDisableOut:
                    for interface in shErroDisableOut:
                        interface = interface.strip()
                        recovInt[0] = f'int {interface}'
                        print(f"INFO: Recovering interface {interface} from errDisabled state on device {validDeviceIP}")
                        authLog.info(f"Recovering interface {interface} on device {validDeviceIP}")
                        recovIntOut = sshAccess.send_config_set(recovInt)
                        print(recovIntOut)
                        authLog.info(f"{recovIntOut}")
                        print(f"INFO: Successfully recovered interface {interface} for device: {validDeviceIP}")
                        authLog.info(f"Successfully recovered interface {interface} for device: {validDeviceIP}")
                        with open(f"Outputs/generalOutputs.txt", "a") as file:
                            file.write(f"INFO: Fixing errDisabled interfaces for device: {validDeviceIP}\n")
                            file.write(f"{shHostnameOut}:\n{recovIntOut}\n")
                    print(f"Saving configuration for device: {validDeviceIP}")
                    sshAccess.send_config_set(writeMem)
                    authLog.info(f"Saved configuration for device: {validDeviceIP}")
                else:
                    print(f"No interfaces were found in errDisable state. Skipping device: {validDeviceIP}")
                    authLog.info(f"No interfaces were found in errDisable state. Skipping device: {validDeviceIP}")

        except Exception as error:
            print(f"An error occurred: {error}\n", traceback.format_exc())
            authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}")
            authLog.debug(traceback.format_exc(),"\n")
            with open(f"failedDevices.csv","a") as failedDevices:
                failedDevices.write(f"{validDeviceIP}\n")
        
        finally:
            print("\nOutputs and files successfully created.")
            print("For any erros or logs please check authLog.txt\n")