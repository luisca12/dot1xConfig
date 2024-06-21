from netmiko import ConnectHandler
from log import authLog

import traceback
import re

shIntStatus = "show interface status"
shHostname = "show run | i hostname"
interface = ''

intList = []
intHostsOut = []

intPatt = r'[a-zA-Z]+\d+\/(?:\d+\/)*\d+'
discardPatt = r'(ip address \d+\.\d+\.\d+\.\d+)|(no switchport)|(switchport mode (?!access))|(switchport access vlan 1001)|(switchport access vlan 1101)|(switchport access vlan 1103)|(shutdown)|(vrf forward)'

intConfigAP = [
    f'int {interface}',
    'authentication event fail action next-method',
    'authentication event server dead action authorize voice',
    'authentication event server alive action reinitialize ',
    'authentication host-mode multi-host',
    'authentication open',
    'authentication order dot1x mab',
    'authentication priority dot1x mab',
    'authentication port-control auto',
    'authentication periodic',
    'authentication timer reauthenticate server',
    'authentication timer inactivity server',
    'authentication violation restrict',
    'mab',
    'dot1x pae authenticator',
    'dot1x timeout tx-period 10',
    'ip access-group ACL-DEFAULT in'
]

intConfigHosts = [
    f'int {interface}',
    'authentication event fail action next-method',
    'authentication event server dead action authorize voice',
    'authentication event server alive action reinitialize ',
    'authentication host-mode multi-auth',
    'authentication open',
    'authentication order dot1x mab',
    'authentication priority dot1x mab',
    'authentication port-control auto',
    'authentication periodic',
    'authentication timer reauthenticate server',
    'authentication timer inactivity server',
    'authentication violation restrict',
    'mab',
    'dot1x pae authenticator',
    'dot1x timeout tx-period 10',
    'ip access-group ACL-DEFAULT in'
]

dot1xConfig = [
    'aaa authorization network default group ISE_SERVERS', 
    'aaa accounting auth-proxy default start-stop group ISE_SERVERS',
    'aaa accounting dot1x default start-stop group ISE_SERVERS',
    'aaa accounting update newinfo periodic 600',
    'aaa server radius dynamic-author',
    'client 30.128.33.197 server-key 7 045A05120772410F1A4A',
    'client 10.155.133.65 server-key 7 050A081B291F43480A56',
    'radius server ISE-Server-MO',
    'address ipv4 10.155.133.65 auth-port 1812 acct-port 1813',
    'automate-tester username radius-test',
    'key 7 094D401D11561A53185F',
    'radius server ISE-Server-VA',
    'address ipv4 30.128.33.197 auth-port 1812 acct-port 1813',
    'automate-tester username radius-test',
    'key 7 094D401D11561A53185F',
    'radius-server attribute 6 on-for-login-auth', 
    'radius-server attribute 8 include-in-access-req',
    'radius-server attribute 25 access-request include',
    'radius-server attribute 31 mac format ietf upper-case',
    'radius-server attribute 31 send nas-port-detail mac-only',
    'radius-server dead-criteria time 5 tries 2',
    'radius-server deadtime 10',
    'aaa group server radius ISE_SERVERS',
    'server name ISE-Server-VA',
    'server name ISE-Server-MO',
    'ip radius source-interface Loopback0',
    'do write'
]

def dot1x(validIPs, username, netDevice):
    # This function is to take a show run
    
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

            print(f"Connecting to device {validDeviceIP}...")
            with ConnectHandler(**currentNetDevice) as sshAccess:
                sshAccess.enable()
                shHostnameOut = sshAccess.send_command(shHostname)
                authLog.info(f"User {username} successfully found the hostname {shHostnameOut}")
                shHostnameOut = shHostnameOut.replace('hostname', '')
                shHostnameOut = shHostnameOut.strip()
                shHostnameOut = shHostnameOut + "#"

                print(f"INFO: Taking a \"{shIntStatus}\" for device: {validDeviceIP}")
                shIntStatusOut = sshAccess.send_command(shIntStatus)
                authLog.info(f"Automation successfully ran the command: {shIntStatus}")
                shIntStatusOut = re.findall(intPatt, shIntStatusOut)
                authLog.info(f"The following interfaces were found under the command: {shIntStatus}\n{shIntStatusOut}")
                if shIntStatusOut:
                    for interface in shIntStatusOut:
                        interface = interface.strip()
                        print(f"INFO: Checking configuration for interface {interface} on device {validDeviceIP}")
                        authLog.info(f"Checking configuration for interface {interface} on device {validDeviceIP}")
                        interfaceOut = sshAccess.send_command(f'show run int {interface}')

                        if discardPatt in interfaceOut:
                            authLog.info(f"Interface {interface} was discarded on device: {validDeviceIP}.")
                        else:
                            authLog.info(f"Interface {interface} will be modified with Dot1X config on device: {validDeviceIP}")
                            print(f"INFO: Interface {interface} will be modified with Dot1X config on device: {validDeviceIP}")
                            intList.append(interface)
                
                for intAP in intList:
                    intAPOut = sshAccess.send_command(f'show run int {intAP}')
                    if "2256" in intAPOut:
                        intConfigAP[0] = f'int {intAP}'
                        intConfigAPOut = sshAccess.send_config_set(intConfigAP)
                    else:
                        intConfigHosts[0] = f'int {intAP}'
                        intConfigHostsOut = sshAccess.send_config_set(intConfigHosts)
                        intHostsOut.append(intAP)
                
                showAccessVlanOut = sshAccess.send_command(f'show run int {intHostsOut[0]} | include switchport access vlan')
                showAccessVlanOut = showAccessVlanOut.replace('switchport access vlan', '')
                showAccessVlanOut = showAccessVlanOut.strip()

                for int in intList:
                    authVlanOut = sshAccess.send_command(f'authentication event server dead action authorize vlan {showAccessVlanOut}')

                try:
                    print(f"INFO: Adding Dot1x Config to device: {validDeviceIP}")
                    dot1xConfigOut = sshAccess.send_config_set(dot1xConfig)
                    print(f"INFO: Successfully added Dot1x config to device: {validDeviceIP}")
                    authLog.info(f"Successfully added Dot1x config to device: {validDeviceIP}")

                    with open(f"Outputs/{validDeviceIP}_Dot1x.txt", "a") as file:
                        file.write(f"User {username} connected to device IP {validDeviceIP}\n\n")
                        file.write(f"{shHostnameOut}\n{dot1xConfigOut}")

                except Exception as error:
                    print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
                    authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}")
                    authLog.debug(traceback.format_exc(),"\n")

        except Exception as error:
            print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
            authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}")
            authLog.debug(traceback.format_exc(),"\n")
            with open(f"failedDevices.txt","a") as failedDevices:
                failedDevices.write(f"User {username} connected to {validDeviceIP} got an error.\n")
        
        finally:
            print("Outputs and files successfully created.\n")
            print("For any erros or logs please check authLog.txt\n")