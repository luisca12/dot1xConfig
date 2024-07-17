from netmiko import ConnectHandler
from log import authLog

import traceback
import re
import os

shIntStatus = "show interface status"
shHostname = "show run | i hostname"
interface = ''
shRun = "show run"

intList = []
intHostsOut = []
intConfigAPList = []
intConfigHostsList = []
authVlanList = []
intConfigAPstr = ""
intConfigHostsstr = ""


intPatt = r'[a-zA-Z]+\d+\/(?:\d+\/)*\d+'
discardPatt = re.compile(r'(ip address \d+\.\d+\.\d+\.\d+)|(no switchport)|(switchport mode (?!access))|(switchport access vlan (1001|1101|1103))|(shutdown)|(vrf forward)')

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
    'ip access-list extended ACL-DEFAULT',
    'permit ip any any',
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
    'device-sensor filter-list lldp list lldp-list',
    'tlv name system-name',
    'tlv name system-description',
    'device-sensor filter-list dhcp list dhcp-list',
    'option name host-name',
    'option name domain-name',
    'option name requested-address',
    'option name parameter-request-list',
    'option name class-identifier',
    'option name client-identifier',
    'device-sensor filter-list cdp list cdp-list',
    'tlv name device-name',
    'tlv name address-type',
    'tlv name capabilities-type',
    'tlv name platform-type',
    'tlv name native-vlan-type',
    'tlv number 34',
    'device-sensor filter-spec dhcp include list dhcp-list',
    'device-sensor filter-spec lldp include list lldp-list',
    'device-sensor filter-spec cdp include list cdp-list',
    'device-sensor accounting',
    'device-sensor notify all-changes',
    'device-tracking tracking auto-source',
    'device-tracking policy DEVTRK',
    'security-level glean',
    'tracking enable',
    'no protocol ndp',
    'no protocol dhcp6',
    'no protocol udp',
    'device-tracking policy DT_TRUNK',
    'trusted-port',
    'device-role switch',
    'no protocol udp',
    'dot1x system-auth-control'
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
                try:
                    sshAccess.enable()
                    shHostnameOut = sshAccess.send_command(shHostname)
                    authLog.info(f"User {username} successfully found the hostname {shHostnameOut}")
                    shHostnameOut = shHostnameOut.replace('hostname', '')
                    shHostnameOut = shHostnameOut.strip()
                    shHostnameOut = shHostnameOut + "#"

                    print(f"INFO: Taking a show run for device: {validDeviceIP}")
                    authLog.info(f"Taking a show run for device: {validDeviceIP}")
                    shRunOut = sshAccess.send_command(shRun)
                    authLog.info(f"Successfully ran the command {shRun} on device: {validDeviceIP}")

                    with open(f"Outputs/{validDeviceIP}_showRun_beforeConfig.txt", "a") as file:
                        file.write(f"User {username} connected to device IP {validDeviceIP}:\n\n")
                        file.write(f"{shHostnameOut}{shRun}\n{shRunOut}\n")
                        authLog.info(f"Successfully saved the running config before the Dot1x change for device: {validDeviceIP}")

                    print(f"INFO: Adding Dot1x Config to device: {validDeviceIP}")
                    dot1xConfigOut = sshAccess.send_config_set(dot1xConfig)
                    print(f"INFO: Successfully added Dot1x config to device: {validDeviceIP}")
                    authLog.info(f"Successfully added Dot1x config to device: {validDeviceIP}, config added:\n{dot1xConfigOut}")
                
                    print(f"INFO: Taking a \"{shIntStatus}\" for device: {validDeviceIP}")
                    shIntStatusOut = sshAccess.send_command(shIntStatus)
                    authLog.info(f"Automation successfully ran the command: {shIntStatus}")
                    shIntStatusOut = re.findall(intPatt, shIntStatusOut)
                    authLog.info(f"The following interfaces were found under the command: {shIntStatus}\n{shIntStatusOut}")
                    if shIntStatusOut:
                        for interface in shIntStatusOut:
                            interface = interface.strip()
                            print(f"INFO: Checking configuration for interface {interface} on device {validDeviceIP}")
                            authLog.info(f"Checking configuration for interface {interface} on device {validDeviceIP}:")
                            interfaceOut = sshAccess.send_command(f'show run int {interface}')
                            authLog.info(f"{interfaceOut}")
                            interfaceOut = interfaceOut.split('\n')
                            discardInt = False
            
                            for line in interfaceOut:
                                if discardPatt.search(line):
                                    authLog.info(f"Discarding interface {interface} due to line: {line}")
                                    discardInt = True
                                    break
                            
                            if discardInt:
                                print(f"INFO: Interface {interface} discarded.")
                                authLog.info(f"Interface {interface} was discarded on device: {validDeviceIP}.")
                            else:
                                print(f"INFO: Interface {interface} will be modified with Dot1X config on device: {validDeviceIP}")
                                authLog.info(f"Interface {interface} will be modified with Dot1X config on device: {validDeviceIP}")
                                intList.append(interface)

                    for intAP in intList:
                        intAPOut = sshAccess.send_command(f'show run int {intAP}')
                        if "2256" in intAPOut:
                            print(f"INFO: Configuring interface {intAP} with Dot1x - Access Point")
                            authLog.info(f"String 2256 was found under \"show run int {intAP}\" for device {validDeviceIP}")
                            intConfigAP[0] = f'int {intAP}'
                            intConfigAPOut = sshAccess.send_config_set(intConfigAP)
                            authLog.info(f"Applied the below configuration to interface {intAP} on device {validDeviceIP}\n{intConfigAPOut}")
                            intConfigAPList.append(intConfigAPOut)
                        else:
                            print(f"INFO: Configuring interface {intAP} with Dot1x - Access Port")
                            authLog.info(f"String 2256 was NOT found under \"show run int {intAP}\" for device {validDeviceIP}")
                            intConfigHosts[0] = f'int {intAP}'
                            intConfigHostsOut = sshAccess.send_config_set(intConfigHosts)
                            authLog.info(f"Applied the below configuration to interface {intAP} on device {validDeviceIP}\n{intConfigHostsOut}")
                            intConfigHostsList.append(intConfigHostsOut)
                            intHostsOut.append(intAP)

                    showAccessVlanOut = sshAccess.send_command(f'show run int {intHostsOut[0]} | include switchport access vlan')
                    authLog.info(f"Automation ran the command \"show run int {intHostsOut[0]} | include switchport access vlan\" for device {validDeviceIP}")
                    showAccessVlanOut = showAccessVlanOut.replace('switchport access vlan', '')
                    showAccessVlanOut = showAccessVlanOut.strip()
                    authLog.info(f"Found the following data VLAN: {showAccessVlanOut} on device {validDeviceIP}")
                    print(f"INFO: Found the following data VLAN: {showAccessVlanOut} on device {validDeviceIP}")

                    authVlan = [
                        f'int {interface}',
                        f'authentication event server dead action authorize vlan {showAccessVlanOut}',
                        f'device-tracking attach-policy DEVTRK'
                    ]

                    for interfaceList in intList:
                        authVlan[0] = f'int {interfaceList}'
                        authVlanOut = sshAccess.send_config_set(authVlan)
                        authLog.info(f"Successfully configured the interface {interfaceList} on device {validDeviceIP} with the below command:\n"
                                    f"{authVlanOut}")
                        print(f"INFO: Confiogured {interfaceList} on device {validDeviceIP} with the below command:\n{authVlanOut}")
                        authVlanList.append(authVlanOut)
                    
                    writeMemOut = sshAccess.send_command('write')
                    print(f"INFO: Running configuration saved for device {validDeviceIP}")
                    authLog.info(f"Running configuration saved for device {validDeviceIP}\n{shHostnameOut}'write'\n{writeMemOut}")

                    intConfigAPstr = " ".join(intConfigAPList)
                    intConfigHostsstr = " ".join(intConfigHostsList)
                    authVlanstr = " ".join(authVlanList)

                    intConfigAPstr.split('\n')
                    intConfigHostsstr.split('\n')
                    authVlanstr.split('\n')

                    with open(f"Outputs/{validDeviceIP}_Dot1x.txt", "a") as file:
                        file.write(f"User {username} connected to device IP {validDeviceIP}, configuration applied:\n\n")
                        file.write(f"{shHostnameOut}\n{dot1xConfigOut}\n")
                        file.write(f"\nBelow is the config applied to all ports with Access Points:\n")
                        file.write(f"{shHostnameOut}\n{intConfigAPstr}\n")
                        file.write(f"\nBelow is the config applied to all ports with Hosts connected:\n")
                        file.write(f"{shHostnameOut}\n{intConfigHostsstr}\n")
                        file.write(f"\nBelow is the config applied to all ports:\n")
                        file.write(f"{shHostnameOut}\n{authVlanstr}")
                    
                    print(f"INFO: Taking a show run after all the changes for device: {validDeviceIP}")
                    authLog.info(f"Taking a show run after all the changes for device: {validDeviceIP}")
                    shRunOutAfter = sshAccess.send_command(shRun)
                    authLog.info(f"Successfully ran the command {shRun} on device: {validDeviceIP}")

                    with open(f"Outputs/{validDeviceIP}_showRun_afterConfig.txt", "a") as file:
                        file.write(f"User {username} connected to device IP {validDeviceIP}:\n\n")
                        file.write(f"{shHostnameOut}{shRun}\n{shRunOutAfter}\n")
                        authLog.info(f"Successfully saved the running config after the Dot1x change for device: {validDeviceIP}")

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
            print(f"Outputs and files successfully created for device {validDeviceIP}.\n")
            print("For any erros or logs please check Logs -> authLog.txt\n")