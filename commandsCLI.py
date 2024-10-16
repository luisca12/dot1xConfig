from netmiko import ConnectHandler
from log import authLog

import traceback
import threading
import time
import re
import os

shIntStatus = "show interface status"
shHostname = "show run | i hostname"
shIntSDW = "show int des | inc sdw|SDW"
interface = ''
shRun = "show run"

clearSession = "clear authentication sessions"

validationCommands= [
    'do show vlan br',
    'do show ip dhcp snooping binding',
    'do show authentication sessions'
]

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
    'aaa authentication dot1x default group ISE_SERVERS',
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
    'exit',
    'ip radius source-interface Loopback0',
    'ip access-list extended ACL-LOW-IMPACT',
    'remark DHCP, DNS, ICMP',
    'permit udp any eq bootpc any eq bootps',
    'permit udp any any eq domain',
    'permit tcp any any eq domain',
    'permit udp any any eq 389',
    'permit tcp any any eq 389',
    'remark Allow Microsoft Ports',
    'permit tcp any any eq 88',
    'permit udp any any eq 88',
    'permit icmp any any',
    'permit udp any any eq ntp',
    'remark PXE / TFTP',
    'permit udp any any eq tftp',
    'permit udp any eq 4011 any',
    'permit udp any any eq 4011',
    'permit udp any range 2070 2080 any',
    'permit udp any any range 2070 2080',
    'remark Drop all the rest',
    'deny ip any any',
    'aaa accounting exec default start-stop group TACACS-Servers',
    'aaa accounting commands 15 default start-stop group TACACS-Servers',
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
    'dot1x system-auth-control'
]

# Regex Patterns
intPatt = r'[a-zA-Z]+\d+\/(?:\d+\/)*\d+'
discardPatt = re.compile(r'(ip address \d+\.\d+\.\d+\.\d+)|(no switchport)|(switchport mode (?!access))|(switchport access vlan (1001|1101|1103|1193))|(shutdown)|(vrf forward)')

def dot1x(validIPs, username, netDevice):
    # This function is to take a show run

    validIPs = [validIPs]
    for validDeviceIP in validIPs:
        intList = []
        intHostsOut = []
        intConfigAPList = []
        intConfigHostsList = []
        authVlanList = []
        intConfigAPstr = ""
        intConfigHostsstr = ""

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
                shHostnameOut = shHostnameOut.split(' ')[1]
                shHostnameOut = shHostnameOut + "#"

                validationCommandsOut = sshAccess.send_config_set(validationCommands)
                authLog.info(f"Automation successfully ran the below commands:\n{validationCommandsOut}")

                print(f"INFO: Taking a show run for device: {validDeviceIP}")
                authLog.info(f"Taking a show run for device: {validDeviceIP}")
                shRunOut = sshAccess.send_command(shRun)
                authLog.info(f"Successfully ran the command {shRun} on device: {validDeviceIP}")

                with open(f"Outputs/Show Run before NAC Config for device {validDeviceIP}.txt", "a") as file:
                    file.write(f"User {username} connected to device IP {validDeviceIP}:\n\n")
                    file.write(f"- Below is the validation:\n{validationCommandsOut}\n\n")
                    file.write(f"- Below is the show run before all new configuration:\n")
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
                authLog.info(f"The following interfaces for device {validDeviceIP} were found under the command: {shIntStatus}\n{shIntStatusOut}")
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
                            authLog.info(f"The following interfaces will be modified with Dot1x config for device {validDeviceIP}:\n{intList}")

                for intAP in intList:
                    intAPOut = sshAccess.send_command(f'show run int {intAP}')
                    if "2256" in intAPOut:
                        print(f"INFO: Configuring interface {intAP} on device {validDeviceIP} with Dot1x - Access Point")
                        authLog.info(f"String 2256 was found under \"show run int {intAP}\" for device {validDeviceIP}")
                        intConfigAP[0] = f'int {intAP}'
                        intConfigAPOut = sshAccess.send_config_set(intConfigAP)
                        authLog.info(f"Applied the below configuration to interface {intAP} on device {validDeviceIP}\n{intConfigAPOut}")
                        intConfigAPList.append(intConfigAPOut)
                    else:
                        print(f"INFO: Configuring interface {intAP} on device {validDeviceIP} with Dot1x - Access Port")
                        authLog.info(f"String 2256 was NOT found under \"show run int {intAP}\" for device {validDeviceIP}")
                        intConfigHosts[0] = f'int {intAP}'
                        intConfigHostsOut = sshAccess.send_config_set(intConfigHosts)
                        authLog.info(f"Applied the below configuration to interface {intAP} on device {validDeviceIP}\n{intConfigHostsOut}")
                        intConfigHostsList.append(intConfigHostsOut)
                        intHostsOut.append(intAP)

                for interfaceList in intList:
                    showAccessVlanOut = sshAccess.send_command(f'show run int {interfaceList} | include switchport access vlan')
                    authLog.info(f"Automation ran the command \"show run int {interfaceList} | include switchport access vlan\" for device {validDeviceIP}")
                    showAccessVlanOut = showAccessVlanOut.replace('switchport access vlan', '')
                    showAccessVlanOut = showAccessVlanOut.strip()

                    authLog.info(f"Found the following data VLAN: {showAccessVlanOut} on interface {interfaceList} for device {validDeviceIP}")
                    print(f"INFO: Found the following data VLAN: {showAccessVlanOut} on interface {interfaceList} for device {validDeviceIP}")

                    authVlan = [
                        f'int {interfaceList}',
                        f'authentication event server dead action authorize vlan {showAccessVlanOut}',
                        f'device-tracking attach-policy DEVTRK'
                    ]

                    authVlanOut = sshAccess.send_config_set(authVlan)
                    authLog.info(f"Successfully configured the interface {interfaceList} on device {validDeviceIP} with the below command:\n"
                                f"{authVlanOut}")
                    print(f"INFO: Configured {interfaceList} on device {validDeviceIP} with the below command:\n{authVlanOut}")
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

                clearSessionOut = sshAccess.send_command(clearSession)
                authLog.info(f"Successfully cleared the authentication sessions on device {validDeviceIP}, {clearSessionOut}")

                time.sleep(15)

                validationCommandsOut1 = sshAccess.send_config_set(validationCommands)
                authLog.info(f"Automation successfully ran the below commands:\n{validationCommandsOut}")

                with open(f"Outputs/NAC Configurations applied to device {validDeviceIP}.txt", "a") as file:
                    file.write(f"User {username} connected to device IP {validDeviceIP}, configuration applied:\n\n")
                    file.write(f"- Below are the Post validation commands:\n{validationCommandsOut1}\n\n")
                    file.write(f"- Below is all the configuration applied:\n")
                    file.write(f"{shHostnameOut}\n{dot1xConfigOut}\n")
                    file.write(f"\n- Below is the config applied to all ports with Access Points:\n")
                    file.write(f"{shHostnameOut}\n{intConfigAPstr}\n")
                    file.write(f"\n- Below is the config applied to all ports with Hosts connected:\n")
                    file.write(f"{shHostnameOut}\n{intConfigHostsstr}\n")
                    file.write(f"\n- Below is the config applied to all ports:\n")
                    file.write(f"{shHostnameOut}\n{authVlanstr}")
                
                print(f"INFO: Taking a show run after all the changes for device: {validDeviceIP}")
                authLog.info(f"Taking a show run after all the changes for device: {validDeviceIP}")
                shRunOutAfter = sshAccess.send_command(shRun)
                authLog.info(f"Successfully ran the command {shRun} on device: {validDeviceIP}")

                with open(f"Outputs/Show Run after NAC config for device {validDeviceIP}.txt", "a") as file:
                    file.write(f"User {username} connected to device IP {validDeviceIP}:\n\n")
                    file.write(f"- Below is the show run of the new configuraiton:\n")
                    file.write(f"{shHostnameOut}{shRun}\n{shRunOutAfter}\n")
                    authLog.info(f"Successfully saved the running config after the Dot1x change for device: {validDeviceIP}")
                
            print(f"Outputs and files successfully created for device {validDeviceIP}.\n")
            print("For any erros or logs please check Logs -> authLog.txt\n")

        except Exception as error:
            print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
            authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}")
            authLog.error(traceback.format_exc())
            with open(f"Devices that failed to apply config.txt","a") as failedDevices:
                failedDevices.write(f"User {username} connected to {validDeviceIP} got an error: {error}\n")      

def dot1xThread(validIPs, username, netDevice):
    threads = []

    for validDeviceIP in validIPs:
        thread = threading.Thread(target=dot1x, args=(validDeviceIP, username, netDevice))
        thread.start()
        authLog.info(f"Thread {thread} started.")
        threads.append(thread)
        authLog.info(f"Thread {thread} appended to threads: {threads}")

    for thread in threads:
        thread.join()