# This scripts extracts the password of saved wifi networks on a windows machine

import colorama
import subprocess
import sys

colorama.init(autoreset=True)

def return_profiles_and_passwords():
    networks_found = []
    networks_and_passwords = {}

    # Extract networks and save in list
    profiles = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True)
    found_profiles = profiles.stdout.split('\n')
    for line in found_profiles:
        if 'user profile' in line.lower():
            networks_found.append(line.split(':')[-1].strip())

    # Extract passwords and save in dictionary
    for network in networks_found:
        get_user_profile_command = 'netsh wlan show profiles ' + 'name='+'"'+network+'"' + ' key=clear'
        get_user_profile = subprocess.run(get_user_profile_command, shell=True, capture_output=True, text=True)
        user_profile = get_user_profile.stdout.split('\n')
        for line in user_profile:
            if 'key content' in line.lower():
                password = line.split(':')[-1].strip()
                networks_and_passwords[network] = password
    
    return networks_and_passwords

def main():
    if 'win' not in sys.platform:
            print("[-] Please run on a windows machine")
            exit()
    passwords_found  = return_profiles_and_passwords()
    print('\n\x1b[36m'+'[*] Networks and Passwords Found:\n')
    for network, password in passwords_found.items():
        print('  \x1b[93m' + network + ' : \x1b[92m' + password)
main()