
import sys
import os
from platform import system as get_os

def find_hosts_file_location():

    if get_os() == "Windows":
        return "C:\\Windows\\System32\\drivers\\etc\\hosts"
    return "/etc/hosts"

def add_to_blocklist(website):
    hosts_file = find_hosts_file_location()
    localhost_ip = "127.0.0.1"   # Adding this ip so that the computer can never access the website's server
    
    if website.startswith("www."):
        non_www_version = website[4:]
        www_version = website
    else:
        non_www_version = website
        www_version = "www." + website
    
    try:
        # Checking if already blocked
        with open(hosts_file, 'r') as f:
            current_content = f.read()
            if website in current_content:
                print(f"{website} is already blocked")
                return
        
        # Writing website name with local ip 
        with open(hosts_file, 'a') as f:
            f.write(f"\n{localhost_ip} {non_www_version}\n")
            f.write(f"{localhost_ip} {www_version}\n")
        
        print(f"Successfully blocked {website} and {www_version}")
        
    except IOError as e:
        if "Permission denied" in str(e):
            print("Need adminnistrator priviledges")
        else:
            print(f"error : {e}")

def remove_from_blocklist(website):
    hosts_file = find_hosts_file_location()
    
    try:

        with open(hosts_file, 'r') as f:
            lines = f.readlines()
        
        new_lines = []
        for line in lines:
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("#"):
                new_lines.append(line)  # Keep comments
                continue
            
            # Skip if line contains the domain and write only the other ones
            if (
                f"127.0.0.1 {website}" in stripped_line or
                f"127.0.0.1 www.{website}" in stripped_line
            ):
                continue
            new_lines.append(line)
        
        # Write back
        with open(hosts_file, 'w') as f:
            f.writelines(new_lines)
        
        print(f"Unblocked {website} (and www.{website} if present)")
    
    except PermissionError:
        print("Need adminnistrator priviledges")
    except Exception as e:
        print(f"error : {e}")



def show_help():

    print("Example for syntax")
    print("  blocker.py block example.com    -To Block a website")
    print("  blocker.py unblock example.com - To Unblock a website")
    print("\n Note: Need administrator privileges")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        show_help()
        sys.exit(1)
    
    command = sys.argv[1].lower()
    site = sys.argv[2].strip()
    
    if command == "block":
        add_to_blocklist(site)
    elif command == "unblock":
        remove_from_blocklist(site)
    else:
        show_help()
