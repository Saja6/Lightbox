import subprocess
import sys
import time

def exitthis(key):
    if key == keyboard.Key.Esc: sys.exit(0)
    
if __name__ == "__main__":
    print("::: Starting Application Installer...\n")
    while True:
        print("Do you want to...")
        print(" 1) Search for a package?\n 2) Install a package?\n 3) Exit?")
        entry = input("Enter a number corresponding to an action: ")
        if entry == "1":
            packages = input("Enter software names for search (no commas, spaced entries): ")
            rawList = packages.split()
            command = ["sudo", "apt", "search"]
            for package in rawList: command.append(package)
            print("::: Searching APT database for packages...")
            try:
                subprocess.run(command, check = True)
            except subprocess.CalledProcessError as e:
                print(f"::: Error while searching for packages: {e}")
            print("::: Finished.")
        elif entry == "2":
            packages = input("Enter software names for installation (no commas, spaced entries): ")
            rawList = packages.split()
            command = ["sudo", "apt", "install"]
            for package in rawList: command.append(package)
            print("::: Searching APT database for packages...")
            try:
                subprocess.run(command, check = True)
            except subprocess.CalledProcessError as e:
                print(f"::: Error while installing packages: {e}")
            print("::: Finished.")
        elif entry == "3": sys.exit(0)
        else: print(f"::: Command not found: {entry}")
