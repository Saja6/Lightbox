import subprocess
import sys
import time

def exitthis(key):
    if key == keyboard.Key.Esc: sys.exit(0)
    
if __name__ == "__main__":
    print("::: Starting Application Uninstaller...\n")
    while True:
        print("Do you want to...")
        print(" 1) Uninstall a package?\n 2) Exit?")
        entry = input("Enter a number corresponding to an action: ")
        if entry == "1":
            packages = input("Enter software names for uninstallation (no commas, spaced entries): ")
            rawList = packages.split()
            doAutoremove = input("Do you want to autoremove any unneeded packages after this uninstall? [Y/n]: ")
            command = ["sudo", "apt", "purge"]
            for package in rawList: command.append(package)
            print("::: Searching APT database for packages...")
            try:
                subprocess.run(command, check = True)
            except subprocess.CalledProcessError as e:
                print(f"::: Error while uninstalling packages: {e}")
            if doAutoremove == "Y" or doAutoremove == "y":
                try:
                    subprocess.run(["sudo", "apt", "autoremove"], check = True)
                except subprocess.CalledProcessError as e:
                    print(f"::: Error while autoremoving unneeded packages: {e}")
                print("::: Finished.")
        elif entry == "2": sys.exit(0)
        else: print(f"::: Command not found: {entry}")

