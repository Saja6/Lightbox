import subprocess
import time
if __name__ == "__main__":
    print("::: Updating software repositories...")
    try:
        subprocess.run( ["sudo", "apt", "update"],check = True)
        print("::: Successfully updated software repositories.")
    except subprocess.CalledProcessError as e:
        print(f"::: Update command failed with exit code {e.returncode}")
    try:
        subprocess.run( ["sudo", "apt", "full-upgrade"],check = True)
        print("::: Upgrade proccess call complete.")
    except subprocess.CalledProcessError as e:
        print(f"::: Update command failed with exit code {e.returncode}")
    print("::: Exiting in 3 seconds...")
    time.sleep(3)
