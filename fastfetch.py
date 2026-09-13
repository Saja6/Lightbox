import subprocess
import time
from pynput import keyboard
import sys

def exitthis(key):
    if key == keyboard.Key.Esc: sys.exit(0)
    
if __name__ == "__main__":
    print("::: Getting system information...")
    try:
        subprocess.run( ["sudo", "fastfetch"],check = True)
    except subprocess.CalledProcessError as e:
        print(f"::: Command failed with exit code {e.returncode}")
    print("::: Press ESC to exit.")
    listener = keyboard.Listener(on_press = exitthis)
    listener.start()
    listener.join()

