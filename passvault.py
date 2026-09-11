# Copyright 2026 Saja6: https://github.com/Saja6

import getpass
import hashlib
import os
import sys
from hmac import compare_digest
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import json

# global variables
databaseLocation = "passwordvault.json"
keyLocation = "master.dat"
entries = {}

# We will create our master password and derive a key from it using PBKDF2,
# which will live in our desired key file.
# @param: nothing.
# @return: nothing.
def createPassword():
    password = getpass.getpass("::: Create a master password: ")
    confirmation = getpass.getpass("::: Confirm your master password: ")
    if password != confirmation:
        print("::: Passwords do not match.")
        return
    salt = os.urandom(16)
    key = PBKDF2(password, salt, dkLen = 32, count = 1000000, hmac_hash_module = SHA256)
    hashedKey = hashlib.sha256(key).digest()
    with open(keyLocation, "wb") as f:
        f.write(salt)
        f.write(hashedKey)
    print("::: Password created.")

# We will verify the password to see if it is a match to our master password
# By running it through the PBKDF2 function as well and comparing their digests.
# @param: nothing.
# @return: The correct password if there is a match, None otherwise.
def verifyPassword():
    password = getpass.getpass("::: Enter your password: ")
    with open(keyLocation, "rb") as f:
        salt = f.read(16)
        storedHash = f.read(32)
    key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)
    calculatedHash = hashlib.sha256(key).digest()
    if compare_digest(calculatedHash, storedHash): return key
    return None

# We will add a new password and username which are mapped to a unique identifier.
# @param: The desired username, password, identifier, and key (for encryption)
# @return: Nothing.
def addPassword(username, password, identifier, key):
    if identifier in entries:
        print(f"::: User with identifier \"{identifier}\" already exists.")
        return
    if not identifier.strip():
        print("::: Identifier cannot be empty.")
        return
    passCipher = AES.new(key, AES.MODE_GCM)
    passCiphertext, ptag = passCipher.encrypt_and_digest(password.encode("utf-8"))
    userCipher = AES.new(key, AES.MODE_GCM)
    userCiphertext, utag = userCipher.encrypt_and_digest(username.encode("utf-8"))
    newEntry = {
        "U": userCiphertext.hex(),
        "P": passCiphertext.hex(),
        "UN": userCipher.nonce.hex(),
        "PN": passCipher.nonce.hex(),
        "UT": utag.hex(),
        "PT": ptag.hex()
    }
    entries[identifier] = newEntry
    json.dump(entries, open(databaseLocation, "w"), indent = 4)

# We will remove a user and all its associated information.
# @param: The identifier, which is mapped to a username and password
# @return: Nothing.
def removeUser(identifier):
    if identifier in entries:
        del entries[identifier]
        with open(databaseLocation, "w") as f: json.dump(entries, f, indent=4)
        print(f"::: Removed all data associated with identifier \"{identifier}\".")
        return
    print(f"::: User with identifier \"{identifier}\" not found.")

# We will aedit the password of an existing user.
# @param: The identifier (for searching the database), and the key for encrypting the new password.
# @return: Nothing.
def editPassword(identifier, key):
    if identifier not in entries:
        print("::: User not found.")
        return
    newPassword = getpass.getpass("::: Enter a new password: ")
    passCipher = AES.new(key, AES.MODE_GCM)
    passCiphertext, tag = passCipher.encrypt_and_digest(newPassword.encode("utf-8"))
    entries[identifier]["P"] = passCiphertext.hex()
    entries[identifier]["PN"] = passCipher.nonce.hex()
    entries[identifier]["PT"] = tag.hex()
    with open(databaseLocation, "w") as f: json.dump(entries, f, indent = 4)
    print(f"::: Password for {identifier} has been updated.")

# We will list all usernames and password with their respective identifiers.
# @param: The key for decrypting each password stored.
# @return: Nothing.
def listPasswords(key):
    if os.path.exists(databaseLocation):
        print("::: Database contents: ")
        for identifier, entry in entries.items():
            encryptedPassword = bytes.fromhex(entry["P"])
            encryptedUsername = bytes.fromhex(entry["U"])
            ptag = bytes.fromhex(entry["PT"])
            utag = bytes.fromhex(entry["UT"])
            unonce = bytes.fromhex(entry["UN"])
            pnonce = bytes.fromhex(entry["PN"])
            passCipher = AES.new(key, AES.MODE_GCM, nonce = pnonce)
            usernameCipher = AES.new(key, AES.MODE_GCM, nonce = unonce)
            try:
                password = passCipher.decrypt_and_verify(encryptedPassword, ptag).decode("utf-8")
                username = usernameCipher.decrypt_and_verify(encryptedUsername, utag).decode("utf-8")
                print(f"::: Identifier: {identifier} | Username: {username} | Password: {password}")
            except ValueError: print(f"::: {identifier}: Authentication failed.")

if __name__ == "__main__":
    if not os.path.exists(keyLocation): createPassword() # make a password if its data file isn't there.
    sessionKey = verifyPassword()
    if sessionKey is None:
        print("::: Incorrect password. Access denied.")
        sys.exit(1)
    if os.path.exists(databaseLocation):
        with open(databaseLocation, "r") as f:
            entries = json.load(f) # re-load the state for the global entries variable.
    else: entries = {}
    print("::: Welcome to PassVault, a stupidly simple, secure password manager.")
    print("---------------------------------------------------")
    print("::: Your passwords will NEVER be stored raw. Your passwords will be\n"
          "::: fully encrypted and unreadable to any unauthorized users on this device.")
    print("---------------------------------------------------")
    print("::: Enter 'help' to see a list of available commands.")
    while True:
        command = input("PassVault> ")
        commands = ["add", "remove", "edit", "help", "exit", "list"]
        if command not in commands:
            print(f"Invalid command: {command}")
            continue
        if command == "add":
            userToAdd = input("::: Enter a username for this entry: ")
            passToAdd = getpass.getpass("::: Enter the password for this user: ")
            identifierToAdd = input("Enter an identifier for this entry: ")
            addPassword(userToAdd, passToAdd, identifierToAdd, sessionKey)
        elif command == "remove":
            identifier = input("::: Enter the identifier whose information will be removed: ")
            removeUser(identifier)
        elif command == "edit":
            identifier = input("::: Enter the identifier whose password will be changed: ")
            editPassword(identifier, sessionKey)
        elif command == "list": listPasswords(sessionKey)
        elif command == "help":
            print("::: Commands include: add, remove, edit, help, list, and exit")
            print("::: 'add': prompts the user to add a username, password, and nickname for the entered data.")
            print("::: 'remove': prompts the user to remove a nickname and its associated username and password.")
            print("::: 'edit': prompts the user to edit a username's password associated with a specific nickname.")
            print("::: 'help': displays this message.")
            print("::: 'list': displays all identifiers and their associated usernames and passwords.")
            print("::: 'exit': exits the program.")
        elif command == "exit": sys.exit(0)
