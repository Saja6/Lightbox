# Copyright 2026 Saja6: https://github.com/Saja6
import hashlib
import json
import os
import sys
import datetime
# we will walk each directory in the list of targets recursively and compute a hash for each file inside it
#   @param: the list of user-defined directories to compute hashes for and the hash function to use.
#   @return: the modified hashMap variable containing the
#       hashes relevant to each file used in each
#       directory located in targets. if targets is empty,
#       computeHashes() will return an empty hashMap.
def computeHashes(targets, hashFunction):
    print("🕒 ::: Computing hashes...")
    hashMap = {}  # here, a file path will be mapped to its corresponding computed hash
    # here is a map of supported hash functions. We will search for the one to use based off the hash function given.
    hashers = {
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha384": hashlib.sha384
    }
    if targets is None: return {}
    myhash = hashers.get(hashFunction)
    if myhash is None: raise ValueError(f"🔴 ::: Unsupported or invalid hash function: {hashFunction}")
    for target in targets:
        for (root, directories, files) in os.walk(target, topdown=True):
            for fileName in files:
                try:
                    hasher = myhash()
                    filePath = os.path.join(root, fileName)  # make sure we got the full path!
                    print(f"🕒 ::: Computing {hashFunction} checksum for {fileName}...")
                    with open(filePath, 'rb') as f:
                        chunk = f.read(8192)
                        while chunk:  # as long as we can read from the file, update the hash as input text grows
                            hasher.update(chunk) # update the hash based off the new piece of data we got.
                            chunk = f.read(8192)
                    fileHash = hasher.hexdigest()  # allow the hash to be in hexadecimal for safety
                    hashMap[filePath] = fileHash  # next, make a new entry in the hashMap
                    print(f"✅ ::: Hash calculated for {fileName}...")
                except (FileNotFoundError, PermissionError): continue
    print("✅ ::: Hash computation complete.")
    return hashMap

# we will write our baseline hashMap results to a JSON file.
#   @param: hashMap and the hash function used to distinguish its hashes
#   @return: none.
def writeMap(hashMap, hashFunction):
    print("🕒 ::: Saving hashes to file...")
    with open(f"hashes{hashFunction}.json", "w") as f:
        json.dump(hashMap, f, indent = 4)
    print("✅ ::: Hashes written successfully.")


# we will load the map from the file
#    @param: the hash function used during computation to identify it as a file containing hashes from a specific function.
#    @return: the hashMap read from the file.
def loadMap(hashFunction):
    try:
        with open(f"hashes{hashFunction}.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        print("⚠️ ::: JSON file is empty or invalid. Stopping.")
        sys.exit(1)

# we will compare the 2 hashMaps to verify file integrity and to detect new or deleted entries.
#   @param: 2 hashMaps, and old and new one. The old map contains the hashes that exist in the JSON file,
#       whereas the new map contains the hashes generated after writing the old map's hashes to the file.
#   @return: a tuple containing the type of action, the path to file, and the old hash and path stored on
#       file in the new map (if needed).

def compareHashes(oldMap, newMap):
    print("🕒 ::: Comparing hashes to stored hashes...")
    changes = []
    for path, oldHash in oldMap.items():  # go through the hash and file path in the old map
        if path not in newMap:  # we can't find the path; it was deleted
            changes.append((path, oldHash, None, "DELETED"))
        elif newMap[path] != oldHash:  # we found different hash values; file was changed
            changes.append((path, oldHash, newMap[path], "MODIFIED"))
    for path in newMap:  # go through each path in the new map
        if path not in oldMap:  # we can't find it in the old map; must be new.
            changes.append((path, None, newMap[path], "NEW"))
    return changes


if __name__ == '__main__':
    # default configuration if none is found:
    config = {
        "hash-function": "sha256",
        "directories": []
    }
    try:
        with open("fict.conf", "r") as f:
            for line in f:
                line = line.strip()  # remove whitespaces before and after line
                if not line or line.startswith("#"): continue  # ignore comments or blank lines
                if "=" in line:
                    key, val = line.split("=", 1)  # separate the key from the value in flip.conf
                    config[key.strip()] = val.strip()
    except FileNotFoundError:
        print("⚠️ ::: fict.conf not found. Using default configurations...")
    # below configurations may end up as default if flip.conf was not found!
    hashFunction = config.get("hash-function", "sha256")
    targetDirectories = [directory.strip() for directory in config.get("directories", "").split(",") if directory.strip()]
    print(
        "::: Welcome to FICT, the File Integrity Checking Tool!\n----------------------------------------------------------------\n❗ "
        "Note: this tool is designed for use on folders containing confidential,\n"
        "personal, or sensitive information that is only accessible by authorized personnel.\n"
        "Using this tool on folders containing frequently-modified or edited content may cause\n"
        "this tool to produce many false positives.\n"
        "::: Your current configuration is:\n"
        f"\tHash function to use: {hashFunction}\n"
        f"\tDirectories: {targetDirectories}\n")
    existingDirectories = [] # a list which will contain only existing directories the user inputs.
    for directory in targetDirectories:
        if not os.path.isdir(directory): print(f"🔴 ::: No such directory: {directory}")
        else: existingDirectories.append(directory)
    if not existingDirectories:
        print("🔴 ::: No valid directories provided. Exiting.")
        sys.exit(1)
    baselineMap = loadMap(hashFunction)  # load a baseline map then compute the new hashes below.
    try:
        newMap = computeHashes(existingDirectories, hashFunction)
    except ValueError:
        print("🔴 ::: Invalid hash function provided. Exiting.")
        sys.exit(1)
    if not baselineMap:
        print("⚠️ No baseline found. Creating baseline...")
        writeMap(newMap, hashFunction)
        print("✅ Baseline created.")
        sys.exit(0)
    results = compareHashes(baselineMap, newMap)
    timestamp = datetime.datetime.now().strftime("%B %d %Y at %I:%M:%S %p")
    entries = [] # list of all entries for JSON file. If no changes are detected, it will be empty.
    with open(f"results{hashFunction}.json", "a") as f:
        if results:
            for result in results:
                filepath, oldhash, newhash, action = result
                entry = {
                    "File": filepath,
                    "OldHash": oldhash,
                    "NewHash": newhash,
                    "Action": action
                }
                entries.append(entry)
                line = (f"🚨::: File changes detected:\n\tAction: {action}\n\tFile path: {filepath}\n\tOld hash: {oldhash}\n\tNew hash: {newhash}\n\tTime detected:{timestamp}")
                print(line)
            json.dump(entries, f, indent = 4)
        else:
            print(f"✅ File integrity check complete! No outstanding changes detected at {timestamp}.")
            # add a disclaimer about the use of md5 or sha1!
    if hashFunction == "sha1" or hashFunction == "md5":
        print(f"\n❗::: WARNING: You have chosen {hashFunction} as the hash function to use.\n"
              "Please be aware that this hash function is cryptographically broken and\n"
              "no longer considered reliable as it produces the same hashes for 2 different things\n"
              f"If you absolutely need to use {hashFunction} as hash function, ignore this message.")
