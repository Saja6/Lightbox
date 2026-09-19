# Copyright 2026 Saja6: https://github.com/Saja6
import hashlib
import os
import sys
import time
import datetime
targets = ["DIRECTORIES"] # the directories we will compute file hashes inside are here (add yours).
# we will walk each directory in the list of targets recursively and compute a hash for each file inside it
#   @param: none
#   @return: the modified hashMap variable containing the
#       hashes relevant to each file used in each
#       directory located in targets. if targets is empty,
#       computeHashes() will return an empty hashMap.
def computeHashes():
    print("🕒 ::: Computing hashes...")
    hashMap = {}  # here, a file path will be mapped to its corresponding computed hash
    if targets == []: return {}
    for thisTarget in targets: # for each directory, we will walk recursively through it
        for (root, directories, files) in os.walk(thisTarget, topdown = True):
            for fileName in files:
                try:
                    hasher = hashlib.sha256() # compute an SHA256 hash
                    filePath = os.path.join(root, fileName) # make sure we got the full path!
                    print(f"🕒 ::: Computing hash for {fileName}...")
                    with open(filePath, 'rb') as f:
                        chunk = f.read(8192)
                        while chunk: # as long as we can read from the file, update the hash as input text grows
                            hasher.update(chunk)
                            chunk = f.read(8192)
                    fileHash = hasher.hexdigest() # allow the hash to be in hexadecimal for safety
                    hashMap[filePath] = fileHash # next, make a new entry in the hashMap
                    print(f"✅ ::: Hash calculated for {fileName}...")
                except (FileNotFoundError, PermissionError):
                    continue
    print("✅ ::: Hash computation complete.")
    return hashMap

# we will write our baseline hashMap results to a file called hashes.log.
#   @param: hashMap
#   @return: none.
def writeMap(map):
    print("🕒 ::: Writing hashes to hashes.log...")
    with open('hashes.log', 'w') as f:
        for fileName, hash in map.items():
            f.write(fileName + ' | ' + hash + '\n')

# we will load the map from the file 
#    @param: nothing.
#    @return: the hashMap read from the file.
def loadMap():
    hashMap = {}
    try:
        with open("hashes.log", "r") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line: continue
                fileName, fileHash = line.split(" | ", 1)
                hashMap[fileName] = fileHash
    except FileNotFoundError: return {}
    return hashMap

# we will compare the 2 hashMaps to verify file integrity and to detect new or deleted entries.
#   @param: 2 hashMaps, and old and new one. The old map contains the hashes that exist in hashes.log,
#       whereas the new map contains the hashes generated after writing the old map's hashes to the file.
#   @return: a tuple containing the type of action, the path to file, and the old hash and path stored on
#       file in the new map (if needed).
    
def compareHashes(oldMap, newMap):
    print("🕒 ::: Comparing hashes to stored hashes...")
    changes = []
    for path, oldHash in oldMap.items(): # go through the hash and file path in the old map
        if path not in newMap: # we can't find the path; it was deleted
            changes.append((path, oldHash, None, "DELETED"))
        elif newMap[path] != oldHash: # we found different hash values; file was changed
            changes.append((path, oldHash, newMap[path], "MODIFIED"))
    for path in newMap: # go through each path in the new map
        if path not in oldMap: # we can't find it in the old map; must be new.
            changes.append((path, None, newMap[path], "NEW"))
    return changes

if __name__ == '__main__':
    print("::: Welcome to FICT, the File Integrity Checking Tool!\n----------------------------------------------------------------\n❗ "
          "Note: this tool is designed for use on folders containing confidential,\n"
          "personal, or sensitive information that is only accessible by authorized personnel.\n"
          "Using this tool on folders containing frequently-modified or edited content may cause\n"
          "this tool to produce many false positives. If using this tool on a suitable set of information,\n"
          "please enter 'C' to continue with the file integrity check for your required directories.\n"
          "Otherwise, please press any other key to exit the program.\n")
    entry = input("Continue? [C/c]: ")
    if entry.lower() == "c":
        baselineMap = loadMap() # load a baseline map then compute the new hashes below.
        newMap = computeHashes()
        if not baselineMap:
            print("⚠️ No baseline found. Creating baseline...")
            writeMap(newMap)
            print("✅ Baseline created.")
            sys.exit(0)
        results = compareHashes(baselineMap, newMap)
        timestamp = datetime.datetime.now().strftime("%B %d %Y at %I:%M:%S %p")
        with open("results.rpt", "a") as f:
            if results:
                for result in results:
                    filepath, oldhash, newhash, action = result
                    print("------------------------------------------------")
                    line = (f"🚨::: File changes detected | {action} |{filepath} | {oldhash} | {newhash} on {timestamp}")
                    print(line)
                    f.write(line + "\n")
            else:
                line = (f"✅ File integrity check complete! No outstanding changes detected at {timestamp}.")
                print(line)
                f.write(line + "\n") 
    else: sys.exit(1)
