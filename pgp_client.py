import os.path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

# we will generate an RSA public/private key pair using the below function.
# @param: none
# @return: nothing
def generateKeys():
    key = RSA.generate(2048)  # 2048-bit key
    private_key = key.export_key()  # export it as a private key and write it to file
    with open("private.pem", "wb") as f: f.write(private_key)
    public_key = key.publickey().export_key()  # do the same for a public key
    with open("public.pem", "wb") as f: f.write(public_key)
    print("Generated private and public keys successfully.")

# we will encrypt a file using AES. RSA will help encrypt the AES key.
# @param: the file to encrypt and the public key
# @return: nothing
def encryptFile(filepath, publickey):
    with open(filepath, "rb") as f: data = f.read()
    sessionKey = get_random_bytes(16)
    AESCipher = AES.new(sessionKey, AES.MODE_EAX)  # generate an AES cipher to encrypt text
    ciphertext, tag = AESCipher.encrypt_and_digest(data)  # encrypt the ciphertext using the data
    RSACipher = PKCS1_OAEP.new(publickey)  # generate an RSA Cipher and use it to encrypt the AES key
    encryptedAESKey = RSACipher.encrypt(sessionKey)  # encrypt the AES key using RSA
    output_filepath = filepath + ".enc"
    with open(output_filepath, "wb") as f: # write what we got.
        f.write(encryptedAESKey)
        f.write(AESCipher.nonce)
        f.write(tag)
        f.write(ciphertext)
    print(f"File encrypted successfully. Saved to {output_filepath}")

# we will decrypt our AES key using RSA and the file using AES
# @param: the file to encrypt and the private key
# @return: nothing
def decryptFile(filepath, privatekey):
    try:
        with open(filepath, "rb") as f:
            encryptedAESKey = f.read(256) # rad the encrypted AES key, nonce, tag, and ciphertext
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
        RSACipher = PKCS1_OAEP.new(privatekey) # derive RSA cipher from private key
        AESKey = RSACipher.decrypt(encryptedAESKey) # decrypt the AES key using it
        AESCipher = AES.new(AESKey, AES.MODE_EAX, nonce = nonce) # derive an AES cipher from the key
        decrypted_data = AESCipher.decrypt_and_verify(ciphertext, tag) # decrypt the data using AES.
        output = filepath.replace(".enc", "")
        with open(output, "wb") as out_file: out_file.write(decrypted_data)
        print(f"Decryption successful. Saved to {output}")
    except Exception as e:
        print(f"Decryption failed: {e}")

# we will append a digital signature to a file using a hash value.
# @param: the file to sign and the private key
# @return: nothing
def signFile(filepath, privatekey):
    with open(filepath, "rb") as f: data = f.read()
    hasher = SHA256.new(data) # make a new hash object
    signature = pkcs1_15.new(privatekey).sign(hasher) # now sign it using PKCS1_15
    signature_filepath = filepath + ".sig"
    with open(signature_filepath, "wb") as f: f.write(signature) # write the signature
    print(f"File signed. Signature has been saved to {signature_filepath}")

# we will verify the signature
# @param: the file encrypted, the signature file, and public key
# @return: nothing
def verifyFile(filepath, signature_path, publickey):
    try:
        with open(filepath, "rb") as f: data = f.read() # read our data from signature and data files
        with open(signature_path, "rb") as f: signature = f.read()
        hasher = SHA256.new(data)
        pkcs1_15.new(publickey).verify(hasher, signature) # verify the signature with our hasher
        print("Signature is valid.")
    except (ValueError, TypeError): print("Signature is invalid.")

# we will receive and process user input.
# @param: none
# @return: nothing
def getInput():
    command = input("Personal PGP> ")
    args = command.split()
    if not args: return
    if args[0] == "generate-keys": generateKeys()
    elif args[0] == "encrypt":
        if len(args) < 3:
            print("Usage: encrypt [filepath] [publickey_path]")
            return
        if not os.path.exists(args[1]):
            print("File doesn't exist.")
            return
        if not os.path.exists(args[2]):
            print("Public key doesn't exist.")
            return
        # import the public key below before encrypting a file.
        with open(args[2], "rb") as key: public_key = RSA.import_key(key.read())
        encryptFile(args[1], public_key)
    elif args[0] == "decrypt":
        if len(args) < 3:
            print("Usage: decrypt [filepath].enc [privatekey_path]")
            return
        if not os.path.exists(args[1]):
            print("File doesn't exist.")
            return
        if not os.path.exists(args[2]):
            print("Private key doesn't exist.")
            return
        # import the private key below before decrypting a file.
        with open(args[2], "rb") as key: private_key = RSA.import_key(key.read())
        decryptFile(args[1], private_key)
    elif args[0] == "sign":
        if len(args) < 3:
            print("Usage: sign [filepath] [privatekey_path]")
            return
        if not os.path.exists(args[1]):
            print("File doesn't exist.")
            return
        if not os.path.exists(args[2]):
            print("Private key doesn't exist.")
            return
        # import the private key below before signing a file.
        with open(args[2], "rb") as key: private_key = RSA.import_key(key.read())
        signFile(args[1], private_key)
    elif args[0] == "verify":
        if len(args) < 4:
            print("Usage: verify [filepath] [signature_path] [publickey_path]")
            return
        if not os.path.exists(args[1]):
            print("File doesn't exist.")
            return
        if not os.path.exists(args[2]):
            print("Signature file doesn't exist.")
            return
        if not os.path.exists(args[3]):
            print("Public key doesn't exist.")
            return
        # import the public key below before verifying a file.
        with open(args[3], "rb") as key: public_key = RSA.import_key(key.read())
        verifyFile(args[1], args[2], public_key)

if __name__ == "__main__":
    while True: getInput()

