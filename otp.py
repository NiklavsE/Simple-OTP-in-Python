from os import urandom

def doEncryption(fileToEncrypt, padFileName, encryptedFileName):
    try:
        with open(fileToEncrypt, "rb") as inputFile, open(padFileName, "wb") as keyFile, open (encryptedFileName, 'wb') as endResult:
            while (inputBytes := inputFile.read(1024)):
                
                inputBytes     = bytearray(inputBytes)
                keyBytes       = bytearray(urandom(len(inputBytes)))
                encryptedBytes = bytearray()

                for index, byte in enumerate(inputBytes):
                    xor = byte ^ keyBytes[index]
                    encryptedBytes.append(xor)

                keyFile.write(keyBytes)
                endResult.write(encryptedBytes)
    except Exception as e:
        print("Something went wrong: " + str(e))

def doDecryption(fileToDecrypt, padFileName, resultFile):
    try:
        with open(fileToDecrypt, "rb") as inputFile, open(padFileName, "rb") as keyFile, open (resultFile, 'wb') as endResult:
            while (inputBytes := inputFile.read(1024)):
                inputBytes     = bytearray(inputBytes)
                keyBytes       = bytearray(keyFile.read(1024))
                decryptedBytes = bytearray()

                for index, byte in enumerate(inputBytes):
                    xor = keyBytes[index] ^ byte
                    decryptedBytes.append(xor)

                endResult.write(decryptedBytes)
    except Exception as e:
        print("Something went wrong: " + str(e))


if __name__ == "__main__":

    print('''
            OTP GENERATOR
            written by Niklavs Eglitis
            Please select mode:
            1. Encryption
            2. Decryption
          ''')
    
    mode = input('Please select a mode(1/2): ')

    if "1" == mode:
        fileToEncrypt     = input('Enter file name to encrypt: ')
        padFileName       = input('Enter OTP file name: ')
        encryptedFileName = input('Enter encrypted file name: ')
        doEncryption(fileToEncrypt, padFileName, encryptedFileName)

    elif "2" == mode:
        fileToDecrypt     = input('Enter file name to decrypt: ')
        padFileName       = input('Enter OTP file name: ')
        decryptedFileName = input('Enter decrypted file name: ')
        doDecryption(fileToDecrypt, padFileName, decryptedFileName)
        
    else:
        print("Unrecognized command.")
            