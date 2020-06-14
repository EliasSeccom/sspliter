#!/bin/python3
##########################################################
import argon2
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode
import os
from os import path
import shutil
import py7zr
import sys

argon_time=200
argon_memory=100  #100000
distribution=3
redundancy=2
passphrase=""
tmpPath="./tmp/"
specFile="spec"

def getChucksize(data):
    return len(data)/redundancy

def comandlineHelp(error = False):
    if (error):
        print("ERROR: " + error)
    exit(99)

def log(level,message):
    if level == "i":
        print("INFO: " + message)
    elif level == "w":
        print("WARNING: " + message)
    elif level == "e":
        print("ERROR: " + message)
        exit(99)

def split(data,split):
    chucksize=int(getChucksize(data))
    return data[split * chucksize: (split + 1) * chucksize]

def writeChuck(data,distCtr,splitCtr,extension):
    # Write file
    file = open(tmpPath + 'P' + str(distCtr) + str(splitCtr) + '.' + extension , 'wb')
    file.write(data)
    file.close()
    hash = generateHashFromData(data)
    appendFile(tmpPath + specFile, str(distCtr) + ";" + str(splitCtr) + ";" + extension + ";" + str(hash) + "\n")


def generateHashFromData(data):
    return hashlib.sha256(data).digest().hex()

def appendFile(file ,data):
    f=open(file, "a+")
    f.write(data)
    f.close()

def basicConfig(salt):
    log("i","Writing config File....")
    f=open(tmpPath + specFile, "a+")
    f.write(str(distribution)+ ";" + str(redundancy) + ";" + str(salt) + ";" + str(argon_time) + ";" + str(argon_memory) + "\n")
    f.close()

def calcuateDistribution(part):
    log("i","Calculating secret distribution")
    returnValue = []
    for i in range(0,redundancy):
        returnValue.append((part+i) % distribution)
    return returnValue

def cleanUpWorking():
    shutil.rmtree(tmpPath, ignore_errors=True)

def generateRandumSalt():
    return b64encode(get_random_bytes(15)).decode("utf-8")

def generateKeys(key,salt, time, memory):
    log("i","Generating keys....")
    keys=[]
    keys.append(argon2.argon2_hash(key, salt, t=time, m=memory))

    # Derive keys from Main Argon Key
    for i in range(0,distribution):
        keys.append(hashlib.sha256(keys[i]).digest())

    # Remove argon base key
    keys.pop(0)

    return keys

def createSplits():
    copied={}
    log("i","Split secret!")
    for i in range(0,distribution):
        log("i",'Generating secret split [' + str(i) + '.ss]!')
        dist_path=tmpPath + str(i)
        os.mkdir(dist_path)

        # Distribute parts
        for l in calcuateDistribution(i):
            if l not in copied.keys():
                copied[l] = 0
            else:
                copied[l] += 1
            ident="P" + str(l) + str(copied[l]) + "."
            shutil.move(tmpPath + ident + "cipher", dist_path)
            shutil.move(tmpPath + ident + "tag" , dist_path)

        # Copy  spec config
        shutil.copy(tmpPath + specFile, dist_path)

        # Generate archive
        root_path=os.getcwd()
        os.chdir(dist_path)
        archive = py7zr.SevenZipFile("../../" + str(i) + '.ss', 'w')
        archive.writeall(".")
        archive.close()
        os.chdir(root_path)

def readSecret(filePath):
    log("i","Reading secret.")
    file = open(filePath, "rb")
    data=file.read()
    file.close()
    return data

def encryptSecret(keys, data, splitsCount):
    distribution_ctr=0
    log("i","Encrypt secret!")
    for i in keys:
        if len(i) != 32:
            continue
        cipher = AES.new(i, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Split into chucks
        for l in range(0,splitsCount):
            writeChuck(split(b64encode(ciphertext),l), distribution_ctr, l, "cipher")
            writeChuck(split(b64encode(tag),l), distribution_ctr, l, "tag" )

        # Increase Distribution ctr
        distribution_ctr+=1
def doesFileExist(file_path):
    return path.exists(file_path)

def main_encryption():
    # Main split/encryption Process
    cleanUpWorking()
    os.mkdir(tmpPath)
    salt=generateRandumSalt()
    basicConfig(salt)
    keys = generateKeys(passphrase, salt, argon_time, argon_memory)
    data=readSecret(filePath[0])
    encryptSecret(keys,data,redundancy)
    createSplits()
    cleanUpWorking()


# Parsing commandline arguments
mode=""
jumpNextArg=False
argLen=len(sys.argv)
filePath=[]
for argCtr in range(1,argLen):
    arg=sys.argv[argCtr]
    if (argCtr+1) < argLen:
        next_arg=sys.argv[argCtr+1]
    if jumpNextArg:
        jumpNextArg=False
        continue
    if arg == "-d":
        if mode != "":
            comandlineHelp("Enc/Dec mode selected!")
        mode="d"
    elif arg == "-e":
        if mode != "":
            comandlineHelp("Enc/Dec mode selected!")
        mode="e"
    elif arg == "-p":
        passphrase=next_arg
        log("i","Setting optional passphrase")
        jumpNextArg=True
    elif arg == "--argon-time":
        argon_time=int(next_arg)
        log("i","Setting argon time setting to " + next_arg + " rounds")
        jumpNextArg=True
    elif arg == "--argon-memory":
        argon_memory=int(next_arg)
        log("i","Setting argon memory setting to " + next_arg + "kb")
        jumpNextArg=True
    else:
        if mode == "":
            comandlineHelp("Missing mode")
        elif mode == "d":
            if doesFileExist(arg):
                filePath.append(arg)
            else:
                log("e", "Given file does not exists [" + arg + "]!")
        elif mode == "e":
            if len(filePath) >= 1:
                comandlineHelp("Not supported to add multible files in encryption mode")
            else:
                if doesFileExist(arg):
                    filePath.append(arg)
                else:
                    log("e", "Given file does not exists [" + arg + "]!")

# Prechecks
if len(filePath) == 0:
    comandlineHelp("No file(s) to enc/dec given")

if passphrase == "":
    log("w", "No passphrase given, so files are only protected through split!")


# Modes
if mode == "e":
    main_encryption()





