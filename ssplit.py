#!/bin/python3
#############################################################################
#
# SSpliter
# Copyright (C) 2020  Elias Summermatter
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#
#############################################################################

#####
# Imports
#####
import argon2
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode
from base64 import b64decode
import os
from os import path
import shutil
import py7zr
import sys
import math

#####
# Initial default values
#####
argon_time=200
argon_memory=100000
distribution=3
redundancy=2
tmpPath="./tmp/"
specFile="spec"

#####
# Values
#####
passphrase=""
salt=""



#####
# Commandline helper function
#####
def commandlineHelp(error = False):
    if (error):
        print("--------------------------------------------")
        print("ERROR: " + error)
        print("--------------------------------------------")
    print(sys.argv[0] + " [mode] [options] [file1] [file2]..." )
    print("Mode:")
    print("  -e: Create new secret split")
    print("  -d: Decrypt secret from splits")
    print("Options:")
    print("  -p [passphrase]: Optional Passphrase")
    print("  --argon-time [rounds]: Custom round count for argon [default " + str(argon_time) + "]")
    print("  --argon-memory [kb]: Custom amount of memory needed for argon [default " + str(argon_memory) + "]")
    print("  --distribution [number]: Specifies the count of the splits which are generated [default " + str(distribution) + "]")
    print("  --redundancy [number]: Specifies how many splits are required to decrypt the secret [default " + str(redundancy) + "]")
    exit(99)

#####
# Logging
#####
def log(level,message):
    if level == "i":
        print("INFO: " + message)
    elif level == "w":
        print("WARNING: " + message)
    elif level == "e":
        print("ERROR: " + message)
        exit(99)

#####
# Calculate chuck size
#####
def getChucksize(data):
    return len(data)/redundancy

#####
# Split data
#####
def split(data,split):
    chucksize=math.ceil(getChucksize(data))
    return data[split * chucksize: (split + 1) * chucksize]

#####
# Writing down a chuck
#####
def writeChuck(data,distCtr,splitCtr,extension):
    # Write file
    saveFile(path.join(tmpPath, 'P' + str(distCtr) + str(splitCtr) + '.' + extension), data)
    hash = generateHashFromData(data)
    appendFile(path.join(tmpPath, specFile), str(distCtr) + ";" + str(splitCtr) + ";" + extension + ";" + str(hash) + "\n")

#####
#  Hashing
#####
def generateHashFromData(data):
    return hashlib.sha256(data).digest().hex()

#####
# Append file
#####
def appendFile(file ,data):
    f=open(file, "a+")
    f.write(data)
    f.close()

#####
# Generate spec file
#####
def basicConfig(salt):
    log("i","Writing config File....")
    filename, file_extension = os.path.splitext(filePath[0])
    f=open(tmpPath + specFile, "a+")
    f.write(str(distribution)+ ";" + str(redundancy) + ";" + str(salt) + ";" + str(argon_time) + ";" + str(argon_memory) + ";" + file_extension + "\n")
    f.close()

#####
# Calculate optional distribution of parts
#####
def calcuateDistribution(part):
    log("i","Calculating secret distribution")
    returnValue = []
    for i in range(0,redundancy):
        returnValue.append((part+i) % distribution)
    return returnValue

#####
# Cleanup
#####
def cleanUpWorking():
    shutil.rmtree(tmpPath, ignore_errors=True)

#####
# Salt generation
#####
def generateRandumSalt():
    return b64encode(get_random_bytes(15)).decode("utf-8")

#####
# Keys generation function
#####
def generateKeys(key,salt, time, memory, distribution):
    log("i","Generating keys....")
    keys=[]
    keys.append(argon2.argon2_hash(key, salt, t=time, m=memory))

    # Derive keys from Main Argon Key
    for i in range(0,distribution):
        keys.append(hashlib.sha256(keys[i]).digest())

    # Remove argon base key
    keys.pop(0)

    return keys

#####
# Create splits
#####
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
            shutil.move(tmpPath + ident + "nonce" , dist_path)

        # Copy  spec config
        shutil.copy(path.join(tmpPath, specFile), dist_path)

        # Generate archive
        root_path=os.getcwd()
        os.chdir(dist_path)
        archive = py7zr.SevenZipFile(path.join("..", "..", str(i) + '.ss'), 'w')
        archive.writeall(".")
        archive.close()
        os.chdir(root_path)

#####
# Read a file
#####
def readFile(filePath):
    log("i","Reading [" + filePath + "]...")
    file = open(filePath, "rb")
    data=file.read()
    file.close()
    return data

#####
# Encrypt the secret
#####
def encryptSecret(keys, data, splitsCount):
    distribution_ctr=0
    log("i","Encrypt file")
    for i in keys:
        if len(i) != 32:
            continue
        cipher = AES.new(i, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Split into chucks
        for l in range(0,splitsCount):
            writeChuck(split(b64encode(ciphertext),l), distribution_ctr, l, "cipher")
            writeChuck(split(b64encode(tag),l), distribution_ctr, l, "tag" )
            writeChuck(split(b64encode(cipher.nonce),l), distribution_ctr, l, "nonce" )

        # Increase Distribution ctr
        distribution_ctr+=1

#####
# Check for existing file
#####
def doesFileExist(file_path):
    return path.exists(file_path)

#####
# Preparing directory for extraction
#####
def makeEnvReady():
    cleanUpWorking()
    os.mkdir(tmpPath)

#####
# Extract files
#####
def unpackFiles():
    for file in filePath:
        log("i", "Unpacking file [" + file + "]")
        try:
            archive = py7zr.SevenZipFile(file, mode='r')
            archive.extractall(path=tmpPath)
            archive.close()
        except:
            log("e", "Error while extracting archive [" + file + "]")

#####
# Parsing configfile
#####
def readSpecFile():
    validConfig=False
    distribution=""
    redundancy= ""
    salt=""
    argon_time=""
    argon_memory=""
    files={}
    if doesFileExist(tmpPath + specFile):
        log("i", "Reading spec file")
        f = open(path.join(tmpPath, specFile), "r")
        for line in f:
            array=line.rstrip().split(';')

            if not validConfig:
                distribution=int(array[0])
                redundancy=int(array[1])
                salt=array[2]
                argon_time=int(array[3])
                argon_memory=int(array[4])
                fileEnd=array[5]
                validConfig=True
            else:
                filename = "P" + array[0] + array[1] + "." + array[2]
                files[filename]=array[3]
        return files, distribution, redundancy, salt, argon_time, argon_memory, fileEnd
    else:
        cleanUpWorking()
        log("e", "No spec file found in unpacked data!")

#####
# Check hash of splits
#####
def validateFiles(files):
    returnFiles={}
    for filename in files:
        if doesFileExist(path.join(tmpPath, filename)):
            log("i", "Validating part [" + filename + "]")
            data = readFile(path.join(tmpPath, filename))
            if generateHashFromData(data) == files[filename]:
                log("i","Part [" + filename + "] is valid")
                returnFiles[filename] = data
            else:
                log("e", "Part [" + filename + "] is invalid. exciting...")
        else:
            log("i", "Skipping missing Part [" + filename + "]")
    return returnFiles

#####
# Find valid parts of split to merge
#####
def findValidSplit(files,redundancy):
    lib={}
    for filename in files:
        splitId=filename[1:2]
        if splitId not in lib.keys():
            lib[splitId] = 1
        else:
            lib[splitId]=lib[splitId] + 1
        if lib[splitId] >= (redundancy * 3):
            return splitId
    return False

#####
# Function that merges spits together
#####
def mergeSplits(files,splitId,redundancy):
    tag=""
    cipher=""
    nonce=""
    for i in range(0,redundancy):
        filename="P" + str(splitId) + str(i)
        tag+=str(files[filename + ".tag"].decode("utf-8"))
        cipher+=str(files[filename + ".cipher"].decode("utf-8"))
        nonce+=str(files[filename + ".nonce"].decode("utf-8"))
    return b64decode(nonce), b64decode(cipher), b64decode(tag)

#####
# Decryption methode
#####

def decryptSecret(keys,splitId,ciphertext,tag,nonce):
    log("i", "Decrypting data...")
    try:
        cipher = AES.new(keys[int(splitId)], AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except:
        log("e", "Some error while decryption of secret occurred! exciting...")

#####
# Save file function
#####
def saveFile(path, data):
    log("i", "Save file as" + path)
    file = open(path , 'wb')
    file.write(data)
    file.close()

#####
# Main encryption method
#####
def main_encryption():
    makeEnvReady()
    salt=generateRandumSalt()
    basicConfig(salt)
    keys = generateKeys(passphrase, salt, argon_time, argon_memory,distribution)
    data=readFile(filePath[0])
    encryptSecret(keys,data,redundancy)
    createSplits()
    cleanUpWorking()

#####
# Main decryption method
#####
def main_decryption():
    makeEnvReady()
    unpackFiles()
    files, distribution, redundancy, salt, argon_time, argon_memory, fileExtension = readSpecFile()
    files = validateFiles(files)
    completeSplitId = findValidSplit(files, redundancy)
    if not completeSplitId:
        log("e", "Not enough valid splits found to restore secret!")
    nonce, cipher, tag = mergeSplits(files,completeSplitId,redundancy)
    keys = generateKeys(passphrase,salt,argon_time,argon_memory, distribution)
    cleartext = decryptSecret(keys,completeSplitId,cipher,tag,nonce)
    saveFile("restored-file" + fileExtension, cleartext)
    cleanUpWorking()

#####
# Parsing commandline arguments
#####
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
            commandlineHelp("Enc/Dec mode selected!")
        mode="d"
    elif arg == "-e":
        if mode != "":
            commandlineHelp("Enc/Dec mode selected!")
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
    elif arg == "--distribution":
        distribution=int(next_arg)
        log("i","Setting distribution parts to " + next_arg + " archives")
        jumpNextArg=True
    elif arg == "--redundancy":
        redundancy=int(next_arg)
        log("i","Setting redundancy to " + next_arg + " archives")
        jumpNextArg=True

    else:
        if mode == "":
            commandlineHelp("Missing mode")
        elif mode == "d":
            if doesFileExist(arg):
                filePath.append(arg)
            else:
                log("e", "Given file does not exists [" + arg + "]!")
        elif mode == "e":
            if len(filePath) >= 1:
                commandlineHelp("Not supported to add multible files in encryption mode")
            else:
                if doesFileExist(arg):
                    filePath.append(arg)
                else:
                    log("e", "Given file does not exists [" + arg + "]!")

# Prechecks
if mode == "":
    commandlineHelp()
if len(filePath) == 0:
    commandlineHelp("No file(s) to are enc/dec given")

if passphrase == "":
    txt=""
    if mode == "e":
        txt=", so files are only protected through split!"
    log("w", "No passphrase given with the option -p" + txt)

# Switch to modes
if mode == "e":
    main_encryption()
else:
    main_decryption()
