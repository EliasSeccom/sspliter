#!/bin/python3
import argon2
import hashlib
from Crypto.Cipher import AES
from base64 import b64encode
import os
import shutil
import py7zr

argon_time=200
argon_memory=100  #100000
distribution=3
redundancy=2
filePath="./secret"
tmpPath="./tmp/"
specFile="spec"

def getChucksize(data):
    return len(data)/redundancy

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

def basicConfig():
    f=open(tmpPath + specFile, "a+")
    f.write(str(distribution)+ ";" + str(redundancy) + ";" + str(argon_time) + ";" + str(argon_memory) + "\n")
    f.close()

def calcuateDistribution(part):
    returnValue = []
    for i in range(0,redundancy):
        returnValue.append((part+i) % distribution)
    return returnValue

def cleanUpWorking():
    shutil.rmtree(tmpPath, ignore_errors=True)


cleanUpWorking()
os.mkdir(tmpPath)
basicConfig()

keys=[]
keys.append(argon2.argon2_hash("password", "some_salt", t=argon_time, m=argon_memory))

# Derive keys from Main Argon Key
for i in range(0,distribution):
    keys.append(hashlib.sha256(keys[i]).digest())

# Generate distribution

# Read Data
file = open(filePath, "rb")
data=file.read()
file.close()

distribution_ctr=0

for i in keys:
    if len(i) != 32:
        continue
    cipher = AES.new(i, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Split into chucks
    for l in range(0,redundancy):
        writeChuck(split(b64encode(ciphertext),l), distribution_ctr, l, "cipher")
        writeChuck(split(b64encode(tag),l), distribution_ctr, l, "tag" )

    # Increase Distribution ctr
    distribution_ctr+=1


copied={}
for i in range(0,distribution):
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


cleanUpWorking()





