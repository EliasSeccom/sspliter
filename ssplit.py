#!/usr/bin/python3
""" Secret Splitter main code"""
#############################################################################
#
# Secret Splitter
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


import hashlib
import math
import os
from os import path
import shutil
import sys
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import argon2 # pylint: disable=E0401
import py7zr # pylint: disable=E0401

#####
# Initial default values
#####
ARGON_TIME = 200
ARGON_MEMORY = 100000
DISTRIBUTION = 3
REDUNDANCY = 2
TMPPATH = "./tmp/"
SPECFILE = "spec"

#####
# Values
#####
PASSPHRASE = ""


def command_line_help(error=False):
    """Prints command-line help"""
    if error:
        print("--------------------------------------------")
        print("ERROR: " + error)
        print("--------------------------------------------")
    print(sys.argv[0] + " [mode] [options] [file1] [file2]...")
    print("Mode:")
    print("  -e: Create new secret split")
    print("  -d: Decrypt secret from splits")
    print("Options:")
    print("  -p [passphrase]: Optional Passphrase")
    print("  --argon-time [rounds]: Custom round count for argon [default " + str(ARGON_TIME) + "]")
    print("  --argon-memory [kb]: Custom amount of memory needed for argon [default " + str(ARGON_MEMORY) + "]")
    print("  --distribution [number]: Specifies the count of the splits which are generated [default " + str(
        DISTRIBUTION) + "]")
    print("  --redundancy [number]: Specifies how many splits are required to decrypt the secret [default " + str(
        REDUNDANCY) + "]")
    sys.exit(99)


def log(level, message):
    """Prints log messages"""
    if level == "i":
        print("INFO: " + message)
    elif level == "w":
        print("WARNING: " + message)
    elif level == "e":
        print("ERROR: " + message)
        sys.exit(99)


def get_chuck_size(data):
    """ Takes data and returns chucksize"""
    return len(data) / REDUNDANCY


def split(data, split_nr):
    """Split data"""
    chucksize = math.ceil(get_chuck_size(data))
    return data[split_nr * chucksize: (split_nr + 1) * chucksize]


def write_chuck(data, dist_ctr, split_ctr, extension):
    """Writing down a chuck"""
    # Write file
    save_file(path.join(TMPPATH, 'P' + str(dist_ctr) + str(split_ctr) + '.' + extension), data)
    file_hash = generate_hash_from_data(data)
    append_file(path.join(TMPPATH, SPECFILE),
                str(dist_ctr) + ";" + str(split_ctr) + ";" + extension + ";" + str(file_hash) + "\n")


def generate_hash_from_data(data):
    """Takes data and returns sha256 hash in hex"""
    return hashlib.sha256(data).digest().hex()


def append_file(file_path, data):
    """Append data to given file"""
    file = open(file_path, "a+")
    file.write(data)
    file.close()


def basic_config(salt):
    """Write config to spec file"""
    log("i", "Writing config File....")
    _, file_extension = os.path.splitext(FILE_PATH[0])
    data = str(DISTRIBUTION) + ";" + str(REDUNDANCY) + ";" + str(salt) + ";" + str(ARGON_TIME) + ";" + str(
        ARGON_MEMORY) + ";" + file_extension + "\n"
    append_file(path.join(TMPPATH, SPECFILE), data)


def calculate_distribution(part):
    """Calculate optional distribution of parts"""
    log("i", "Calculating secret distribution")
    return_value = []
    for i in range(0, REDUNDANCY):
        return_value.append((part + i) % DISTRIBUTION)
    return return_value


def clean_up_working():
    """cleanup working dir"""
    shutil.rmtree(TMPPATH, ignore_errors=True)


def generate_random_salt():
    """returns crypto secure random salt"""
    return b64encode(get_random_bytes(15)).decode("utf-8")


def generate_keys(key, salt, time, memory, distribution):
    """ generate and derive keys for encryption"""
    log("i", "Generating keys....")
    keys = []
    keys.append(argon2.argon2_hash(key, salt, t=time, m=memory))

    # Derive keys from Main Argon Key
    for i in range(0, distribution):
        keys.append(hashlib.sha256(keys[i]).digest())

    # Remove argon base key
    keys.pop(0)

    return keys


def create_splits():
    """ Distributes encrypted data. Package and compress parts to archive"""
    copied = {}
    log("i", "Split secret!")
    for i in range(0, DISTRIBUTION):
        log("i", 'Generating secret split [' + str(i) + '.ss]!')
        dist_path = path.join(TMPPATH, str(i))
        os.mkdir(dist_path)

        # Distribute parts
        for part in calculate_distribution(i):
            if part not in copied.keys():
                copied[part] = 0
            else:
                copied[part] += 1
            ident = "P" + str(part) + str(copied[part]) + "."
            shutil.move(TMPPATH + ident + "cipher", dist_path)
            shutil.move(TMPPATH + ident + "tag", dist_path)
            shutil.move(TMPPATH + ident + "nonce", dist_path)

        # Copy  spec config
        shutil.copy(path.join(TMPPATH, SPECFILE), dist_path)

        # Generate archive
        root_path = os.getcwd()
        os.chdir(dist_path)
        archive = py7zr.SevenZipFile(path.join("..", "..", str(i) + '.ss'), 'w')
        archive.writeall(".")
        archive.close()
        os.chdir(root_path)


def read_file(file_path):
    """ Takes file path and return the binary content of file"""
    log("i", "Reading [" + file_path + "]...")
    file = open(file_path, "rb")
    data = file.read()
    file.close()
    return data


def encrypt_data(keys, data, split_count):
    """Takes key and data and writes encrypted chuncks"""
    distribution_ctr = 0
    log("i", "Encrypt file")
    for i in keys:
        if len(i) != 32:
            raise Exception("Generated key have not required length for encryption")
        cipher = AES.new(i, AES.MODE_GCM) # pylint: disable=E1101
        ciphertext, tag = cipher.encrypt_and_digest(data) # pylint: disable=E1101

        # Split into chucks
        for count in range(0, split_count):
            write_chuck(split(b64encode(ciphertext), count), distribution_ctr, count, "cipher")
            write_chuck(split(b64encode(tag), count), distribution_ctr, count, "tag")
            write_chuck(split(b64encode(cipher.nonce), count), distribution_ctr, count, "nonce") # pylint: disable=E1101

        # Increase Distribution ctr
        distribution_ctr += 1


def does_file_exist(file_path):
    """ Takes file path returns true if path is valid"""
    return path.exists(file_path)


def prepare_env():
    """Preparing directory for extraction"""
    clean_up_working()
    os.mkdir(TMPPATH)


def extract_files():
    """ extract the file """
    for file in FILE_PATH:
        log("i", "Unpacking file [" + file + "]")
        try:
            archive = py7zr.SevenZipFile(file, mode='r')
            archive.extractall(path=TMPPATH)
            archive.close()
        except:  # pylint: disable=W0702
            log("e", "Error while extracting archive [" + file + "]")


def parse_spec_file():
    """ Reads spec file and returns config values and hashes of files"""
    valid_config = False
    distribution = ""
    redundancy = ""
    salt = ""
    argon_time = ""
    argon_memory = ""
    files = {}
    if does_file_exist(path.join(TMPPATH, SPECFILE)): # pylint: disable=R1705
        log("i", "Reading spec file")
        file = open(path.join(TMPPATH, SPECFILE), "r")
        for line in file:
            array = line.rstrip().split(';')

            if not valid_config:
                distribution = int(array[0])
                redundancy = int(array[1])
                salt = array[2]
                argon_time = int(array[3])
                argon_memory = int(array[4])
                files_extension = array[5]
                valid_config = True
            else:
                filename = "P" + array[0] + array[1] + "." + array[2]
                files[filename] = array[3]
        return files, distribution, redundancy, salt, argon_time, argon_memory, files_extension
    else:
        clean_up_working()
        log("e", "No spec file found in unpacked data!")
    return False


def check_files_integrity(files):
    """ takes file list and checks hash against given hash to validate file integrity"""
    return_files = {}
    for filename in files:
        if does_file_exist(path.join(TMPPATH, filename)):
            log("i", "Validating part [" + filename + "]")
            data = read_file(path.join(TMPPATH, filename))
            if generate_hash_from_data(data) == files[filename]:
                log("i", "Part [" + filename + "] is valid")
                return_files[filename] = data
            else:
                log("e", "Part [" + filename + "] is invalid. exciting...")
        else:
            log("i", "Skipping missing Part [" + filename + "]")
    return return_files


def find_valid_split(files, redundancy):
    """ Find compleat split form given splits """
    lib = {}
    for filename in files:
        split_id = filename[1:2]
        if split_id not in lib.keys():
            lib[split_id] = 1
        else:
            lib[split_id] = lib[split_id] + 1
        if lib[split_id] >= (redundancy * 3):
            return split_id
    return False


def merge_splits(files, split_id, redundancy):
    """ takes splits and merge them together """
    tag = ""
    cipher = ""
    nonce = ""
    for i in range(0, redundancy):
        filename = "P" + str(split_id) + str(i)
        tag += str(files[filename + ".tag"].decode("utf-8"))
        cipher += str(files[filename + ".cipher"].decode("utf-8"))
        nonce += str(files[filename + ".nonce"].decode("utf-8"))
    return b64decode(nonce), b64decode(cipher), b64decode(tag)


def decrypt_file(keys, split_id, ciphertext, tag, nonce):
    """ Takes keys and encrypted data and returns cleartext """
    log("i", "Decrypting data...")
    try:
        cipher = AES.new(keys[int(split_id)], AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except:  # pylint: disable=W0702
        log("e", "Some error while decryption of secret occurred! exciting...")


def save_file(file_path, data):
    """ takes path and data and saves data to path """
    log("i", "Save file as" + file_path)
    file = open(file_path, 'wb')
    file.write(data)
    file.close()


def main_encryption():
    """ Main routine to split and encrypt data"""
    prepare_env()
    salt = generate_random_salt()
    basic_config(salt)
    keys = generate_keys(PASSPHRASE, salt, ARGON_TIME, ARGON_MEMORY, DISTRIBUTION)
    data = read_file(FILE_PATH[0])
    encrypt_data(keys, data, REDUNDANCY)
    create_splits()
    clean_up_working()


def main_decryption():
    """ Main routine to merge and decrypt data"""
    prepare_env()
    extract_files()
    files, distribution, redundancy, salt, argon_time, argon_memory, file_extension = parse_spec_file()
    files = check_files_integrity(files)
    complete_split_id = find_valid_split(files, redundancy)
    if not complete_split_id:
        log("e", "Not enough valid splits found to restore secret!")
    nonce, cipher, tag = merge_splits(files, complete_split_id, redundancy)
    keys = generate_keys(PASSPHRASE, salt, argon_time, argon_memory, distribution)
    cleartext = decrypt_file(keys, complete_split_id, cipher, tag, nonce)
    save_file("restored-file" + file_extension, cleartext)
    clean_up_working()


#####
# Parsing commandline arguments
#####
MODE = ""
JUMP_TO_NEXT_ARG = False
ARG_LEN = len(sys.argv)
FILE_PATH = []
for argCtr in range(1, ARG_LEN):
    arg = sys.argv[argCtr]
    if (argCtr + 1) < ARG_LEN:
        next_arg = sys.argv[argCtr + 1]
    if JUMP_TO_NEXT_ARG:
        JUMP_TO_NEXT_ARG = False
        continue
    if arg == "-d":
        if MODE != "":
            command_line_help("Enc/Dec mode selected!")
        MODE = "d"
    elif arg == "-e":
        if MODE != "":
            command_line_help("Enc/Dec mode selected!")
        MODE = "e"
    elif arg == "-p":
        PASSPHRASE = next_arg
        log("i", "Setting optional passphrase")
        JUMP_TO_NEXT_ARG = True
    elif arg == "--argon-time":
        ARGON_TIME = int(next_arg)
        log("i", "Setting argon time setting to " + next_arg + " rounds")
        JUMP_TO_NEXT_ARG = True
    elif arg == "--argon-memory":
        ARGON_MEMORY = int(next_arg)
        log("i", "Setting argon memory setting to " + next_arg + "kb")
        JUMP_TO_NEXT_ARG = True
    elif arg == "--distribution":
        DISTRIBUTION = int(next_arg)
        log("i", "Setting distribution parts to " + next_arg + " archives")
        JUMP_TO_NEXT_ARG = True
    elif arg == "--redundancy":
        REDUNDANCY = int(next_arg)
        log("i", "Setting redundancy to " + next_arg + " archives")
        JUMP_TO_NEXT_ARG = True

    else:
        if MODE == "":
            command_line_help("Missing mode")
        elif MODE == "d":
            if does_file_exist(arg):
                FILE_PATH.append(arg)
            else:
                log("e", "Given file does not exists [" + arg + "]!")
        elif MODE == "e":
            if len(FILE_PATH) >= 1:
                command_line_help("Not supported to add multible files in encryption mode")
            else:
                if does_file_exist(arg):
                    FILE_PATH.append(arg)
                else:
                    log("e", "Given file does not exists [" + arg + "]!")

# Prechecks
if MODE == "":
    command_line_help()
if len(FILE_PATH) == 0:
    command_line_help("No file(s) to are enc/dec given")

if PASSPHRASE == "":
    TXT = ""
    if MODE == "e":
        TXT = ", so files are only protected through split!"
    log("w", "No passphrase given with the option -p" + TXT)

# Switch to modes
if MODE == "e":
    main_encryption()
else:
    main_decryption()
