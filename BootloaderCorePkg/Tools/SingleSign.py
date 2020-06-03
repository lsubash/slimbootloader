#!/usr/bin/env python
## @ SingleSign.py
# Single signing script
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

##
# Import Modules
#
import os
import sys
import re
import shutil
import subprocess
import struct
import hashlib
import string

# KEY_SIZE_TYPE defines the key sizes to be used for signing
# KEY_SIZE_TYPE = RSA2048 uses RSA 2K size keys
# KEY_SIZE_TYPE = RSA3072 uses RSA 3K size keys
KEY_SIZE_TYPE = 'RSA2048'

SIGNING_KEY = {
    # Key Id                    | Key File Name start |
    # ===========================================================
    # MASTER_KEY_ID is used for signing Slimboot Key Hash Manifest (KEYH Component)
    "MASTER_KEY_ID"          :    "MasterTestKey",

    # CFGDATA_KEY_ID is used for signing external Config data blob)
    "CFGDATA_KEY_ID"         :    "ConfigTestKey",

    # FIRMWAREUPDATE_KEY_ID is used for signing capsule firmware update image)
    "FIRMWAREUPDATE_KEY_ID"  :    "FirmwareUpdateTestKey",

    # CONTAINER_KEY_ID is used for signing container header with mono signature
    "CONTAINER_KEY_ID"       :    "ContainerTestKey",

    # CONTAINER_COMP1_KEY_ID, CONTAINER_COMP2_KEY_ID is used for signing container components
    "CONTAINER_COMP1_KEY_ID" :    "ContainerComp1TestKey",
    "CONTAINER_COMP2_KEY_ID" :    "ContainerComp2TestKey",

    # OS1_PUBLIC_KEY_ID, OS2_PUBLIC_KEY_ID is used for referencing Boot OS public keys
    "OS1_PUBLIC_KEY_ID"      :    "OS1_pubkey",
    "OS2_PUBLIC_KEY_ID"      :    "OS2_pubkey",

    }


def get_openssl_path ():
    if os.name == 'nt':
        if 'OPENSSL_PATH' not in os.environ:
            os.environ['OPENSSL_PATH'] = "C:\\Openssl\\"
        if 'OPENSSL_CONF' not in os.environ:
            openssl_cfg = "C:\\Openssl\\openssl.cfg"
            if os.path.exists(openssl_cfg):
                os.environ['OPENSSL_CONF'] = openssl_cfg
    openssl = os.path.join(os.environ.get ('OPENSSL_PATH', ''), 'openssl')
    return openssl

def run_process (arg_list, print_cmd = False, capture_out = False):
    sys.stdout.flush()
    if print_cmd:
        print (' '.join(arg_list))

    exc    = None
    result = 0
    output = ''
    try:
        if capture_out:
            output = subprocess.check_output(arg_list).decode()
        else:
            result = subprocess.call (arg_list)
    except Exception as ex:
        result = 1
        exc    = ex

    if result:
        if not print_cmd:
            print ('Error in running process:\n  %s' % ' '.join(arg_list))
        if exc is None:
            sys.exit(1)
        else:
            raise exc

    return output

#
# Sign an file using openssl
#
# priv_key   [Input]        Key Id or Path to Private key
# hash_type  [Input]        Signing hash
# sign_scheme[Input]        Sign/padding scheme
# in_file    [Input]        Input file to be signed
# out_file   [Input/Output] Signed data file
#

def single_sign_file (priv_key, hash_type, sign_scheme, in_file, out_file):

    _hash_type_string = {
        "SHA2_256"    : 'sha256',
        "SHA2_384"    : 'sha384',
        "SHA2_512"    : 'sha512',
    }

    _hash_digest_Size = {
        # Hash_string : Hash_Size
        "SHA2_256"    : 32,
        "SHA2_384"    : 48,
        "SHA2_512"    : 64,
        "SM3_256"     : 32,
    }

    _sign_scheme_string = {
        "RSA_PKCS1"    : 'pkcs1',
        "RSA_PSS"      : 'pss',
    }

    # Check for Key Id or key path
    if not os.path.exists(priv_key):
        slimboot_key_dir = os.environ.get('SLIMBOOT_KEY_DIR')
        print ("slimboot_key_dir1 %s" % slimboot_key_dir)
        if not os.path.exists(slimboot_key_dir):
            raise Exception ("SLIMBOOT_KEY_DIR is not defined. Set SLIMBOOT_KEY_DIR !!")
        # Generate key file name from key id
        priv_key_file = SIGNING_KEY[priv_key] + '_' + KEY_SIZE_TYPE +'.pem'
        priv_key =  os.path.join (slimboot_key_dir, priv_key_file)

    # Temporary files to store hash generated
    hash_file_tmp = out_file+'.hash.tmp'
    hash_file     = out_file+'.hash'

    # Generate hash using openssl dgst in hex format
    cmdargs = [get_openssl_path(), 'dgst', '-'+'%s' % _hash_type_string[hash_type], '-out', '%s' % hash_file_tmp, '%s' % in_file]
    run_process (cmdargs)

    # Extract hash form dgst command output and convert to ascii
    with open(hash_file_tmp, 'r') as fin:
        hashdata = fin.read()
    fin.close()

    try:
        hashdata = hashdata.rsplit('=', 1)[1].strip()
    except:
        raise Exception('Hash Data not found for signing!')

    if len(hashdata) != (_hash_digest_Size[hash_type] * 2):
        raise Exception('Hash Data size do match with for hash type!')

    hashdata_bytes = bytearray.fromhex(hashdata)
    open (hash_file, 'wb').write(hashdata_bytes)

    # sign using Openssl pkeyutl
    cmdargs = [get_openssl_path(), 'pkeyutl', '-sign', '-in', '%s' % hash_file, '-inkey', '%s' % priv_key,
               '-out', '%s' % out_file, '-pkeyopt', 'digest:%s' % _hash_type_string[hash_type],
               '-pkeyopt', 'rsa_padding_mode:%s' % _sign_scheme_string[sign_scheme]]

    run_process (cmdargs)

    return

#
# Extract public key using openssl
#
# in_key        [Input]         Private key or public key in pem format
# pub_key_file  [Input/Output]  Public Key to a file
#
# return        keydata (mod, exp) in bin format
#

def single_sign_gen_pub_key (in_key, pub_key_file = None):

    # Check for Key Id or key path
    if not os.path.exists(in_key):
        # Check if SLIMBOOT_KEY_DIR is set
        slimboot_key_dir = os.environ.get('SLIMBOOT_KEY_DIR')
        print ("slimboot_key_dir %s" % slimboot_key_dir)
        if not os.path.exists(slimboot_key_dir):
            raise Exception ("SLIMBOOT_KEY_DIR is not defined. Set SLIMBOOT_KEY_DIR !!")
        # Generate key file name from key_id
        key_file = SIGNING_KEY[in_key] + '_' + KEY_SIZE_TYPE+'.pem'
        in_key =  os.path.join (slimboot_key_dir, key_file)

    if not os.path.isfile(in_key):
        raise Exception ("Invalid input key file '%s' !" % in_key)

    # Expect key to be in PEM format
    is_prv_key = False
    cmdline = [get_openssl_path(), 'rsa', '-pubout', '-text', '-noout', '-in', '%s' % in_key]
    # Check if it is public key or private key
    text = open(in_key, 'r').read()
    if '-BEGIN RSA PRIVATE KEY-' in text:
        is_prv_key = True
    elif '-BEGIN PUBLIC KEY-' in text:
        cmdline.extend (['-pubin'])
    else:
        raise Exception('Unknown key format "%s" !' % in_key)

    if pub_key_file:
        cmdline.extend (['-out', '%s' % pub_key_file])
        capture = False
    else:
        capture = True

    output = run_process (cmdline, capture_out = capture)
    if not capture:
        output = text = open(pub_key_file, 'r').read()
    data     = output.replace('\r', '')
    data     = data.replace('\n', '')
    data     = data.replace('  ', '')

    # Extract the modulus
    if is_prv_key:
        match = re.search('modulus(.*)publicExponent:\s+(\d+)\s+', data)
    else:
        match = re.search('Modulus(?:.*?):(.*)Exponent:\s+(\d+)\s+', data)
    if not match:
        raise Exception('Public key not found!')
    modulus  = match.group(1).replace(':', '')
    exponent = int(match.group(2))

    mod = bytearray.fromhex(modulus)
    # Remove the '00' from the front if the MSB is 1
    if mod[0] == 0 and (mod[1] & 0x80):
        mod = mod[1:]
    exp = bytearray.fromhex('{:08x}'.format(exponent))

    keydata   = mod + exp

    return keydata

