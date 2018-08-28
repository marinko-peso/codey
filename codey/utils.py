# -*- coding: utf-8 -*-
import os
import sys
import struct
import hashlib

from Crypto import Random
from Crypto.Cipher import AES

AES_MODE = AES.MODE_CBC
IVEC_SIZE = 16

# Larger chunk sizes can be faster for some files and machines.
DEFAULT_CHUNKSIZE = 64 * 1024
# Size of Q, unsigned long long from C, standard size 8.
FILE_LENGTH_FIELD_SIZE = struct.calcsize('Q')

OUTPUT_FILE_DEFAULT_SUFFIX = '.enc'

# Indicator for moving file pointer relative to end of file.
WHENCE_EOF = 2


def generate_key(password, salt):
    """
    PyCrypto block-level encryption API is low level & expects key to be 16, 24 or 32 bytes (AES-128, AES-196 and AES-256).
    Generating 32 byte key from password provided to eaze up the process.
    256 bit key: 1.1x10e77 combinations and 3.31x10e56 years to crack it on brute force attack by a supercomputer of 10.51 Pentaflops.
    (even though in average key is found after testing around 50 percent of combinations)

    Using key stretching PBKDF2 alghorithm to prevent attacker from using pre-computed lookup tables for the key,
    forcing him to brute force attack.
    Using at least 100,000 iterations since its suggested for sha256 as of 2013.
    """
    return hashlib.pbkdf2_hmac('sha256', password, salt, 100000)


def encrypt_file(password, keyphrase, in_filename, out_filename=None, chunksize=DEFAULT_CHUNKSIZE):
    """
    Encrypts a file content.
    :param password: {String} encryption password (used for key generation).
    :param keyphrase: {String} encryption keyphrase (used for salt on key generation).
    :param in_filename: {String} name of the input file.
    :param out_filename: {String} name of the output file. Defaults to '<in_filename>.enc'
    :param chunksize: {Integer} size of the chunk to read and encrypt the file with. Must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + OUTPUT_FILE_DEFAULT_SUFFIX
    # Get the key for the current combination.
    key = generate_key(password, keyphrase)

    # Generating initialization vector (IV).
    # Important part of block encryption algorithms that work in chained modes (like CBC) we are using.
    # For maximal security, the IV is randomly generated for every encryption.
    ivec = Random.new().read(IVEC_SIZE)
    encryptor = AES.new(key, AES_MODE, ivec)

    filesize = os.path.getsize(in_filename)
    file_length_field = struct.pack('<Q', filesize)

    # Prepare status data for feedback.
    status_data = {
        'status': True,
        'out_filename': out_filename,
        'error': ''
    }

    try:
        with open(in_filename, 'rb') as infp:
            with open(out_filename, 'wb') as outfp:

                # First write IV to the file so we can read it later on.
                outfp.write(ivec)

                chunk = None
                final_chunk = False

                while True:
                    # Encrypt the previous chunk, then read the next.
                    if chunk is not None:
                        outfp.write(encryptor.encrypt(chunk))
                    # If we came to the end of the file.
                    if final_chunk:
                        break
                    # Get the next chunk of file.
                    chunk = infp.read(chunksize)

                    # When we get smaller than a full chunk, input file is done.
                    # Adding the padding and length indicator.
                    # This is to make sure we get a full chunk so filling in with blank space.
                    if len(chunk) == 0 or len(chunk) % 16 != 0:
                        padding_size = (
                            16 - (len(chunk) + FILE_LENGTH_FIELD_SIZE) % 16
                        )
                        padding = ' ' * padding_size

                        chunk += padding
                        # Add the original file length at the end of the file for later extraction on decryption.
                        chunk += file_length_field
                        assert len(chunk) % 16 == 0
                        final_chunk = True
    except:
        e = sys.exc_info()[0]
        # Catch all possible errors and return so caller can be notified.
        status_data['status'] = False
        status_data['error'] = str(e)

    return status_data


def decrypt_file(password, keyphrase, in_filename, out_filename=None, chunksize=DEFAULT_CHUNKSIZE):
    """
    Decrypts a file to its original content.
    :param password: {String} encryption password (used for key generation).
    :param keyphrase: {String} encryption keyphrase (used for salt on key generation).
    :param in_filename: {String} name of the input file.
    :param out_filename: {String} name of the output file. Defaults to '<in_filename>' without enc extension.
    :param chunksize: {Integer} size of the chunk to read and encrypt the file with. Must be divisible by 16.
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]
    # Get the key for the current combination.
    key = generate_key(password, keyphrase)

    # Prepare status data for feedback.
    status_data = {
        'status': True,
        'out_filename': out_filename,
        'error': ''
    }

    try:
        with open(in_filename, 'rb') as infp:
            # Read the initialization vector (IV) from the encrypted file.
            ivec = infp.read(IVEC_SIZE)
            decryptor = AES.new(key, AES_MODE, ivec)

            with open(out_filename, 'wb+') as outfp:
                # We need to read the next chunk to know how to treat first chunk.
                import pdb
                pdb.set_trace()
                chunk = infp.read(chunksize)
                final_chunk = False

                while True:
                    # We need to read the new chunk to know how to treat the current chunk.
                    new_chunk = infp.read(chunksize)
                    # Revert back to original.
                    original_chunk = decryptor.decrypt(chunk)
                    # Check did we reach end of file. This time we know there have to be full
                    # chunks since we made sure of that in encryption.
                    if len(new_chunk) == 0:
                        final_chunk = True
                    # Write to file.
                    outfp.write(original_chunk)

                    if final_chunk:
                        # Read the expected file length from the now
                        # complete reconstruction of the original file.
                        # This moves the file pointer back from the end of
                        # the file then reads the same number of bytes
                        # back in, so should leave the file pointer at the
                        # same position, but we break out of the read loop anyway.
                        outfp.seek(-FILE_LENGTH_FIELD_SIZE, WHENCE_EOF)
                        file_length_field = outfp.read(FILE_LENGTH_FIELD_SIZE)
                        origsize = struct.unpack('<Q', file_length_field)[0]
                        break

                    # Move to next chunk.
                    chunk = new_chunk

                # Get file back to this original size before encryption.
                outfp.truncate(origsize)
    except:
        e = sys.exc_info()[0]
        # Catch all possible errors and return so caller can be notified.
        status_data['status'] = False
        status_data['error'] = str(e)

    return status_data
