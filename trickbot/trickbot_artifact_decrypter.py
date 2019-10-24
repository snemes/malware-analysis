#!/usr/bin/env python3
import argparse
import base64
import itertools
import logging
import os
import struct
import sys

# run "python3 -m pip install -r requirements.txt" if you are missing these
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA384
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

logging.basicConfig(format='%(message)s', level=logging.INFO, stream=sys.stderr)
log = logging.getLogger()

BASE64_STANDARD = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
BASE64_CUSTOM = b'HJIA/CB+FGKLNOP3RSlUVWXYZfbcdeaghi5kmn0pqrstuvwx89o12467MEDyzQjT'

ECC_KEY = '''-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8yCG2yBN8HM3tfsYsMCvgLvz+/FKwDvG
AB8j7xxMBlSjj6YZfEFX6wu8f0GhWHlwDcOhOBxe4nrRKfu2VUHVjsfHPh7ztGdj
01D1W1/RwFa4OIfbtUTX4Th5PmMrAy7I
-----END PUBLIC KEY-----
'''

verifier = DSS.new(ECC.import_key(ECC_KEY), 'fips-186-3')


def derive_key(rounds, data):
    h = SHA256.new()
    for _ in range(rounds):
        h.update(data)
        data = h.digest()
    return data


def decrypt_data(data):
    if data is None:
        return None

    key = derive_key(128, data[:0x20])[:0x20]
    iv = derive_key(128, data[0x10:0x30])[:0x10]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    def pad(s):
        return s + (-len(s) % 16) * bytes([-len(s) % 16])

    data = pad(data[0x30:])
    data = cipher.decrypt(data)

    if len(data) >= 8:
        size, _ = struct.unpack_from('=II', data)
        signature = data[size+0x08:size+0x68]
        data = data[:size+0x08]
        try:
            verifier.verify(SHA384.new(data), signature)
        except ValueError:
            log.warning('[!] WARNING: Bad public key signature')
        data = data[0x08:]

    return data


def xor(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])


def calc_checksum(data):
    x = 0
    for b in data:
        x = (x + b) & 0xffffffff
        x = (x + ((x << 10) & 0xffffffff)) & 0xffffffff
        x = (x ^ ((x >> 6) & 0xffffffff)) & 0xffffffff
    x = (x + ((x <<  3) & 0xffffffff)) & 0xffffffff
    x = (x ^ ((x >> 11) & 0xffffffff)) & 0xffffffff
    x = (x + ((x << 15) & 0xffffffff)) & 0xffffffff
    return x


def base64_encode(data, alphabet):
    return base64.b64encode(data).translate(bytes.maketrans(BASE64_STANDARD, alphabet)).rstrip(b'=')


def base64_decode(data, alphabet):
    return base64.b64decode((data + b'==').translate(bytes.maketrans(alphabet, BASE64_STANDARD)))


def find_b64alphabet(data):
    b64alphabet = bytearray(BASE64_CUSTOM)

    for i in itertools.permutations(b64alphabet[-9:]):
        b64alphabet[-9:] = bytearray(i)
        x = base64_decode(data, b64alphabet)
        if len(x) <= 64:
            continue

        items = x.split(b' ')
        if len(items) != 5:
            continue
        if len(items[0]) != 64:
            continue
        if not all(_ in b'0123456789ABCDEF' for _ in items[0]):
            continue
        if not all(_ in b'0123456789' for _ in items[1]):
            continue
        if not all(_ in b'0123456789' for _ in items[2]):
            continue
        if not all(_ in b'0123456789' for _ in items[3]):
            continue
        if not all(_ in b'0123456789' for _ in items[4]):
            continue

        if int(items[1]) != calc_checksum(base64_encode(bytes(range(256)), b64alphabet)):
            continue

        return bytes(b64alphabet), items[0], int(items[2]), int(items[3]), int(items[4])

    return None


def probe_config_file(filepath, dumpdir):
    group_tag = None
    client_id = None
    config = None

    items = None
    b64alphabet = None
    bot_key = None
    ln_group_tag = None
    ln_client_id = None
    ln_config = None

    linenum = 0
    with open(filepath, 'rb') as f:
        for line in f:
            linenum += 1
            line = line.strip().split(b'=', 1)[-1].translate(None, b' ')
            if not all(_ in (BASE64_STANDARD + b'=') for _ in line):
                continue

            if not items:
                if len(line) < 96:
                    continue
                items = find_b64alphabet(line)
                if not items:
                    continue
                b64alphabet, bot_key, ln_group_tag, ln_client_id, ln_config = items
                log.info('[+] Found config file: %r', filepath)
                log.info('    [+] Base64 alphabet: %r', b64alphabet.decode())
                log.info('    [+] Bot ID: %r', bot_key.decode())
                linenum = 0
            elif linenum == ln_group_tag:
                data = xor(base64_decode(line, b64alphabet), bot_key)
                group_tag = data.decode('utf-16le')
            elif linenum == ln_client_id:
                data = xor(base64_decode(line, b64alphabet), bot_key)
                client_id = data.decode('utf-16le')
            elif linenum == ln_config:
                data = xor(base64_decode(line, b64alphabet), bot_key)
                config = decrypt_data(data)
            elif group_tag and client_id and config:
                log.info('    [+] Group tag: %r', group_tag)
                log.info('    [+] Client ID: %r', client_id)
                log.info('    [+] Configuration: %r', config.decode())
                with open(os.path.join(dumpdir, 'config.xml'), 'wb') as f:
                    f.write(config)
                return bot_key

    return None


def decrypt_module_configs(bot_key, directory, dumpdir):
    numfiles = 0
    for entry in os.listdir(directory):
        path = os.path.join(directory, entry)
        if not os.path.isfile(path):
            continue

        with open(path, 'rb') as f:
            data = f.read()

        decrypted = decrypt_data(xor(data, bot_key))
        if decrypted is None:
            continue

        log.info('[+] Found module config: %r', path)

        outfile = os.path.join(dumpdir, '{}_{}.xml'.format(os.path.basename(directory).rsplit('_', 1)[0], entry))
        with open(outfile, 'wb') as f:
            f.write(decrypted)
        numfiles += 1

    if numfiles == 0:
        raise FileNotFoundError

    return numfiles


def decrypt_modules(bot_key, directory, dumpdir):
    numfiles = 0
    for entry in os.listdir(directory):
        if not entry.endswith(('32', '64')):
            continue
        path = os.path.join(directory, entry)
        if not os.path.isfile(path):
            continue

        with open(path, 'rb') as f:
            data = f.read()

        decrypted = decrypt_data(xor(data, bot_key))
        if decrypted is None:
            continue
        if not decrypted.startswith(b'MZ'):
            continue

        log.info('[+] Found module binary: %r', path)

        outfile = os.path.join(dumpdir, entry + '.dll')
        with open(outfile, 'wb') as f:
            f.write(decrypted)
        numfiles += 1

        try:
            numfiles += decrypt_module_configs(bot_key, os.path.join(directory, entry + '_configs'), dumpdir)
        except FileNotFoundError:
            continue

    if numfiles == 0:
        raise FileNotFoundError

    return numfiles


def main():
    parser = argparse.ArgumentParser(description='Decrypts and dumps various artifacts (current configuration, modules and module configurations) from a computer infected with Trickbot')
    parser.add_argument('directory', nargs='?', default='.', help='Trickbot malware directory')
    parser.add_argument('-d', '--dumpdir', default='decrypted', help='Dump directory for the decrypted files')
    args = parser.parse_args()

    args.dumpdir = os.path.abspath(args.dumpdir)
    os.makedirs(args.dumpdir, exist_ok=True)

    numfiles = 0
    bot_key = None
    for entry in os.listdir(args.directory):
        path = os.path.join(args.directory, entry)
        if not os.path.isfile(path):
            continue
        if os.path.samefile(path, sys.argv[0]):
            continue

        log.info('[?] Probing config file: %r', path)
        bot_key = probe_config_file(path, args.dumpdir)
        if bot_key:
            numfiles += 1
            break

    if not bot_key:
        log.error('[!] ERROR: Failed to find bot key')
        return

    for entry in os.listdir(args.directory):
        path = os.path.join(args.directory, entry)
        if not os.path.isdir(path):
            continue
        if os.path.samefile(path, args.dumpdir):
            continue

        try:
            numfiles += decrypt_modules(bot_key, path, args.dumpdir)
            break
        except FileNotFoundError:
            continue

    if numfiles > 0:
        log.info('[+] Saved %d decrypted file(s) to: %r', numfiles, args.dumpdir)
    else:
        log.error('[!] ERROR: Failed to decrypt any files')


if __name__ == '__main__':
    main()
