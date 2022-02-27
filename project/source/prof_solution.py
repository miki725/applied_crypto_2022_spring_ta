#!/usr/bin/env python3
from Crypto.Cipher import AES
import argparse
import hashlib
import sys
import os
import getpass
import secrets
import json
import hmac
import re
import unicodedata


def err(msg="", endl="\n"):
    print(msg, file=sys.stderr, end=endl)


def fatal(msg="", endl="\n"):
    err(msg, endl)
    sys.exit(1)


def get_password():
    if sys.stdin.isatty():
        return getpass.getpass("password: ").encode("utf-8")
    else:
        return sys.stdin.readline().strip().encode("utf-8")


PBKDF2_ITERS = 250000
NUM_KEYS = 7
MD_FILE_PREFIX = ".fenc-meta."
WC_SMALLEST_WD = 4


def xor_bytes(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])


def get_master_info(pw, salt):
    raw = hashlib.pbkdf2_hmac(
        hash_name="sha256", password=pw, salt=salt, iterations=PBKDF2_ITERS, dklen=32
    )
    return raw[:16], raw[16:]


def ctr_block(ctx, starting_value, ix):
    blist = list(starting_value)
    i = 15
    blist[i] += ix

    while i:
        if blist[i] <= 255:
            break
        rem = blist[i] >> 8
        blist[i] &= 255
        i = i - 1
        blist[i] = blist[i] + rem

    return ctx.encrypt(bytes(blist))


def ctr_keystream(ctx, starting_value, num_bytes):
    ret = b""
    i = 0

    while len(ret) < num_bytes:
        ret += ctr_block(ctx, starting_value, i)
        i += 1

    return ret[:num_bytes]


def gen_key_schedule(master_key, start):
    ctx = AES.new(master_key, mode=AES.MODE_ECB)
    return [ctr_block(ctx, start, i) for i in range(NUM_KEYS)]


def ctr_mode_round(block, roundkey):
    lin = block[:16]
    rin = block[16:]
    ctx = AES.new(roundkey, AES.MODE_ECB)
    ks = ctr_keystream(ctx, lin, len(rin))

    return lin + xor_bytes(rin, ks)


def hmac_round(block, roundkey):
    lin = block[:16]
    rin = block[16:]
    ctx = hmac.new(roundkey, digestmod="sha256")

    ctx.update(rin)
    return xor_bytes(ctx.digest()[:16], lin) + rin


def block_cipher_encrypt(keysched, state):
    state = ctr_mode_round(state, keysched[1])
    state = hmac_round(state, keysched[2])
    state = ctr_mode_round(state, keysched[3])

    return hmac_round(state, keysched[4])


def block_cipher_decrypt(keysched, state):
    state = hmac_round(state, keysched[4])
    state = ctr_mode_round(state, keysched[3])
    state = hmac_round(state, keysched[2])

    return ctr_mode_round(state, keysched[1])


def mac_ciphertext(key, ct):
    ctx = hmac.new(key, digestmod="sha256")
    ctx.update(ct)
    return ctx.digest()


class EncFileInfo:
    def __init__(self, name, mdfd, mdpath, fd):
        self.name = name
        self.fd = fd
        self.mdfd = mdfd
        self.mdpath = mdpath

    def encrypt_setup(self, pw):
        self.bytearr = self.fd.read()
        self.bytelen = len(self.bytearr)
        self.salt = secrets.token_bytes(16)
        self.mk, self.nonce = get_master_info(pw, self.salt)
        self.sched = gen_key_schedule(self.mk, self.nonce)

        if len(self.bytearr) < 32:
            import pdb

            pdb.set_trace()
            err(f"{self.name}: File too small to encrypt. Skipping.")
            self.rm_metadata_file()
            self.skip_me = True
            return

        self.skip_me = False

        self.ct = block_cipher_encrypt(self.sched, self.bytearr)
        self.mac = mac_ciphertext(self.sched[5], self.ct)

        try:
            self.text = self.bytearr.decode("utf8")
            self.searchable = True
        except UnicodeDecodeError:
            self.searchable = False

        self.generate_terms()

    def compute_search_macs(self, wordlist):
        arr = [x.casefold() for x in wordlist]
        arr = [unicodedata.normalize("NFC", x) for x in arr]
        err(json.dumps(arr))
        arr = [x.encode("utf8") for x in arr]
        arr = [mac_ciphertext(self.sched[6], x) for x in arr]
        s = set(arr)  # Get rid of dupes,

        return list(s)  # But return a list so we can sort.

    def search_matches_any(self, termlist):
        to_find = self.compute_search_macs(termlist)

        for item in to_find:
            if item in self.terms:
                return True

        return False

    def add_wildcard_terms(self, arr):
        ret = set({})

        for item in arr:
            ret.add(item)
            for i in range(WC_SMALLEST_WD, len(item)):
                ret.add(item[:i] + "*")

        return list(ret)

    def generate_terms(self):
        if not self.searchable:
            self.terms = []
            return

        arr = re.findall(r"[\w]+", self.text, re.UNICODE)
        arr = [x for x in arr if (len(x) >= 4 and len(x) <= 12)]
        arr = self.add_wildcard_terms(arr)
        arr = self.compute_search_macs(arr)

        arr.sort()

        self.terms = arr

    def format_key_for_stdout(self, d):
        d[self.name] = (self.mk + self.nonce).hex()

    def write_encryption_output(self):
        if self.skip_me:
            return

        md_todump = {
            "salt": self.salt.hex(),
            "validator": self.sched[0].hex(),
            "mac": self.mac.hex(),
            "terms": [x.hex() for x in self.terms],
        }

        json.dump(md_todump, fp=self.mdfd)
        self.mdfd.close()

        self.fd.seek(0)
        self.fd.truncate()
        self.fd.write(self.ct)
        self.fd.close()

    def decrypt_setup(self, pw):
        try:
            self.metadata = json.load(self.mdfd)
            self.salt = bytearray.fromhex(self.metadata["salt"])
            self.validator = bytearray.fromhex(self.metadata["validator"])
            self.mac = bytearray.fromhex(self.metadata["mac"])
            self.terms = [bytearray.fromhex(x) for x in self.metadata["terms"]]
        except:
            fatal(f"{self.name}: bad metadata. Aborting.")

        self.mk, self.nonce = get_master_info(pw, self.salt)

        return

    def validate_password(self):
        self.sched = gen_key_schedule(self.mk, self.nonce)

        if self.validator != self.sched[0]:
            err(f"{self.name}: Password did not match.")
            return False

        return True

    def validate_mac(self):
        # Finally we can read the ciphertext.
        self.ct = self.fd.read()
        self.bytelen = len(self.ct)

        mac = mac_ciphertext(self.sched[5], self.ct)
        if mac != self.mac:
            err(
                f"{self.name}: Invalid MAC; ciphertext "
                "has been tampered with; cannot decrypt."
            )
            return False

        return True

    def rm_metadata_file(self):
        self.mdfd.seek(0)
        self.mdfd.truncate()
        self.mdfd.close()
        try:
            os.unlink(self.mdpath)
        except:
            pass

    def write_decryption_output(self):
        self.bytearr = block_cipher_decrypt(self.sched, self.ct)

        self.rm_metadata_file()

        self.fd.seek(0)
        self.fd.truncate()
        self.fd.write(self.bytearr)
        self.fd.close()


def get_encrypt_file_objs(file_list):
    ret = []
    bail = False
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY

    for fname in file_list:
        mdfd = None

        try:
            fd = open(fname, "r+b")
        except:
            err(f"{fname}: file not found.")
            bail = True

        try:
            dirname, basename = os.path.split(os.path.abspath(fname))
            mdpath = os.path.join(dirname, MD_FILE_PREFIX + basename)
            mdh = os.open(mdpath, flags)
            mdfd = open(mdh, "w")
        except:
            err(f"{fname}: file already encrypted.")
            bail = True

        finfo = EncFileInfo(fname, mdfd, mdpath, fd)
        ret.append(finfo)

    if bail:
        fatal("Not encrypting due to errors.")

    return ret


def get_decrypt_file_objs(file_list):
    ret = []
    bail = False

    for fname in file_list:
        try:
            fd = open(fname, "r+b")
        except:
            err(f"{fname}: file not found.")
            bail = true
        try:
            dirname, basename = os.path.split(os.path.abspath(fname))
            mdpath = os.path.join(dirname, MD_FILE_PREFIX + basename)
            mdfd = open(mdpath, "r+b")
            finfo = EncFileInfo(fname, mdfd, mdpath, fd)
            ret.append(finfo)
        except:
            err(f"{fname}: not encrypted (metadata file not found)")
            bail = True

    if bail:
        fatal("Not decrypting due to errors.")

    return ret


def dump_keys_if_requested(files, print_keys):
    if print_keys:
        keyinfo = {}
        [x.format_key_for_stdout(keyinfo) for x in files]
        json.dump(keyinfo, fp=sys.stdout)
        print()


def op_encrypt(file_list, print_keys):
    files = get_encrypt_file_objs(file_list)

    try:
        pw = get_password()
    except:
        for fobj in files:
            fobj.rm_metadata_file()
            raise

    for fobj in files:
        fobj.encrypt_setup(pw)

    dump_keys_if_requested(files, print_keys)

    for fobj in files:
        fobj.write_encryption_output()

    return


def op_decrypt(file_list, print_keys):
    files = get_decrypt_file_objs(file_list)
    pw = get_password()

    for fobj in files:
        fobj.decrypt_setup(pw)

    dump_keys_if_requested(files, print_keys)

    bail = False
    for fobj in files:
        if not fobj.validate_password():
            bail = True
    if bail:
        fatal("Not decrypting due to errors.")

    for fobj in files:
        if not fobj.validate_mac():
            bail = True

    if bail:
        fatal("Not decrypting due to errors.")

    for fobj in files:
        fobj.write_decryption_output()

    return


def op_search(terms, print_keys):
    ld = os.listdir()
    prefix = MD_FILE_PREFIX
    fnames = [x[len(prefix) :] for x in ld if x.startswith(prefix)]
    files = [EncFileInfo(x, open(prefix + x, "r"), prefix + x, None) for x in fnames]
    pw = get_password()
    results = []
    valid = []

    for fobj in files:
        fobj.decrypt_setup(pw)
        if not fobj.validate_password():
            continue
        valid.append(fobj)
        if fobj.search_matches_any(terms):
            results.append(fobj.name)

    dump_keys_if_requested(valid, print_keys)

    for item in results:
        print(item)


def parse_argv_and_go():
    ops = {"e": op_encrypt, "d": op_decrypt, "s": op_search}

    parser = argparse.ArgumentParser(prog="fencrypt")

    parser.add_argument("-e", action="store_true", help="Encrypt file(s) [default]")
    parser.add_argument("-d", action="store_true", help="Decrypt file(s)")
    parser.add_argument(
        "-s", action="store_true", help="Search files in the current directory"
    )
    parser.add_argument(
        "-j", action="store_true", help="Output the master keys associated with files."
    )
    parser.add_argument(
        "files",
        type=str,
        nargs="+",
        action="store",
        help="A list of file names to operate upon.",
    )

    arginfo = vars(parser.parse_args())

    # Figure out which operation we're doing, and if none is specified,
    # assume it is encrypt.
    op = None
    for flag in "eds":
        if arginfo[flag] == True:
            if op:
                fatal("Cannot perform multiple operations at once.")
            else:
                op = flag
    if not op:
        op = "e"

    ops[op](set(arginfo["files"]), arginfo["j"])


if __name__ == "__main__":
    parse_argv_and_go()
