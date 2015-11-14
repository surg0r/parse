__author__ = 'pete'

#Python 2.7 script to parse a blockchain .dat and extract bitcoin pubkey hashes (hex) and derive all used addresses
#bug where the version byte isn't being coded during b58 encoding so I simply prefix it manually.
#addresses linked to a database..

import binascii
import glob
from bitcoin import *
import hashlib
import MySQLdb



def to_hex(bytestring):
    """
    convert given little-endian bytestring to hex
    """
    return binascii.hexlify(bytestring[::-1])


def double_hash(bytestring):
    """
    double SHA256 hash given bytestring
    """
    return hashlib.sha256(hashlib.sha256(bytestring).digest()).digest()


def hash160(bytestring):
    """
    SHA256 hash of given bytestring followed by RIPEMD-160 hash
    """
    return hashlib.new('ripemd160', hashlib.sha256(bytestring).digest()).digest()


def base58(bytestring):
    """
    base58 encode given bytestring
    """
    base58_characters = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value = int(binascii.hexlify(bytestring), 16)

    result = ""
    while value >= len(base58_characters):
        value, mod = divmod(value, len(base58_characters))
        result += base58_characters[mod]
    result += base58_characters[value]

    # handle leading zeros
    for byte in bytestring:
        if byte == 0:
            result += base58_characters[0]
        else:
            break

    return result[::-1]


def ripemd160_to_address(key_hash):
    version = b"\00"
    #version = chr(0)
    checksum = double_hash(version + key_hash)[:4]
    return base58(version + key_hash + checksum)


def public_key_to_address(public_key):
    return ripemd160_to_address(hash160(public_key))

class Database:

    def __init__(self):
        self.host = 'localhost'
        self.user = 'pydb'
        self.passwd = 'password'
        self.db  = 'pydb'
        self.connection = MySQLdb.connect(self.host, self.user, self.passwd, self.db)

    def query(self, q):
        cursor = self.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(q)
        return cursor.fetchall()

    def commit(self):
        self.connection.commit()

    def __del__(self):
        self.connection.close()

class Block_Chain:
    def __init__(self, data):
         self.index = 0
         self.blockcount = 0
         self.data = data

    def uint_8(self):
        data = self.data[self.index]
        self.index += 1
        return ord(data)

    def uint_16(self):
         return self.uint_8() + (self.uint_8() << 8)

    def uint_32(self):
        return self.uint_16() + (self.uint_16() << 16)

    def uint_64(self):
      return self.uint_32() + (self.uint_32() << 32)

    def byte_string(self,length):
        byte_string = self.data[self.index:self.index+length]
        self.index += length
        return byte_string

    def var_int_len(self):
        data = self.uint_8()
        if data < 0xFD:
            return data
        elif data == 0xFD:
            return self.uint_16()
        elif data == 0xFE:
            return self.uint_32()
        elif data == 0xFF:
            return self.uint_64()



class Block:
    def __init__(self,magic_bytes):
        self.magic_byte = magic_bytes
        self.block_length = bc.uint_32()
        self.version = bc.uint_32()
        self.hash = to_hex(bc.byte_string(32))        #might be problem with hexlify..check args..
        self.merkle = to_hex(bc.byte_string(32))
        self.timestamp = bc.uint_32()
        self.diff = bc.uint_32()
        self.nonce = bc.uint_32()

        self.transaction_count = bc.var_int_len()

        for x in range(self.transaction_count):
            trans = Transaction()

class Transaction:
    def __init__(self):
        self.transaction_version_number = bc.uint_32()
        self.total_inputs = bc.var_int_len()

        for x in range(self.total_inputs):
            inpu = Input()

        self.total_outputs = bc.var_int_len()

        for x in range(self.total_outputs):
            outpu = Output()


        self.transaction_lock_time = bc.uint_32()


class Input:
    def __init__(self):
        self.hash = to_hex(bc.byte_string(32))
        self.transaction_index = bc.uint_32()
        self.scriptlength = bc.var_int_len()
        self.script = bc.byte_string(self.scriptlength)
        self.sequence_number = bc.uint_32()

class Output:                                   #useful script info https://en.bitcoin.it/wiki/Script
    def __init__(self):
        self.value = bc.uint_64()

        #could insert value stripping code but addresses may be reused to probably no need

        self.scriptlength = bc.var_int_len()
        self.script = bc.byte_string(self.scriptlength)     #contains pubkey

        if self.scriptlength < 65:      #if <66 bytes then probably compressed key (20 byte pubkey hash)
            if ord(self.script[0]) == 118:  #OP_DUP
                if ord(self.script[1]) == 169:  #OP_HASH160
                    if ord(self.script[2]) == 20:    #20 byte pubkeyhash
                        if ord(self.script[23]) == 0x88:    #OP_EQUALVERIFY
                            if ord(self.script[24]) == 0xAC:    #OP_CHECKSIG
                                pubkeys.append(binascii.hexlify(self.script[3:23]))
                                addresses.append('1'+ripemd160_to_address(self.script[3:23]))


        else:                               #extract unhashed early 65 byte public keys
            if self.scriptlength == 67:
                if ord(self.script[0]) == 65:
                    pubkeys.append(binascii.hexlify(self.script[1:66]))
                    addresses.append('1'+public_key_to_address(self.script[1:66]))

            if self.scriptlength == 66:
                if ord(self.script[65]) == 172:      #OP_CHECKSIG
                    pubkeys.append(binascii.hexlify(self.script[0:65]))
                    addresses.append('1'+public_key_to_address(self.script[0:65]))


if __name__ == "__main__":

    ran_addr = []
    match = []
    pubkeys = []
    addresses = []


    db = Database()                     #import the list of generated bitcoin addresses from database
    q = "SELECT VERSION()"
    print db.query(q)
    q = 'SELECT ADDR FROM BRAIN'
    ran_addr = db.query(q)
    print 'Imported '+str(len(ran_addr))+' addresses from mysql..'


    bcfiles = glob.glob('./*.dat')
    for bcf in range(len(bcfiles)):
        bcfile = open(bcfiles[bcf])
        blkdata = bcfile.read()

        print 'Parsing '+bcfiles[bcf]

        bc = Block_Chain(blkdata)

        for x in range(len(blkdata)):          #this and code below could be performed class Block_Chain

            if bc.index > len(blkdata)-4:        #reached the end of the dat file..
                print bcfiles[bcf]+', blocks:'+str(bc.blockcount)+' total addresses n: '+str(len(addresses))
                #mysql db insertion code here..
                #for x in range()
                #   for x in range(len(addresses)):
                #       q="INSERT INTO BTC (PUBKEYHASH,ADDRESS) VALUES ('%s','%s')" % (pubkeys[x],addresses[x])
                #       db.query(q)
                #       db.commit()
                #       time.sleep(0.0001)
                break

            magic_bytes = bc.uint_32()

            if magic_bytes == 0xD9B4BEF9:
                blk = Block(magic_bytes)
                bc.blockcount += 1
               # print 'Block '+str(bc.blockcount)+' @ '+str(x)+', len '+str(blk.block_length)
               # print 'Number of transactions: '+str(blk.transaction_count)
            else:
                bc.index -= 3                   #iterate through until hit magic byte..

    print 'Matching '+str(len(ran_addr))+' generated with '+str(len(addresses))+'..(this will take a long, long, long time)'
    for x in range(len(ran_addr)):
        for y in range(len(addresses)):
            if ran_addr[x] == addresses[y]:
                match.append(ran_addr[x])
                print ran_addr[x]
    print str(len(match))+' matches'