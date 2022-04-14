# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
'''
This module detects cryptocurrency (currently just bitcoin) addresses in text.

Sandia National Labs
'''
from builtins import range, bytes
from hashlib import sha256
from binascii import unhexlify
from laikaboss.si_module import SI_MODULE
import logging

# re2 speeds up execution, but is optional
try:
    import re2 as re
    has_re2 = True
except ImportError:
    import re
    has_re2 = False

digits58 = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
digits32 = b'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

class META_CRYPTOCURRENCY(SI_MODULE):
    def __init__(self):
        self.module_name = 'META_CRYPTOCURRENCY'

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        bitcoinCandidates = re.findall(b'[0-9A-HJ-NP-Za-z]{25,}', scanObject.buffer)
        bitcoinAddresses = []
        for c in bitcoinCandidates:
            if self._check_address(c):
                bitcoinAddresses.append(c)
        if bitcoinAddresses:
            #Remove duplicates
            dedupAddresses = []
            for addr in bitcoinAddresses:
                if addr not in dedupAddresses:
                    dedupAddresses.append(addr)
            scanObject.addMetadata(self.module_name, 'bitcoin', dedupAddresses)
            scanObject.addFlag('crypto:bitcoin')
        return moduleResult

    @classmethod
    def _check_address(cls, addr):
        if addr.startswith(b'1') or addr.startswith(b'3'):
            return cls._check_bc(addr)
        elif addr.startswith(b'bc1'):
            parts = addr.split(b'1')
            if len(parts) > 1:
                try:
                    dataPart = [digits32.index(c) for c in parts[-1]]
                except ValueError:
                    return False
                return cls._bech32_verify_checksum(bytes(b''.join(parts[:-1])), dataPart)
        return False

    #This code is pulled from BIP 173
    @staticmethod
    def _bech32_polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = (chk >> 25)
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk

    @staticmethod
    def _bech32_hrp_expand(s):
        return [x >> 5 for x in s] + [0] + [x & 31 for x in s]

    @classmethod
    def _bech32_verify_checksum(cls, hrp, data):
        return cls._bech32_polymod(cls._bech32_hrp_expand(hrp) + data) == 1 

    #The following two methods are adapted from http://rosettacode.org/wiki/Bitcoin/address_validation
    @classmethod
    def _decode_base58(cls, bc, length):
        n = 0
        for char in bc:
            n = n * 58 + digits58.index(char)
        return cls._to_bytes(n, length)

    @classmethod
    def _check_bc(cls, bc):
        try:
            bcbytes = cls._decode_base58(bc, 25)
            return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]
        except Exception:
            return False

    #Extra to_bytes function because python 2 doesn't have nice things
    @staticmethod
    def _to_bytes(n, length):
        h = '%x' % n
        s = ('0'*(len(h) % 2) + h).zfill(length*2)
        return unhexlify(s)
