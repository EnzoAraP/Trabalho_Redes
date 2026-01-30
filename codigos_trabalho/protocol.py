# protocol.py
import struct

import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- helpers de chave / criptografia ---
def gen_x25519_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return priv, pub  # priv é objeto X25519PrivateKey, pub é bytes(32)

def derive_symmetric_key(priv: x25519.X25519PrivateKey, peer_pub_bytes: bytes):
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = priv.exchange(peer_pub)  # 32 bytes
    # Derivar chave com HKDF -> 32 bytes (para AES-256-GCM) ou 16 bytes para AES-128
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"udp-tf-session",
    ).derive(shared)
    return key  # bytes

def encrypt_payload_aesgcm(key: bytes, header_bytes: bytes, plaintext: bytes):
    aes = AESGCM(key)
    nonce = os.urandom(12)  # 12 bytes padrão para GCM
    ct = aes.encrypt(nonce, plaintext, header_bytes)  # usa header como AAD
    return nonce + ct  # formato: nonce || ciphertext_with_tag

def decrypt_payload_aesgcm(key: bytes, header_bytes: bytes, enc_payload: bytes):
    try:
        nonce = enc_payload[:12]
        ct = enc_payload[12:]
        aes = AESGCM(key)
        pt = aes.decrypt(nonce, ct, header_bytes)
        return pt
    except Exception as e:
        raise ValueError("decryption failed") from e

# Cabeçalho: seq(4) | ack(4) | flags(1) | rwnd(2)
HEADER_FORMAT = "!IIBH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

FLAG_SYN  = 0x01
FLAG_ACK  = 0x02
FLAG_FIN  = 0x04
FLAG_DATA = 0x08

def make_packet(seq, ack, flags, rwnd=0, payload=b"", key=None):
    header = struct.pack(HEADER_FORMAT, seq, ack, flags, rwnd)
    if key is not None and payload:
        enc = encrypt_payload_aesgcm(key, header, payload)
        return header + enc
    else:
        return header + payload

def parse_packet(data, key=None):
    header = data[:HEADER_SIZE]
    payload = data[HEADER_SIZE:]
    seq, ack, flags, rwnd = struct.unpack(HEADER_FORMAT, header)
    if key is not None and (flags & FLAG_DATA) and payload:
        # tentamos decriptografar; se falhar, lança exceção
        payload = decrypt_payload_aesgcm(key, header, payload)
    return seq, ack, flags, rwnd, payload



LOSS_RATE = 0.000