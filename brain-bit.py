import base58
import hashlib
 
from fastecdsa import curve
from fastecdsa import keys
 
updhsh = lambda h, s: [h.update(s), h][1]
b58chk = lambda s: base58.b58encode(bytes(hexbyt(s)))
concat = lambda s1, s2: "{}{}".format(s1, s2)
hexbyt = lambda s: bytes(bytearray.fromhex(s))
rmd160 = lambda s: updhsh(hashlib.new('ripemd160'), hexbyt(s)).hexdigest()
sha256 = lambda s: hashlib.sha256(hexbyt(s)).hexdigest()
 
def btc_public_key(public_key):
    k1 = sha256(public_key)
    k2 = concat('00', rmd160(k1))
    k3 = sha256(sha256(k2))
    k4 = k3[:8]
    k5 = concat(k2, k4)
    k6 = b58chk(k5)
    return k6
 
private_key, public_key = keys.gen_keypair(curve.secp256k1)
public_key = "04{:x}{:x}".format(public_key.x, public_key.y)
 
print(private_key)
print(btc_public_key(public_key))