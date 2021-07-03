G = Point(
    x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    curve=secp256k1)

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

I = Point(x=None, y=None, curve=secp256k1)

assert N * G == I

pub = Point(
    x=0x9577FF57C8234558F293DF502CA4F09CBC65A6572C842B39B366F21717945116,
    y=0x10B49C67FA9365AD7B90DAB070BE339A1DAF9052373EC30FFAE4F72D5E66D053,
    curve=secp256k1
)
d: int = 2 ** 240 + 2 ** 31
print(d * G)
print(pub)

e = PrivateKey(randint(0, N))
pub = e.secret * G
z = randint(0, 2 ** 256)
signature: Signature = e.sign(z)
assert signature.verify(z, pub)
