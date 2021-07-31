from dataclasses import dataclass
from random import randint
from random import randrange
import hashlib
import base64

@dataclass
class PrimeGaloisField:
    prime: int

    def __contains__(self, field_value: "FieldElement") -> bool:

        return 0 <= field_value.value < self.prime


@dataclass
class FieldElement:
    value: int
    field: PrimeGaloisField

    def __repr__(self):
        return "0x" + f"{self.value:x}".zfill(64)

    @property
    def P(self) -> int:
        return self.field.prime

    def __add__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(
            value=(self.value + other.value) % self.P,
            field=self.field
        )

    def __sub__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(
            value=(self.value - other.value) % self.P,
            field=self.field
        )

    def __rmul__(self, scalar: int) -> "FieldValue":
        return FieldElement(
            value=(self.value * scalar) % self.P,
            field=self.field
        )

    def __mul__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(
            value=(self.value * other.value) % self.P,
            field=self.field
        )

    def __pow__(self, exponent: int) -> "FieldElement":
        return FieldElement(
            value=pow(self.value, exponent, self.P),
            field=self.field
        )

    def __truediv__(self, other: "FieldElement") -> "FieldElement":
        other_inv = other ** -1
        return self * other_inv


@dataclass
class EllipticCurve:
    a: int
    b: int

    field: PrimeGaloisField

    def __contains__(self, point: "Point") -> bool:
        x, y = point.x, point.y
        return y ** 2 == x ** 3 + self.a * x + self.b

    def __post_init__(self):

        self.a = FieldElement(self.a, self.field)
        self.b = FieldElement(self.b, self.field)

        if self.a not in self.field or self.b not in self.field:
            raise ValueError


@dataclass
class Point:
    x: int
    y: int

    curve: EllipticCurve

    def __post_init__(self):

        if self.x is None and self.y is None:
            return

        self.x = FieldElement(self.x, self.curve.field)
        self.y = FieldElement(self.y, self.curve.field)

        if self not in self.curve:
            raise ValueError

    def __add__(self, other):

        if self == I:
            return other

        if other == I:
            return self

        if self.x == other.x and self.y == (-1 * other.y):
            return I

        if self.x != other.x:
            x1, x2 = self.x, other.x
            y1, y2 = self.y, other.y

            s = (y2 - y1) / (x2 - x1)
            x3 = s ** 2 - x1 - x2
            y3 = s * (x1 - x3) - y1

            return self.__class__(
                x=x3.value,
                y=y3.value,
                curve=self.curve
            )

        if self == other and self.y == inf:
            return I

        if self == other:
            x1, y1, a = self.x, self.y, self.curve.a

            s = (3 * x1 ** 2 + a) / (2 * y1)
            x3 = s ** 2 - 2 * x1
            y3 = s * (x1 - x3) - y1

            return self.__class__(
                x=x3.value,
                y=y3.value,
                curve=self.curve
            )

    def __rmul__(self, scalar: int) -> "Point":

        current = self
        result = I
        while scalar:
            if scalar & 1:
                result = result + current
            current = current + current
            scalar >>= 1
        return result


@dataclass
class Signature:
    r: int
    s: int

    def verify(self, z: int, pub_key: Point) -> bool:
        s_inv = pow(self.s, -1, N)
        u = (z * s_inv) % N
        v = (self.r * s_inv) % N
        return (u*G + v*pub_key).x.value == self.r

@dataclass
class PrivateKey:
    secret: int

    def sign(self, z: int) -> Signature:
        e = self.secret
        k = randint(0, N)
        R = k * G
        r = R.x.value
        k_inv = pow(k, -1, N)
        s = ((z + r*e) * k_inv) % N

        return Signature(r, s)

def sha256(msg: str):
    hash = int('0x'+hashlib.sha256(msg.encode()).hexdigest(), 16)
    return hash

def sha1(msg: str):
    hash = int('0x'+hashlib.sha1(msg.encode()).hexdigest(), 16)
    return hash

def lsh(msg: str):
    from lsh import LSHDigest
    lsh = LSHDigest.getInstance(256, 256)
    lsh.update(msg.encode())
    hash = lsh.final()
    return hex(int.from_bytes(hash,'big'))

def largePrime(bit):
    def rand(n):
        return randrange(2**(n-1)+1, 2**n-1)

    def gLLP(n):
        while True: 
      
            # Obtain a random number
            prime_candidate = rand(n) 
      
            for divisor in first_primes_list: 
                if prime_candidate % divisor == 0 and divisor**2 <= prime_candidate:
                    break
                # If no divisor found, return value
                else: return prime_candidate

    def iMRP(miller_rabin_candidate):
        maxDivisionsByTwo = 0
        evenComponent = miller_rabin_candidate-1
      
        while evenComponent % 2 == 0:
            evenComponent >>= 1
            maxDivisionsByTwo += 1
        assert(2**maxDivisionsByTwo * evenComponent == miller_rabin_candidate-1)
      
        def trialComposite(round_tester):
            if pow(round_tester, evenComponent, miller_rabin_candidate) == 1:
                return False
            for i in range(maxDivisionsByTwo):
                if pow(round_tester, 2**i * evenComponent, miller_rabin_candidate) == miller_rabin_candidate-1:
                    return False
            return True
      
        # Set number of trials here
        numberOfRabinTrials = 20 
        for i in range(numberOfRabinTrials):
            round_tester = randrange(2, miller_rabin_candidate)
            if trialComposite(round_tester):
                return False
        return True

    first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67, 
                     71, 73, 79, 83, 89, 97, 101, 103, 
                     107, 109, 113, 127, 131, 137, 139, 
                     149, 151, 157, 163, 167, 173, 179, 
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]

    while True:
        n = bit
        prime_candidate = gLLP(n)
        if not iMRP(prime_candidate):
            continue
        else:
            return prime_candidate
            break

def b64e(data: int):
    base64_bytes = base64.b64encode(bytes.fromhex(str(data).replace('0x','')))
    base64_message = base64_bytes.decode('ascii')
    return base64_message

if __name__ == "__main__":

    ######[ SEC-P256-r1 ]#####################################################

    P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    inf = float("inf")

    field = PrimeGaloisField(prime=P)
    secp256r1 = EllipticCurve(a=A, b=B, field=field)

    G = Point(
    x=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    y=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    curve=secp256r1)    
    I = Point(x=None, y=None, curve=secp256r1)

    #####################################################################

    priv = 0x9f07090a27c7f3eaf51980059cae33420865890c72d51a8d3a20fee02c82afc63ab79c604ec6b691b94bc288b910327cd38cce7f11b61ab330b9b506c149722f
    #largePrime(512)
    msg = ''
    
    z = sha256(msg)

    e = PrivateKey(priv)
    pub = e.secret * G
    
    signature = e.sign(z)
    # print(signature.verify(z, pub))

    f_pubKey = hex(int(f'0x40{str(pub.x).replace("0x","")}{str(pub.y).replace("0x","")}',16))
    f_privKey = hex(priv)
    f_msg = hex(z)
    f_Sign = hex(int(f'0x30450220{str(hex(e.sign(z).r)).replace("0x","")}022100{str(hex(e.sign(z).s)).replace("0x","")}',16))

    print(b64e(f_pubKey))