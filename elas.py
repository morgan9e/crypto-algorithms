from dataclasses import dataclass
from random import randint


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
                curve=secp256k1
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
                curve=secp256k1
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


if __name__ == "__main__":

    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A = 0
    B = 7

    field = PrimeGaloisField(prime=P)
    secp256k1 = EllipticCurve(a=A, b=B, field=field)

    G = Point(
    x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    curve=secp256k1)
    
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    I = Point(x=None, y=None, curve=secp256k1)

    inf = float("inf")

    priv: int = 0xea11d6ada978a0b491aa5cbbe4df17a65c2fecc24448e95d1ccd854b43991bec
    e = PrivateKey(priv)

    pub = e.secret * G
    print(pub)
    z = 0x7e240de74fb1ed08fa08d38063f6a6a91462a815
    
    signature: Signature = e.sign(z)
    print(e.sign(z))
    assert signature.verify(z, pub)