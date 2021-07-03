

SBox = [0x0B, 0x0F, 0x03, 0x02, 0x0A, 0x0C, 0x09, 0x01, 0x06, 0x07, 0x08, 0x00, 0x0E, 0x05, 0x0D, 0x04]
# Inverse substitution box used on individual nibbles
InvSBox = [0x0B, 0x07, 0x03, 0x02, 0x0F, 0x0D, 0x08, 0x09, 0x0A, 0x06, 0x04, 0x00, 0x05, 0x0E, 0x0C, 0x01]

RC = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0x91, 0xa8, 0xe2, 0x30, 0x07, 0x37, 0x44,
    0x4a, 0x90, 0x83, 0x22, 0x92, 0xf9, 0x13, 0x0d,
    0x80, 0xe2, 0xaf, 0x89, 0xce, 0xe4, 0xc6, 0x98
]

_State = [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE]
Key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]

def cipher(ExtendedKey):
    """ The complete PRINCE forward encryption on the 64-bit state performed through nibble calculations """
    global _State

    _State = [_State[i] ^ ExtendedKey[i] for i in range(8)]

    _AddKey(ExtendedKey)
    _AddRoundConstant(0)

    
    _SubNibbles()
    _MLayer()
    _AddRoundConstant(1)
    _AddKey(ExtendedKey)
    
    _SubNibbles()
    _MPrimeLayer()
    _InvSubNibbles()

    _AddKey(ExtendedKey)
    _AddRoundConstant(2)
    _InvMLayer()
    _InvSubNibbles()

    _AddRoundConstant(3)
    _AddKey(ExtendedKey)

    _State = [_State[i] ^ ExtendedKey[i+8] for i in range(8)]

def ExtendKey(Key):
    """ PRINCE's version of a key schedule, which extends our 128-bit key to a 192-bit key """
    newKey = [0x00] * 24
    
    for i in range(8):
        # k_0 stays the same
        newKey[i] = Key[i]
        # k'_0 is a k_0 rotated right one bit and XORed with the last bit
        newKey[i + 8] = (Key[i] >> 1) | (Key[(i + 1) % 8] << 7 & 0x80)
        # k_1 stays the same
        newKey[i + 16] = Key[i + 8]
    
    newKey[15] ^= (Key[7] & 0x10)
    
    return newKey

def _ShiftRows():
    """ Helper method which distinguishes our two linear layers M from M' """
    global _State
    
    temp = _State[:] # copy the state into a temporary holder
    perm = [0, 5, 2, 7, 4, 1, 6, 3]
    
    _State = [ (temp[perm[i]] & 0x0F) | (_State[perm[(i+2)%8]] & 0xF0) for i in range(8)]


def _InvShiftRows():
    """ Inverse of our ShiftRows() function which allows us to distinguish M'^-1 from M^-1 """
    global _State
    
    temp = _State[:] # copy the state into a temporary holder
    perm = [0, 5, 2, 7, 4, 1, 6, 3]
    
    _State = [ (temp[perm[i]] & 0x0F) | (_State[perm[(i+6)%8]] & 0xF0) for i in range(8)]


def _SubNibbles():
    """ Send the state through a substitution layer nibble-by-nibble """
    global _State
    _State = [ (SBox[_State[i] >> 4] << 4) | SBox[_State[i] & 0x0F] for i in range(8) ]


def _InvSubNibbles():
    """ Inverse of our substitution layer which sends each substituted nibble back to the original nibble """
    global _State
    _State = [ (InvSBox[_State[i] >> 4] << 4) | InvSBox[_State[i] & 0x0F] for i in range(8) ]


def _MPrimeLayer():
    """ Our linear layer, designed to use as little space as possible and prevent wasted clock-cycles. Recall that this method is in fact its own inverse. """
    global _State
    
    # M0
    temp = _State[0] # we only need 1 storage variable here
    _State[0] = (temp & 0xD7) ^ (_State[1] & 0x7D) ^ (temp >> 4 & 0x0B) ^ (_State[1] >> 4 & 0x0E) ^ (temp << 4 & 0xB0) ^ (_State[1] << 4 & 0xE0)
    _State[1] = (temp & 0x7D) ^ (_State[1] & 0xD7) ^ (temp >> 4 & 0x0E) ^ (_State[1] >> 4 & 0x0B) ^ (temp << 4 & 0xE0) ^ (_State[1] << 4 & 0xB0)
    # M1
    temp = _State[2]
    _State[2] = (temp & 0xEB) ^ (_State[3] & 0xBE) ^ (temp >> 4 & 0x0D) ^ (_State[3] >> 4 & 0x07) ^ (temp << 4 & 0xD0) ^ (_State[3] << 4 & 0x70)
    _State[3] = (temp & 0xBE) ^ (_State[3] & 0xEB) ^ (temp >> 4 & 0x07) ^ (_State[3] >> 4 & 0x0D) ^ (temp << 4 & 0x70) ^ (_State[3] << 4 & 0xD0)
    # M1
    temp = _State[4]
    _State[4] = (temp & 0xEB) ^ (_State[5] & 0xBE) ^ (temp >> 4 & 0x0D) ^ (_State[5] >> 4 & 0x07) ^ (temp << 4 & 0xD0) ^ (_State[5] << 4 & 0x70)
    _State[5] = (temp & 0xBE) ^ (_State[5] & 0xEB) ^ (temp >> 4 & 0x07) ^ (_State[5] >> 4 & 0x0D) ^ (temp << 4 & 0x70) ^ (_State[5] << 4 & 0xD0)
    # M0
    temp = _State[6]
    _State[6] = (temp & 0xD7) ^ (_State[7] & 0x7D) ^ (temp >> 4 & 0x0B) ^ (_State[7] >> 4 & 0x0E) ^ (temp << 4 & 0xB0) ^ (_State[7] << 4 & 0xE0)
    _State[7] = (temp & 0x7D) ^ (_State[7] & 0xD7) ^ (temp >> 4 & 0x0E) ^ (_State[7] >> 4 & 0x0B) ^ (temp << 4 & 0xE0) ^ (_State[7] << 4 & 0xB0)

def _MLayer():
    """ The adjusted linear layer which is utilized each regular round """
    _MPrimeLayer()
    _ShiftRows()

def _InvMLayer():
    """ The inverse adjusted linear layer which is utilized each inverse regular round """
    _InvShiftRows()
    _MPrimeLayer()

def _AddRoundConstant(round):
    """ Function which simply applies a given round's constant to the state """
    global _State
    _State = [ _State[i] ^ RC[8 * round + i] for i in range(8)]

def _AddKey(ExtendedKey):
    """ Function which adds k_1 to the state """
    global _State
    _State = [ _State[i] ^ ExtendedKey[i + 16] for i in range(8) ]


if __name__ == "__main__":
    ExtendedKey = ExtendKey(Key)
    cipher(ExtendedKey)
    print('0x', end='')
    for i in range(8):
        print(format(_State[i] >> 4 | (_State[i] << 4 & 0xF0), '02x'), end='')
    print()