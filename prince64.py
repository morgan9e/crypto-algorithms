class prince:
    def __init__(self, inL: list, inK: list):
        self.SBox = [0x0B, 0x0F, 0x03, 0x02, 0x0A, 0x0C, 0x09, 0x01, 0x06, 0x07, 0x08, 0x00, 0x0E, 0x05, 0x0D, 0x04]
        self.InvSBox = [0x0B, 0x07, 0x03, 0x02, 0x0F, 0x0D, 0x08, 0x09, 0x0A, 0x06, 0x04, 0x00, 0x05, 0x0E, 0x0C, 0x01]

        self.RC = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x31, 0x91, 0xa8, 0xe2, 0x30, 0x07, 0x37, 0x44,
            0x4a, 0x90, 0x83, 0x22, 0x92, 0xf9, 0x13, 0x0d,
            0x80, 0xe2, 0xaf, 0x89, 0xce, 0xe4, 0xc6, 0x98
        ]

        self._plaintext = inL
        self.Key = inK

    def cipher(self, ExKey):

        self._plaintext = [self._plaintext[i] ^ ExKey[i] for i in range(8)]

        self._AddKey(ExKey)
        self._RCLayer(0)

        
        self._SLayer()
        self._MLayer()
        self._RCLayer(1)
        self._AddKey(ExKey)
        
        self._SLayer()
        self._MPrimeLayer()
        self._InvSLayer()

        self._AddKey(ExKey)
        self._RCLayer(2)
        self._InvMLayer()
        self._InvSLayer()

        self._RCLayer(3)
        self._AddKey(ExKey)

        self._plaintext = [self._plaintext[i] ^ ExKey[i+8] for i in range(8)]

    def ExtendKey(self, Key):
        newKey = [0x00] * 24
        
        for i in range(8):
            newKey[i] = Key[i]
            newKey[i + 8] = (Key[i] >> 1) | (Key[(i + 1) % 8] << 7 & 0x80)
            newKey[i + 16] = Key[i + 8]
        
        newKey[15] ^= (Key[7] & 0x10)
        
        return newKey

    def _SR(self):
        temp = self._plaintext[:]
        perm = [0, 5, 2, 7, 4, 1, 6, 3]
        
        self._plaintext = [ (temp[perm[i]] & 0x0F) | (self._plaintext[perm[(i+2)%8]] & 0xF0) for i in range(8)]


    def _InvSR(self):
        temp = self._plaintext[:]
        perm = [0, 5, 2, 7, 4, 1, 6, 3]
        
        self._plaintext = [ (temp[perm[i]] & 0x0F) | (self._plaintext[perm[(i+6)%8]] & 0xF0) for i in range(8)]

    def _SLayer(self):
        self._plaintext = [ (self.SBox[self._plaintext[i] >> 4] << 4) | self.SBox[self._plaintext[i] & 0x0F] for i in range(8) ]


    def _InvSLayer(self):
        self._plaintext = [ (self.InvSBox[self._plaintext[i] >> 4] << 4) | self.InvSBox[self._plaintext[i] & 0x0F] for i in range(8) ]

    def _MPrimeLayer(self):
        temp = self._plaintext[0]
        self._plaintext[0] = (temp & 0xD7) ^ (self._plaintext[1] & 0x7D) ^ (temp >> 4 & 0x0B) ^ (self._plaintext[1] >> 4 & 0x0E) ^ (temp << 4 & 0xB0) ^ (self._plaintext[1] << 4 & 0xE0)
        self._plaintext[1] = (temp & 0x7D) ^ (self._plaintext[1] & 0xD7) ^ (temp >> 4 & 0x0E) ^ (self._plaintext[1] >> 4 & 0x0B) ^ (temp << 4 & 0xE0) ^ (self._plaintext[1] << 4 & 0xB0)
        temp = self._plaintext[2]
        self._plaintext[2] = (temp & 0xEB) ^ (self._plaintext[3] & 0xBE) ^ (temp >> 4 & 0x0D) ^ (self._plaintext[3] >> 4 & 0x07) ^ (temp << 4 & 0xD0) ^ (self._plaintext[3] << 4 & 0x70)
        self._plaintext[3] = (temp & 0xBE) ^ (self._plaintext[3] & 0xEB) ^ (temp >> 4 & 0x07) ^ (self._plaintext[3] >> 4 & 0x0D) ^ (temp << 4 & 0x70) ^ (self._plaintext[3] << 4 & 0xD0)
        temp = self._plaintext[4]
        self._plaintext[4] = (temp & 0xEB) ^ (self._plaintext[5] & 0xBE) ^ (temp >> 4 & 0x0D) ^ (self._plaintext[5] >> 4 & 0x07) ^ (temp << 4 & 0xD0) ^ (self._plaintext[5] << 4 & 0x70)
        self._plaintext[5] = (temp & 0xBE) ^ (self._plaintext[5] & 0xEB) ^ (temp >> 4 & 0x07) ^ (self._plaintext[5] >> 4 & 0x0D) ^ (temp << 4 & 0x70) ^ (self._plaintext[5] << 4 & 0xD0)
        temp = self._plaintext[6]
        self._plaintext[6] = (temp & 0xD7) ^ (self._plaintext[7] & 0x7D) ^ (temp >> 4 & 0x0B) ^ (self._plaintext[7] >> 4 & 0x0E) ^ (temp << 4 & 0xB0) ^ (self._plaintext[7] << 4 & 0xE0)
        self._plaintext[7] = (temp & 0x7D) ^ (self._plaintext[7] & 0xD7) ^ (temp >> 4 & 0x0E) ^ (self._plaintext[7] >> 4 & 0x0B) ^ (temp << 4 & 0xE0) ^ (self._plaintext[7] << 4 & 0xB0)

    def _MLayer(self):
        self._MPrimeLayer()
        self._SR()

    def _InvMLayer(self):
        self._InvSR()
        self._MPrimeLayer()

    def _RCLayer(self, round):
        self._plaintext = [ self._plaintext[i] ^ self.RC[8 * round + i] for i in range(8)]

    def _AddKey(self, ExKey):
        self._plaintext = [ self._plaintext[i] ^ ExKey[i + 16] for i in range(8) ]

    def prince(self):
        ExKey = self.ExtendKey(self.Key)
        self.cipher(ExKey)
        return [nibble >> 4 | (nibble << 4 & 0xF0) for nibble in self._plaintext]

    def start(self):
        ExKey = self.ExtendKey(self.Key)
        self.cipher(ExKey)
        print('0x', end='')
        for i in range(8):
            print(format(self._plaintext[i] >> 4 | (self._plaintext[i] << 4 & 0xF0), '02x'), end='')
        print()