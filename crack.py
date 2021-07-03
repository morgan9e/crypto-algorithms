from prince64 import prince

plainfile = open("pt.dat", "rb")
cipherfile = open("ct.dat", "rb")

pbyte = plainfile.read(8)
cbyte = cipherfile.read(8)
pbytearay = [((a&0x0F)<<4)|((a&0xF0)>>4) for a in list(pbyte)][::-1]
cbytearay = [((a&0x0F)<<4)|((a&0xF0)>>4) for a in list(cbyte)][::-1]
a = prince(pbytearay,[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
a.start()