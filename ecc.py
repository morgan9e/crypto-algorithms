from random import *
import math
A = 0
B = 7
P = 2**21 - 1# 2**256 - 2**224 + 2**192 + 2**96 - 1

def doubleing(point):
	x1 = point[0]
	y1 = point[1]

	lamda = ((3*(x1**2)+A) % P) * ((2*y1)**(P-2) % P) % P
	x2 = (lamda**2 - 2*x1) % P
	y2 = ((x1 - x2)*lamda - y1) % P

	return (x2, y2)

def adding(point1, point2):
	x1 = point1[0]
	y1 = point1[1]
	x2 = point2[0]
	y2 = point2[1]

	lamda = (((y2 - y1) % P) * ((x2 - x1)**(P-2) % P)) % P
	x3 = (lamda**2 - x1 - x2) % P
	y3 = ((x1 - x3) * lamda - y1) % P

	return (x3, y3)

def muling(point, n):
	double = doubleing(point)
	if(n==2):
		return double
	elif(n==1):
		return point
	else:
		log2n = int(math.log(n, 2))
		mul = {}
		ddowl = double
		num = 2
		count = 1
		mul[2] = double
		mul[1] = point

		while(log2n>count):
			tmp = doubleing(ddowl)
			num = num*2
			mul[num] = tmp
			ddowl = tmp
			count += 1

		what = 1
		whatadd = []
		
		while(n):
			if(n % 2 == 1):
				whatadd.append(what)
			what = what * 2
			n = int(n / 2)

		result = mul[whatadd[0]]
		del(whatadd[0])
		if len(whatadd) >= 1:
			for i in whatadd:
				result = adding(result,mul[i])

		return result

if __name__=="__main__":
	count = randint(0,2**1000)
	x1 = randint(0,2**1000)
	y1 = randint(0,2**1000)
	res = muling((x1,y1),count)
	print(hex(count), res, sep='\n')