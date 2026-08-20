x = 32

ip: str = ""

i = 1

while i <= x:
    #ip.__add__(".")
    ip = ip.__add__(str(1))
    #print("x")
    i+= 1

print(ip)

n = 8 #tamanio del octeto
p = 0
new_ip: str = ""
for e in ip:
    #print(e)
    p+= 1
    if p == n:
        #print("cuarto")
        p-= n
        new_ip = new_ip.__add__(str(1)).__add__(".")
    else:
        new_ip = new_ip.__add__(str(1))

#remover ultimo punto
new_ip.removesuffix(".")     #no funciona

print(new_ip[0:35])