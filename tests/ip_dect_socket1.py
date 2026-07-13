from socket import * 
import time
from src.get_red_info import * # => podremos conseguir obtener todas las direcciones?

starttime = time.time()

#if __name__ == "main":
#target = input('Enter host for scanning: ') #"127.0.0.1"
target = "192.168.1.6" #
t_IP = gethostbyname(target)

#hice un scaneo con nmap y entre los host activos encontre estos puertos
ports = [80, 8082, 8008, 7, 9080, 7000, 8001, 8002, 8080]

new_t_IP = tuple(t_IP)
#print(type(new_t_IP))
#print('Starting scanning on host: ', t_IP)

""" for i in range(50, 500):
    s = socket(AF_INET, SOCK_STREAM ) """
#nuevo socket
s = socket(AF_INET, SOCK_STREAM)

for port in ports:  
    #la conexion requiere un puerto para crearse, y si el puerto dado no esta abierto no devolvera OPEN
    conn = s.connect_ex((t_IP, port)) #recibe address, hecho t_IP + i(port), funciona solo hostname?
    if (conn == 0):
        print('Port %s: OPEN' % (t_IP))
    else:
        print('No OPEN %s: at least with that port' % (t_IP))
    #s.close()

#print('Time taken: ', time.time() - starttime)