from socket import * 
import time

starttime = time.time()

#if __name__ == "main":
#target = input('Enter host for scanning: ') #"127.0.0.1"
target = "127.0.0.1"
t_IP = gethostbyname(target)
print('Starting scanning on host: ', t_IP)

for i in range(50, 500):
    s = socket(AF_INET, SOCK_STREAM )

    conn = s.connect_ex((t_IP, i))
    if (conn == 0):
        print('Port %d: OPEN' % (i,))
    s.close()

print('Time taken: ', time.time() - starttime)