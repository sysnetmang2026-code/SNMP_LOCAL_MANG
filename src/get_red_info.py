import ifaddr
import ipaddress

#funciona
""" adapters = ifaddr.get_adapters()

for adapter in adapters:
    if adapter.nice_name == "Intel(R) Wi-Fi 6 AX201 160MHz":
        print(f"IPs of network adapter {adapter.nice_name}:")
        for ip in adapter.ips:
            if ip.is_IPv4:
                # ip.ip is the address, ip.network_prefix is the CIDR mask (e.g., 24)
                print(f"   Address: {ip.ip}")
                print(f"   Network prefix: {ip.network_prefix}")
                 """


""" adapters = ifaddr.get_adapters()

for adapter in adapters:
    if "wi-fi 6" in adapter.nice_name.lower():
        for ip in adapter.ips:
            if ip.is_IPv4:
                # Construir objeto IPv4Interface con dirección y prefijo
                iface = ipaddress.IPv4Interface(f"{ip.ip}/{ip.network_prefix}")
                
                print(f"Adaptador: {adapter.nice_name}")
                print(f"   Dirección: {ip.ip}")
                print(f"   Prefijo: {ip.network_prefix}")
                print(f"   Subred: {iface.network}")   # Ejemplo: 192.168.1.0/24
                print(f"   Dirección de red: {iface.network.network_address}")
                print(f"   Broadcast: {iface.network.broadcast_address}") """

adapters = ifaddr.get_adapters()

def get_localhost_ip():
    for adapter in adapters:
        if "wi-fi 6" in adapter.nice_name.lower():
            for ip in adapter.ips:
                if ip.is_IPv4:
                    #iface = ipaddress.IPv4Interface(f"{ip.ip}/{ip.network_prefix}")

                    return ip.ip
                
def get_subnet_mask():
    for adapter in adapters:
        if "wi-fi 6" in adapter.nice_name.lower():
            for ip in adapter.ips:
                if ip.is_IPv4:
                    #iface = ipaddress.IPv4Interface(f"{ip.ip}/{ip.network_prefix}")

                    return ip.network_prefix
                
def get_network_address():
    for adapter in adapters:
        if "wi-fi 6" in adapter.nice_name.lower():
            for ip in adapter.ips:
                if ip.is_IPv4:
                    iface = ipaddress.IPv4Interface(f"{ip.ip}/{ip.network_prefix}")

                    return iface.network.network_address
                
def get_broadcast():
    for adapter in adapters:
        if "wi-fi 6" in adapter.nice_name.lower():
            for ip in adapter.ips:
                if ip.is_IPv4:
                    iface = ipaddress.IPv4Interface(f"{ip.ip}/{ip.network_prefix}")

                    return iface.network.broadcast_address
                
def get_subnet():
    for adapter in adapters:
        if "wi-fi 6" in adapter.nice_name.lower():
            for ip in adapter.ips:
                if ip.is_IPv4:
                    iface = ipaddress.IPv4Interface(f"{ip.ip}/{ip.network_prefix}")

                    return iface.network
                
""" var1 = get_localhost_ip()
var2 = get_subnet_mask()
var3 = get_network_address()
var4 = get_broadcast()
var5 = get_subnet()

print(var1, var2, var3, var4, var5) """
                
""" subnet = get_subnet()
print(subnet) """




