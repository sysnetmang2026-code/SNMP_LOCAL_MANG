from nmap_scanner import EscanerRedDB
from get_red_info import *

db = EscanerRedDB("red.db")



rango = get_subnet()
rango_str = str(rango)

while True:

    print("1. Escanear red")
    print("2. Ver resultados")
    print("3. Salir")

    choice = input("Seleccione una opción: ")

    if choice == '1':
        db.escanear_red(rango_str)

    elif choice == '2':
        db.mostrar_dispositivos()

    elif choice == '3':
        db.close()
        break

    else:
        print("Opción no válida")