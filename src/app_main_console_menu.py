#from src.escaneoderedconNmapySqliteoui import *
from src.escaneoderedconNmapySqliteoui import EscanearRedDB
from src.get_red_info import *


rango = get_subnet()
rango_str = str(rango)

while True:
    print("1. Escanear red")
    print("2. Ver resultados")
    print("3. Salir")
    choice = input("Seleccione una opción: ")

    if choice == '1':
        EscanearRedDB.escanear_red(rango_str)
    elif choice == '2':
        EscanearRedDB.ver_resultados()
    elif choice == '3':
        print("Saliendo...")
        break
    else:
        print("Opción no válida, por favor intente de nuevo.")