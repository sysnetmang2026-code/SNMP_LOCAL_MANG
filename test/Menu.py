"""Menu experimental para consultar OIDs SNMP de Mikrotik.

Este archivo pertenece al espacio de pruebas `test/` y consume funciones de
`prueba.py`. Su objetivo es listar los OIDs configurados y solicitar su consulta
desde un menu de consola sencillo.
"""

from prueba import cargar_oids
from prueba import consultar_oid


while True:
    print("""BIenvenidos a Mikrotik1
           1.Listado de OIDS
           2. Salir""")

    opcion = input("que deseas Hacer?")

    try:
        match int(opcion):
            case 1:
                OIDS = cargar_oids()

                for oid in OIDS:
                    consultar_oid(oid)
                    print(oid)
                    print("-------------------------------")

            case 2:
                print("Cerrando")
                break
    except Exception:
        print
