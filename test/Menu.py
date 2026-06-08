from prueba import cargar_oids
from prueba import consultar_oid
while True: 
    print ("""BIenvenidos a Mikrotik1
           1.Listado de OIDS
           2. Salir""")
    
    opcion= input("que deseas Hacer?")
   
    try :    
      match int(opcion) :
        case 1: 
            OIDS = cargar_oids()
            """print (type(OIDS)) """
            for oid in OIDS:
                consultar_oid(oid)
                print(oid)
                print("-------------------------------")

        case 2: 
            print("Cerrando")
            break
    except:
       print