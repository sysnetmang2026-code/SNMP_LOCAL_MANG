"""
Menu.py - Menu de opciones en terminal
========================================
Tarea 3: Menu que mantiene el programa corriendo
hasta que el usuario decida salir.
Importa toda la logica desde prueba.py
"""

import sys
import asyncio

sys.stdout.reconfigure(encoding='utf-8')

# -------------------------------------------
# Importamos la logica desde prueba.py
# -------------------------------------------
from prueba import (
    AGENTE_IP,
    COMUNIDAD,
    ARCHIVO,
    consultar_todos,
    cargar_datos,
    guardar_todos,
    asegurar_directorio,
    iniciar_auto_update,
    detener_auto_update,
)
import prueba


# -------------------------------------------
# ACCIONES del menu
# -------------------------------------------
def accion_consultar_ahora():
    print("\n  Consultando MikroTik via SNMP...\n")
    resultados = asyncio.run(consultar_todos())
    if resultados:
        print("  " + "-" * 52)
        for nombre, valor in resultados.items():
            print(f"  {nombre:<32} : {valor}")
        print("  " + "-" * 52)
        guardar_todos(resultados)
        print(f"\n  Datos guardados en {ARCHIVO}")
    else:
        # Manejo de error: router apagado o sin conexion
        print("  No se obtuvo respuesta del router.")
        print("  Verifica que el MikroTik este encendido y accesible.")


def accion_ver_fichero():
    print(f"\n  Contenido de {ARCHIVO}:\n")
    datos = cargar_datos()
    if datos:
        print("  " + "-" * 52)
        for clave, valor in datos.items():
            print(f"  {clave:<32} : {valor}")
        print("  " + "-" * 52)
    else:
        print("  El fichero esta vacio. Realiza una consulta primero.")


def accion_toggle_auto_update():
    if prueba._auto_update_activo:
        detener_auto_update()
    else:
        iniciar_auto_update()


# -------------------------------------------
# TAREA 3 - Menu de opciones
# -------------------------------------------
def mostrar_menu():
    estado = "activo" if prueba._auto_update_activo else "inactivo"
    print("\n")
    print("  " + "=" * 48)
    print("  Panel de Informacion  -  MikroTik")
    print("  " + "=" * 48)
    print(f"  Router IP   : {AGENTE_IP}")
    print(f"  Comunidad   : {COMUNIDAD}")
    print(f"  Auto-update : {estado}")
    print("  " + "-" * 48)
    print("  1. Consultar datos ahora")
    print("  2. Ver datos guardados")
    print("  3. Activar / Detener auto-update")
    print("  4. Salir")
    print("  " + "=" * 48)
    print("  Opcion: ", end="")


def ejecutar_menu():
    asegurar_directorio()

    opciones = {
        "1": accion_consultar_ahora,
        "2": accion_ver_fichero,
        "3": accion_toggle_auto_update,
    }

    while True:
        mostrar_menu()
        opcion = input().strip()

        if opcion == "4":
            detener_auto_update()
            print("\n  Saliendo...\n")
            break
        elif opcion in opciones:
            opciones[opcion]()
        else:
            print("\n  Opcion no valida.")

        input("\n  Presiona Enter para continuar...")


# -------------------------------------------
# PUNTO DE ENTRADA  -  ejecutar: python Menu.py
# -------------------------------------------
if __name__ == "__main__":
    ejecutar_menu()