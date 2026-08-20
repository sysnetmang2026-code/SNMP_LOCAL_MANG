import webbrowser
from flask import Flask, render_template
import os
import asyncio
import threading

def abrirWeb():
    webbrowser.open("http://127.0.0.1:5000/view/panel-red.html")


#template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "view")) #funciona si este script esta dentro de src
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "view")) #los .. retrocedian una carpeta
#static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "view")) #funciona si este script esta dentro de src
static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "view"))

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
#app = Flask(__name__)

#==========================rutas de la web=================================
@app.route("/view/panel-red")
def index():
    #return open("panel-red.html").read()
    return render_template('panel-red.html')

@app.route("/view/inicio")
def inicio():
    return render_template('inicio.html')

@app.route("/view/router_info")
def routerInfo():
    return render_template('router_info.html')

webbrowser.open("http://127.0.0.1:5000/view/inicio") #abrir la web
if __name__ == "__main__":
    app.run(debug=False)


    #threading.Timer(1, abrirWeb).start()
    #webbrowser.open("http://127.0.0.1:5000/view/panel-red.html")
    """ if __name__ == "__main__":
        app.run(host="127.0.0.1", port=8080, debug=True) """
