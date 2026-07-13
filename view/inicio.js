const myModal = document.getElementById('myModal');
//const myInput = document.getElementById('myInput');

console.log(myModal);


document.addEventListener("DOMContentLoaded", async function () {
    
    //cambiar color body ??

    let contenedorMensajeEntrada = document.getElementById("bienvenidaMsg");
    contenedorMensajeEntrada.style.alignContent = "center";
    contenedorMensajeEntrada.style.alignItems = "center";

    let contenedorPrincipal = document.getElementById("contenedorPrincipal");

    let columnasOpciones = document.querySelectorAll(".col");
    console.log(columnasOpciones)

    columnasOpciones.forEach(column => {
        //column.style.border = "solid #000000";
        //column.appendChild()
    });

    //const myModal = document.getElementById('myModal')
    //const myInput = document.getElementById('myInput')

    //==========================abrir modal de ingreso de credenciales============================
    const exampleModal = document.getElementById('exampleModal');

    var modal1 = bootstrap.Modal.getOrCreateInstance(exampleModal);
    //modal1.show(); //=> terminar de mostrar el modal

    //=============================click en cards=============================================
    const myRouter = document.getElementById('myRouterCard');

    myRouter.addEventListener('click', function () {
        //window.location.replace(`router_info.html`)
    })
});