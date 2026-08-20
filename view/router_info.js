

document.addEventListener('DOMContentLoaded', async function () {
    velocidadDescargaJs();
})

//funcion fuera del DOMcontentLoaded para que se actualize la velocidad

    console.log('panel de informacion del router')
    const bloqueVelocidadDescarga = document.getElementById('tdDownloadSpeed')

    function velocidadDescargaJs () {
        let userImageLink = "https://media.geeksforgeeks.org/wp-content/cdn-uploads/20200714180638/CIP_Launch-banner.png";
        let time_start, end_time;

        //let speedInMbps;
        // The size in bytes
        let downloadSize = 5616998;
        let downloadImgSrc = new Image();

        downloadImgSrc.onload = function () {
            end_time = new Date().getTime();
            //setInterval( function() { displaySpeed(); }, 5000)
            displaySpeed();
        };
        time_start = new Date().getTime();
        downloadImgSrc.src = userImageLink;


        function displaySpeed() {
            let timeDuration = (end_time - time_start) / 1000;
            let loadedBits = downloadSize * 8;

            /* Converts a number into string
                using toFixed(2) rounding to 2 */
            let bps = (loadedBits / timeDuration).toFixed(2);
            let speedInKbps = (bps / 1024).toFixed(2);
            let speedInMbps = 0; //limpiar para no acumular, no funciono
            speedInMbps = (speedInKbps / 1024).toFixed(2);
            console.log(parseFloat(speedInMbps))
            /* alert("Your internet connection speed is: \n"
                + bps + " bps\n" + speedInKbps
                + " kbps\n" + speedInMbps + " Mbps\n"); */
            //velocidadFinal = parseFloat(speedInMbps);
            bloqueVelocidadDescarga.innerHTML = ``; //limpiar?
            bloqueVelocidadDescarga.innerHTML = `${speedInMbps} Mbps`;
        }
    }

    setInterval( function() { velocidadDescargaJs(); }, 5000)
    console.log(bloqueVelocidadDescarga)
    console.log()
    //bloqueVelocidadDescarga.innerHTML = '';