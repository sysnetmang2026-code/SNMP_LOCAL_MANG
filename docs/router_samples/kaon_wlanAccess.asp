<html>

<head>
<link rel="stylesheet" type="text/css" href="main.css" />
<meta name="GENERATOR" content="Microsoft FrontPage 5.0">
<meta name="ProgId" content="FrontPage.Editor.Document">
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Residential Gateway Configuration: Wireless - Access Control</title>
<script language="javascript">
<!-- hide me
function commitAccess()
{
	window.document.wlanAccess.commitwlanAccess.value = 1;
}

function onLoadScript()
{
   
}

function wlanAccessChangeMbssIndex()
{
   window.document.wlanAccess.wlanAccessMbssIndexChanged.value = 1;
   window.document.wlanAccess.submit();
}

function checkMacRestrictWps2Dialog()
{
	if((window.document.wlanAccess.MacRestrictMode.value == 1) &&
	  (window.document.wlanAccess.WirelessMac01.value == "")&&(window.document.wlanAccess.WirelessMac09.value == "") &&
	  (window.document.wlanAccess.WirelessMac02.value == "")&&(window.document.wlanAccess.WirelessMac10.value == "") &&
	  (window.document.wlanAccess.WirelessMac03.value == "")&&(window.document.wlanAccess.WirelessMac11.value == "") &&
	  (window.document.wlanAccess.WirelessMac04.value == "")&&(window.document.wlanAccess.WirelessMac12.value == "") &&
	  (window.document.wlanAccess.WirelessMac05.value == "")&&(window.document.wlanAccess.WirelessMac13.value == "") &&
	  (window.document.wlanAccess.WirelessMac06.value == "")&&(window.document.wlanAccess.WirelessMac14.value == "") &&
	  (window.document.wlanAccess.WirelessMac07.value == "")&&(window.document.wlanAccess.WirelessMac15.value == "") &&
	  (window.document.wlanAccess.WirelessMac08.value == "")&&(window.document.wlanAccess.WirelessMac16.value == "")) 
	  {
		//if(!confirm("Setting MAC Restrict Mode to Allow with empty MAC addresses will disable WPS. Do you want to continue?")){
		if(!confirm("Configurar Modo de restriccion de MAC en Permitir con direcciones MAC vacias deshabilitara WPS. Quieres continuar?")){
			window.document.wlanAccess.MacRestrictMode.value = 0;
		}
	}
}

// show me -->

</script>
</head>

<body onLoad="onLoadScript(); setReadonly();">
<header>
 <div id="Header">
  <h1>
   <img src="KaonLogo.png" alt="Docsis">
  </h1>
  <h2>
   DOCSIS 3.0
  </h2>
  <h3>
  <a><img src="header_logout.png" onclick="logout();"></a>
  </h3>
 </div>
</header>
<div class="gnb">
   <ul>
	<li><a href="/RgSwInfo.asp">Estado</a></li><li><a href="/RgSetup.asp">Red</a></li><li><a href="/RgContentFilter.asp">Cortafuegos</a></li><li><a class="h1"><img src="header_menu_point.png"></a> <a class="Active" href="/wlan24G.asp">2.4GHz</a></li><li><a href="/wlan5G.asp">5GHz</a></li><li><a href="/MtaStatus.asp">MTA</a></li><li><a href="/RgFirewallEL.asp">Administración</a></li>
   </ul>
</div>
<!-- <div id="navigation_bar">
<a href="http://www.broadcom.com/"><img border="0" src="logo_new.gif" width="154" height="106" /></a> -->
<article>
 <aside>
   <nav>
    <ul class="NavMenu">
    <li><a href="/wlanRadio.asp">Radio</a></li><li><a href="/wlanPrimaryNetwork.asp">Red Primaria</a></li><li><a href="/wlanGuestNetwork.asp">Red de Invitado</a></li><li><a href="/wlanAdvanced.asp">Avanzado</a></li><li><a class="Active" href="/wlanAccess.asp">Control de Acceso</a></li><li><a href="/wlanWmm.asp">WMM</a></li><li><a href="/wlanMedia.asp">Medios</a></li><li><a href="/wlanStatus.asp">Estado</a></li><div id="version" style="visibility:hidden">1.0</div> 
  </ul>
    </nav>
   </aside>
<div id="main_page">
  <div class="description">
<!--    <h1>Wireless</h1> -->
    <h4>802.11 Control de Acceso</h4>
   Esta página permite la configuración del control de acceso al AP y revisar el estado de los clientes
  </div>
<form action=/goform/wlanAccess method=POST name="wlanAccess">
<div class="table_data">
<table class="ListTypeB">
<input type="hidden" name="wlanAccessMbssIndexChanged"value=0 > 
<tr><td>Interfaz inalámbrica</td><td><select name="wlanAccessCurrentNetworks" onchange="wlanAccessChangeMbssIndex();">);<option value=0 selected>CLARO1_B55087 (74:3A:EF:B5:50:8B)<option value=1 >Invitados (76:3A:EF:B5:50:8C)</select></td></tr>
</table>
<table class="ListTypeB"> 
<tr>
<td>Modo de restricción de MAC</td>
<td><select name="MacRestrictMode" onChange="submit();"><option value=0 >Deshabilitado<option value=1 >Permitir<option value=2 selected>Denegar</select></td>
</tr>
<tr>
<td>Filtro de MAC basado en respuestas</td>
<td><select name="MacProbeResponse" onChange="submit();"><option value=0 >Apagado<option value=1 selected>Encendido</select></td>
</tr>
<tr>
<td>Direcciónes MAC (Ejemplo: 01:23:45:67:89:AB) </td><td></td>
</tr>
<tr>
<td colspan="2" align="center">
<input type="text" name="WirelessMac01" size=17 maxlength=17 value=06:C8:51:8A:3C:06>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac06" size=17 maxlength=17  value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac11" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac16" size=17 maxlength=17 value="">
</td>
</tr>
<tr>
<td colspan="2" align="center">
<input type="text" name="WirelessMac02" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac07" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac12" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac17" size=17 maxlength=17 value="">
</td>
</tr>
<tr>
<td colspan="2" align="center">
<input type="text" name="WirelessMac03" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac08" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac13" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac18" size=17 maxlength=17 value="">
</td>
</tr>
<tr>
<td colspan="2" align="center">
<input type="text" name="WirelessMac04" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac09" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac14" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac19" size=17 maxlength=17 value="">
</td>
</tr>
<tr>
<td colspan="2" align="center">
<input type="text" name="WirelessMac05" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac10" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac15" size=17 maxlength=17 value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<input type="text" name="WirelessMac20" size=17 maxlength=17 value="">
</td>
</tr>
<tr>
<td style="background-color:#FFF;"></td>
</tr>
<tr>
<td style="background-color:#FFF;" colspan=4 align=center>
<input class="btn_red" type="submit" value=" Aplicar " onClick="commitAccess();">
<input type="hidden" name="commitwlanAccess" value=0 >
</td>
</tr>
</table>
<table class="ListTypeA">
<caption>Clientes conectados</caption>
<tr><th class="red_bcenter">Dirección MAC</th><th class="red_bcenter">Duración</th><th class="red_bcenter">RSSI(dBm)</th><th class="red_bcenter">Dirección IP</th><th class="red_bcenter">Nombre de Host</th><th class="red_bcenter">Modo</th><th class="red_bcenter">Velocidad (Kbps)</th></tr><tr><td>E4:5E:37:C4:C1:7E</td><td>1</td><td>-67</td><td>192.168.1.21</td><td>DESKTOP-LJI5CB9</td><td>n</td><td>6000</td></tr>
<tr><td>DC:BD:7A:FF:33:56</td><td>8</td><td>0</td><td>192.168.1.14</td><td></td><td>n</td><td>-1</td></tr>

</table>
</div>
</form>
</div>
</article>
<footer>
<div id="Footer">
 <div><h3><form action=/goform/RgLanguage method=POST name="Language" style="font-size: 17px;">Idioma <select name="cbWebUILanguage" onChange="submit();" style="font-size: 17px;
font-weight: bold;">
<option value="spa" selected>Spanish<option value="eng"  >English</select>&nbsp;&nbsp;</form></h3></div>
<h1><img src="kaon_logo_footer.png" alt="KAON"></h1><h2>&copy;2001-2019 Kaonmedia Corporation. All rights reserved.</h2>
<div>
</footer>
<script type="text/javascript">
var accessType = "";

function logout()
{
  var userAgent = navigator.userAgent.toLowerCase();

  if (userAgent.indexOf("msie") != -1) {
    document.execCommand("ClearAuthenticationCache", false);
  }

  xhr_objectCarte = null;

  if(window.XMLHttpRequest)
    xhr_object = new XMLHttpRequest();
  else if(window.ActiveXObject)
    xhr_object = new ActiveXObject("Microsoft.XMLHTTP");
  else
    return;

  xhr_object.open ('GET', '/', false, 'username', 'password15307');
  xhr_object.send ("");
  xhr_object = null;

  document.location = '/';
  return false;
}
</script>
<script type="text/javascript" src="common.js"></script>
</body>

</html>
