from PIL import Image
from pyzbar import pyzbar
import vt
import requests
from bs4 import BeautifulSoup
from flask_app import app
import os
import time
import json

vt_api_key = ""
whoisxmlapi_apikey = ""
def read_qr(qr):
    img = Image.open(os.path.join(app.config['UPLOADED_IMAGES_DEST'],qr))
    output = pyzbar.decode(img)
    if output:
        datos = str(output[0].data)[2:len(str(output[0].data))-1]
        if datos[:4] != "http":
            return None
        else:
            return datos
    else: 
        return None


def virustotal_url(url):
    client = vt.Client(vt_api_key)
    url_id = vt.url_id(url)
    print(url_id)
    try:
        url_result = client.get_object(f"/urls/{url_id}")
    except:
        return {}
    resultados = dict(url_result.last_analysis_stats)
    resultados.pop('undetected')
    resultados.pop('timeout')
    resultados.setdefault("misma_url", True if url_result.last_final_url == url else False)
    try:
        resultados.setdefault("links", url_result.outgoing_links)
    except:
        pass
    # print(url_result.last_analysis_results)
    url_ip = client.get_json("/urls/{}/last_serving_ip_address", url_id)
    resultados.setdefault("ip_vt", url_ip["data"]["id"])

    client.close()
    return resultados

#por tema de api y limite de busquedas, lo limitaré a los primeros 3 resultados. Podría hacerlo asíncrono para que haga 4 peticiones por minuto
def virustotal_links(links):
    lista_peligrosos = []
    client = vt.Client(vt_api_key)
    for url in links:
        print(url)
        url_id = vt.url_id(url)
        try:
            url_result = client.get_object("/urls/{}", url_id)
            if url_result.last_analysis_stats["malicious"] != 0:
                lista_peligrosos.append(url)
        except:
            print("No se ha podido analizar")
    client.close()
    return lista_peligrosos


#FUNCION QUE ENCUENTRA TODOS LOS LINKS EN UNA PAGINA
#DIFERENCIA ENTRE ENLACES INTERNOS O EXTERNOS Y ARCHIVOS
#BUSCA IMÁGENES CON DIMENSIONES 0X0
#FALTARIA ANALIZAR ESOS LINKS Y ARCHIVOS CON LA API DE VIRUSTOTAL PERO ESTÁ EL LÍMITE DE CONSULTAS
def scrappel_web(url):
    try: 
        url_original = requests.get(url)
    except:
        return {"links" : [], "archivos": [], "imagenesSospechosas": []}

    extensiones_no_procesadas = [".html",".css",".com",".es",".eng",".org",".net"]
    if url_original.status_code == 200: 
        soup = BeautifulSoup(url_original.content, "html.parser")
        links= []
        archivos = []
        for h in soup.find_all(href=True):
            h = str(h["href"]).strip()
            if len(h) > 1:
                if h[:4] == "http":
                    l = h  
                else:
                    l = url_original.url[:url_original.url.find("/",8)] + h if h[0] == "/" else url_original.url[:url_original.url.find("/",8)] + '/' + h

                i = l.rfind(".")
                
                if l.count("/") >= 3 and l[i:].count("/") == 0:
                    if l[l.rfind("."):] not in extensiones_no_procesadas:
                        if l[i:i+5] != ".php?":
                            archivos.append(l)
                        else:
                            links.append(l)
                    else:
                        links.append(l)
                else: 
                    links.append(l)

        print("busqueda imagenes")
        img = busqueda_imagenes(url_original.url)
        return {"links":links, "archivos":archivos, "imagenesSospechosas":img}
                #FORMA ACTUAL: SI HAY 3 O MAS / SIGNIFICA QUE YA ESTAMOS DENTRO DE UNA WEB (NO ES EL DOMINIO PRINCIPAL) 
                #SI DESPUES DEL ÚLTIMO . NO HAY MÁS DIRECTORIOS ES EL ARCHIVO FINAL 
                #DESCARTAMOS DOCUMENTOS HTML Y CSS

#FUNCION QUE BUSCA Y ANALIZA EL TAMAÑO DE LAS IMAGENES DE UNA WEB
def busqueda_imagenes(url):
    #BUSQUEDA DE IMAGENES
    try: 
        contenido = requests.get(url)
    except:
        print("error de conexion")
        return 0

    imagenes0x0 = []
    if contenido.status_code == 200:
        soup = BeautifulSoup(contenido.content, "html.parser")
        for img in soup.find_all("img"):
            try: 
                hola = img.attrs["src"]
            except:
                imagenes0x0.append(img)
                
            try:
                if img.attrs["width"] == 0:
                    imagenes0x0.append(img)
            except:
                pass

            try:
                if img.attrs["height"] == 0:
                    imagenes0x0.append(img)
            except:
                pass
    eventos = ["onerror", "onload", "onloadedmetadata", "onloadeddata", "onloadstart","role","class"]

    imagenesSospechosas = {}

    for i in imagenes0x0:
        for e in eventos: 
            if e in i.attrs:
                imagenesSospechosas.setdefault(i,[e]) if not i in imagenesSospechosas else imagenesSospechosas[i].append(e)

    return imagenesSospechosas


'''
Funcion que descarga archivos, los manda analizar y los desinstala
'''
def analisis_archivos(archivos):
    client = vt.Client(vt_api_key)
    file_analisis = []
    malicious = []
    file_list = []
    dir, filename = os.path.split(os.path.abspath(__file__))
    for archivo in archivos:
        file = requests.get(archivo, stream=True)
        nombre_archivo = archivo.split("/")[len(archivo.split("/"))-1]
        print(nombre_archivo)
        try:
            with open(f"{dir}\\uploads\\{nombre_archivo}","wb") as f:
                for chunk in file.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)

            with open(f"{dir}\\uploads\\{nombre_archivo}","rb") as f:
                file_analisis.append(client.scan_file(f))
                file_list.append(nombre_archivo)
        except:
            pass

    for a,b in enumerate(file_analisis):
        while True:
            analisis = client.get_object("/analyses/{}",b.id)
            if analisis.status == "completed":
                if analisis.stats["malicious"] > 0:
                    malicious.append(archivos[a])
                break 
            print("esperando un poquito mas")
            time.sleep(30)

    print("va a entrar en el for")
    for archivo in file_list:
        try:
            print(archivo)
            os.remove(f"{dir}\\uploads\\{archivo}")
        except:
            continue
    return malicious
    

#OBTENCION DE LA DIRECCIÓN IP OBJETIVO Y ANÁLISIS DE LA MISMA CON WHOIS
import socket
def obtener_info_equipo_remoto(url):
    equipo_remoto = url.split("/")[2]
    contenido = {"ip": "none"}
    try:
        contenido = requests.get(f"https://website-contacts.whoisxmlapi.com/api/v1?apiKey={whoisxmlapi_apikey}&domainName={equipo_remoto}")
        contenido = dict(json.loads(contenido.text))
    except:
        print("error")
        pass
    try:
        ip = socket.gethostbyname(equipo_remoto)
        print ("La direccion IP es: %s" %ip)
        if contenido:
            contenido.setdefault("ip", ip)
            return contenido
        return ip
    except socket.error:
        print (f"error en la ip : {equipo_remoto}")
    return contenido

# print(obtener_info_equipo_remoto("https://www.7-zip.org/"))
