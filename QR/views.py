from analisis import scrappel_web
from flask import request, render_template, jsonify, redirect, url_for
from app import app
from forms import Form_Imagen
from flask_wtf import csrf
from werkzeug.utils import secure_filename
from analisis import read_qr, virustotal_url, virustotal_links, obtener_info_equipo_remoto, analisis_archivos
import os
from models import db, Web, Owner

@app.route('/', methods = ['GET', 'POST'])
def index():
    resultado = {}
    url = ""
    form = Form_Imagen()
    csrf.generate_csrf()
    if form.validate_on_submit():
        print("archivo subido con exito")
        print(form.imagen.data.filename)
        if secure_filename(form.imagen.data.filename) != '':
            form.imagen.data.save(os.path.join(app.config['UPLOADED_IMAGES_DEST'],form.imagen.data.filename))
            url = read_qr(form.imagen.data.filename)
            print(url)
            if url is not None:
                print("es un qr valido")
                web = Web.query.filter(Web.url == url).first()
                if web:
                    resultado = {"analisis":web.analisis, "links_riesgo":web.links, "archivos_riesgo":web.files, "ip":web.ip, "owner_name":web.owner_name, "misma_url":web.misma_url, "imagenesSospechosas":web.images}
                    print(resultado)
                else:
                    resultado = virustotal_url(url)
                    print("Analisis iniciar con virustotal terminado")
                    scrapper = scrappel_web(url)
                    resultado["links"] = list(set(resultado["links"] + scrapper["links"]))
                    resultado.setdefault("links_riesgo", virustotal_links(resultado["links"]))
                    resultado.setdefault("archivos", scrapper["archivos"])
                    print("scrapper analizados")
                    resultado.setdefault("imagenesSospechosas", scrapper["imagenesSospechosas"])
                    resultado.setdefault("archivos_riesgo", analisis_archivos(resultado["archivos"]))
                    whois = obtener_info_equipo_remoto(url)
                    if type(whois) == str:
                        resultado.setdefault("ip", whois)
                    else:
                        try:
                            resultado.setdefault("ip", whois["ip"])
                            try:
                                if len(whois["companyNames"]) >= 1:
                                    owner_name = whois["company_names"][0]
                                else:
                                    print("toca hacer el print del owner_name")
                                    print(whois["meta"]["title"])
                                    owner_name = whois["meta"]["title"]
                            except:
                                owner_name = "Unknown"
                                print(owner_name)
                            resultado.setdefault("owner_name", owner_name)
                            resultado.setdefault("company_names", whois["companyNames"])
                            resultado.setdefault("emails", whois["emails"])
                            phones = ', '.join([i["phoneNumber"] for i in whois["phones"]]) 
                            resultado.setdefault("phones",phones)
                            hay_owner = Owner.query.filter(Owner.owner_name==owner_name).first()
                            print(hay_owner)
                            if hay_owner:
                                pass
                            else:
                                owner = Owner(owner_name=owner_name, antecedentes="", phones=phones, company_names=','.join(resultado["company_names"]), emails=','.join(resultado["emails"]))
                                db.session.add(owner)
                                db.session.commit()
                        except:
                            print("error añadiendo al Owner")
                            pass
                    
                    harmless = resultado["harmless"]
                    suspicious = resultado["suspicious"]
                    malicious = resultado["malicious"]
                    analisis = f"harmless: {harmless}, suspicious: {suspicious}, malicious: {malicious}"
                    resultado.setdefault("analisis", analisis)
                    imgsus = 0 if resultado["misma_url"] == False else 1
                    web = Web(url=url, owner_name=owner_name, ip=resultado["ip"], files=','.join(resultado["archivos_riesgo"]), links=','.join(resultado["links_riesgo"]), images=','.join(resultado["imagenesSospechosas"]), misma_url=imgsus, analisis=analisis)
                    db.session.add(web)
                    db.session.commit()
                    resultado["archivos_riesgo"] = ','.join(resultado["archivos_riesgo"])
                    resultado["links_riesgo"] = ','.join(resultado["links_riesgo"])
                    resultado["imagenesSospechosas"] = ','.join(resultado["imagenesSospechosas"])
                    print(resultado)
            os.remove("uploads/img/"+form.imagen.data.filename)
            #return redirect(url_for('index'))
    else: 
        print("error al subir archivo")
    return render_template('index.html', form=form, result=resultado, url=url)