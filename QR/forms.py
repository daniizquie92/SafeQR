from flask_wtf import FlaskForm
from wtforms import FileField, ValidationError
from flask_wtf.file import FileRequired
import re
import imghdr

class Form_Imagen(FlaskForm):
    imagen = FileField("Introduzca el QR (jpg, png)", validators=[FileRequired()])

    def validate_imagen(form,field):
        filename = field.data.filename.replace(' ', '')
        if (not re.search("^[a-zA-Z0-9_/-/(/)]*[.]jpg$", filename) 
            and not re.search("^[a-zA-Z0-9_/-/(/)]*[.]png$", filename) 
            and not re.search("^[a-zA-Z0-9_/-/(/)]*[.]jpeg$", filename)):
            raise ValidationError("Invalid input syntax")

        stream = field.data.stream
        header = stream.read(512)
        stream.seek(0) 
        format = imghdr.what(None, header)
        if not format:
            raise ValidationError("Archivo invalido")
