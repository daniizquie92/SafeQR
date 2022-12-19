from app import app
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy(app)

from flask_login import UserMixin

class Owner(UserMixin, db.Model):
    __tablename__ = 'Owner'
    owner_name = db.Column(db.String(100), primary_key=True)
    antecedentes = db.Column(db.String(1000))
    phones = db.Column(db.String(1000))
    company_names = db.Column(db.String(2000))
    emails = db.Column(db.String(2000))
    #fecha = db.Column(db.String(100))

class Web(UserMixin,db.Model):
    __tablename__ = 'Web'
    url = db.Column(db.String(100), primary_key=True)
    owner_name = db.Column(db.String(100), db.ForeignKey("Owner.owner_name"))
    ip = db.Column(db.String(20))
    files = db.Column(db.String(1000))
    links = db.Column(db.String(8000))
    images = db.Column(db.String(1000))
    misma_url = db.Column(db.Integer)
    analisis = db.Column(db.String(500))
    

    def save(self):
        if not self.url:
            print("registro creado")
            db.session.add(self)
        db.session.commit()

