from app import app
import os

dir, filename = os.path.split(os.path.abspath(__file__))
app.config['SECRET_KEY'] = "asoidfjioasjfsodjfSJFOAOFu49812ofi"
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif']
app.config['UPLOADED_IMAGES_DEST'] = f"{dir}\\uploads\\img"

configuration = {"MYSQL_USERNAME":"",
    "MYSQL_PASSWORD":"",
    "MYSQL_HOSTNAME":"",
    "MYSQL_DATABASENAME":""}


app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://{username}:{password}@{hostname}/{databasename}".format(
  username=configuration["MYSQL_USERNAME"],
  password=configuration["MYSQL_PASSWORD"],
  hostname=configuration["MYSQL_HOSTNAME"],
  databasename=configuration["MYSQL_DATABASENAME"]
  )
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

from flask import render_template

from errors import *

from views import *

if __name__ == "__main__":
    app.run(debug=True)

    