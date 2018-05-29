import os, requests, json, sys, traceback
import pandas as pd
from flask import Flask, url_for, render_template, jsonify, request, Response, redirect

from flask.ext.login import LoginManager,current_user #added login manager
from flask_pymongo import PyMongo

from werkzeug import secure_filename
from werkzeug.routing import RequestRedirect
from flask import make_response
from concurrent.futures import ThreadPoolExecutor
from gevent import monkey, sleep

from web_app.files_utils import allowed_file, UPLOAD_FOLDER
from web_app.csv2json import parse_csv
from web_app.greq import verify;
from collections import OrderedDict
from datetime import datetime
from web_app.permutator import *
from flask import request, redirect, render_template, url_for, flash
from flask import Flask, url_for, render_template, jsonify, request, Response, redirect

from flask_login import login_user, logout_user, login_required
from .forms import LoginForm,SignupForm
from .user import User
import os, requests, json, sys, traceback
#from flask_sslify import SSLify


APP__ROOT = os.path.dirname(os.path.abspath(__file__))

# DOCS https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.ThreadPoolExecutor
executor = ThreadPoolExecutor(2)

monkey.patch_all() #monkey patch for thread pool related problems


# Define the WSGI application object
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
FORMAT = '%Y%m%d%H%M%S'

app.config['WTF_CSRF_ENABLED'] = True
app.config['SECRET_KEY'] =  os.urandom(50);

MONGO_URI = "mongodb://admin:admin123@ds149134.mlab.com:49134/heroku_2g2nnp30"

if not MONGO_URI:
    MONGO_URI = "mongodb://localhost:27017/api";
print("MONGO_URL: "+MONGO_URI)

app.config['MONGO_URI'] = MONGO_URI
mongo = PyMongo(app); #initialize mongo

#sslify = SSLify(app)

lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'


# gets the email status
def get_json(url, data):
    # url = 'https://mailgnome.herokuapp.com/check_email/'
    email = data['email']
    r = requests.get(url + email.lower());
    print(r)
    data = r.json();
    return data;


# csv parse job pool
def parse_csv_pool(email_list, req_id):
    try:
        # email_list = parse_csv(filename);
        email_list = verify(email_list, req_id);
        print("One job finished!")
    except Exception as e:
        traceback.print_exc()


#    return Response(json.dumps(email_list,  mimetype='application/json'))


# list parse job pool for guessing
def guess_pool(list_email_list, req_id):
    try:
        for email_list in list_email_list:
            parse_csv_pool(email_list, req_id);
        print('guessing file finished!');
    except Exception as e:
        traceback.print_exc();

from web_app import views