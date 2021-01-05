from flask import Flask, request, jsonify, render_template
from middleware import middleware
import numpy as np
import pickle
import pandas as pd
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
import sqlite3
import time

app = Flask(__name__)

# calling our middleware

app.wsgi_app = middleware(app.wsgi_app)

@app.route('/')
def hello():
    return render_template('success.html')

if __name__ == "__main__":
    app.run()
