from werkzeug.wrappers import Request, Response, ResponseStream
import numpy as np
from flask import Flask, request, jsonify, render_template, Response
import pickle
import pandas as pd
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
import sqlite3
import time
from functools import wraps
import datetime
from flask import jsonify
import json
import mysql.connector

def get_country(ip_address):
    try:
        response = requests.get("http://ip-api.com/json/{}".format(ip_address))
        js = response.json()
        country = js['countryCode']
        return country
    except Exception as e:
        return "Unknown"

class middleware():
    def __init__(self, app):
        self.app = app


    #    mycursor.execute("CREATE TABLE dashboard_table_1 (length INTEGER, ip_address VARCHAR(30), header VARCHAR(30), prediction VARCHAR(10), os VARCHAR(20), entryDate DATETIME, mobile INTEGER)")


    def __call__(self, environ, start_response):
        request = Request(environ)
        import re
        # model = pickle.load(open('rf.pkl','rb'))
        headers = request.headers
        print(str(headers))
        host = headers.get('Host') # 1
        protocol = 'HTTP/1.1' # 2
        userAgent = str(headers.get('User-Agent')) # 3
        acceptLanguage = 'en' # 4
        payload = str(headers) # 5
        cookie = 'abc'
        contentLength = len(headers) # 7
        connection = 'close' # 8
        acceptEncoding = str(headers.get('Accept-Encoding')) # 9
        acceptCharset = 'utf-8' # 10
        pragma = 'no-cache' # 11
        cacheControl = str(pragma) # 12
        method = 'GET' # 13
        contentType = 'application/x-www-form-urlencoded'
        df = pd.DataFrame({'method': [method], 'protocol': [protocol], 'userAgent': [str(userAgent)], 'pragma': [pragma], 'cacheControl': [cacheControl],
        'acceptEncoding': [str(acceptEncoding)], 'acceptCharset': [acceptCharset], 'acceptLanguage': [acceptLanguage],
        'host': [str(host)], 'connection': [connection], 'contentLength': [contentLength], 'contentType': [contentType],
        'cookie': [cookie], 'payload': [payload]})
        df = df.astype("|S")
        ipadd = (request.environ.get('HTTP_X_REAL_IP', request.remote_addr))
        country = get_country(ipadd)
        print(str(country))
        # le = preprocessing.LabelEncoder() ## need to change the encoder that is used
        # encoded_df = df.apply(le.fit_transform)
        # arr = encoded_df.values
        # y = np.reshape(arr, (-1, 14))
        #
        #
        # y = model.predict(y)
        # if(y[0]<0.5):
        #     result = 'benign'
        # else:
        #     result = 'malicious'
        df2 = pd.read_csv('nikto_new.csv')
        list2 = list(df2['User-Agent'])
        for i in list2:
            if(i in userAgent):
                result = 'malicious'
            else:
                result = 'benign'
        ## get the os type:


        os = ''
        if('Mac' in userAgent):
            os = 'MacOS'
        elif('Windows' in userAgent):
            os = 'Windows'
        elif(('Linux' in userAgent) | ('Nikto' in userAgent)):
            os = 'Linux'
        else:
            os = 'Linux'
        mobile = 0
        if('Mobile' in userAgent):
            mobile = 1
        else:
            mobile = 0

        headers = str(headers)
        length = str(len(headers))
        ipadd = str(request.environ.get('HTTP_X_REAL_IP', request.remote_addr))

        mydb = mysql.connector.connect(
        host="sql12.freemysqlhosting.net",
        user="sql12385151",
        password="2BpydgEQwF",
        database = "sql12385151"
        )

        mycursor = mydb.cursor()

        sql = "INSERT INTO dashboard_table_1 (length, ip_address, header, prediction, os, entryDate, mobile) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        val = (length,ipadd, headers,result,os,datetime.datetime.now(),mobile)
        mycursor.execute(sql, val)
        mydb.commit()

        print(mycursor.rowcount, "record inserted.")

        if(result == 'benign'):
            return self.app(environ, start_response)

        res = Response(u'Authorization failed', mimetype= 'text/plain', status=401)
        return res(environ, start_response)
