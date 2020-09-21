#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@File   : flask-coding.py
@Author : DEADF1SH_CAT
'''

import json
from flask import Flask
from flask import render_template
from flask import request
import coding

app = Flask(__name__)

@app.route('/', methods=['POST','GET'])
def index():
    return render_template('index.html')

@app.route('/coding', methods=['POST'])
def codec():
    data = request.json.get('data')
    codingtype = data['type']
    action = data['action']
    string = data['string']
    
    if "key" in data:
        key = data['key']
        code = coding.Codec(codingtype,action,key)
    else:
        code = coding.Codec(codingtype,action)
        
    return code.run(string)

if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0',port='8000')