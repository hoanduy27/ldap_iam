import os
from flask import Flask, request, Response, render_template
from flask_cors import CORS
import json
from markupsafe import escape
from schema import Schema
from flask_expects_json import expects_json
from utils import *
from datetime import datetime
from flask_paginate import Pagination,get_page_args

path = os.path.abspath(__file__)
parent_path = path.rsplit(os.path.sep, 2)[0]
import sys
sys.path.append(parent_path)
from iam import IAM, Err

app = Flask(__name__)
CORS(app)
def capfirst(text):
    return text[0].upper() + text[1:].lower()

app.add_template_filter(capfirst)


request_schema = Schema()
iam_object = None
import pandas as pd
log = pd.read_csv("log.csv")


@app.route("/login", methods=["GET","POST"])
# @expects_json(request_schema.login)
def login():
    if request.method == "POST":
        data = request.json
        # print(data)
        if not (validate_request(data,request_schema.login)): 
            response = {'status': 'FAILED','error': "Internal Server Error"}
            return Response(response=json.dumps(response), status=400, mimetype="application/json")

        username = data["username"]
        password = data["password"]
        role = data["role"]

        global iam_object
        try:
            iam_object = IAM(username,password,role)
        except Err as e:
            response = {'status': "FAILED",
                        'error': str(e)}    
            return Response(response=json.dumps(response), status=400, mimetype="application/json")

        timestamp = datetime.now().strftime("%H:%M:%S %d/%m/%Y")
        
        global log
        log.loc[len(log)] = [timestamp,username,role]
        log.to_csv("log.csv",index=False)

        response = {'status': "OK",
                    'role' : iam_object.role}
        return Response(response=json.dumps(response), status=200, mimetype="application/json")

    if iam_object.role.upper() == "ADMIN":
        page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
        content = log.to_numpy().tolist()[::-1][offset:offset+per_page]
        pagination = Pagination(page=page, per_page=per_page, offset=offset,total=len(log),css_framework="foundation6")
        return render_template('admin.html',content=content,len=len(content),pagination=pagination,page=page,per_page=per_page)
    else:
        content = iam_object.getInfo()
        content['root'] = os.path.join(parent_path,"Frontend")
        print(content)
        return render_template('user.html', **content)

@app.route("/add-user", methods=["POST"])
@expects_json(request_schema.login)
def add_user():
    pass

@app.route("/remove-user", methods=["POST"])
@expects_json(request_schema.login)
def remove_user():
    pass

@app.route("/change-role", methods=["POST"])
@expects_json(request_schema.login)
def change_role():
    pass

@app.route("/update-info", methods=["POST"])
def update_info():
    global iam_object
    if iam_object is not None:
        data = request.json
        if not (validate_request(data,request_schema.updateInfo)): 
            response = {'status': 'FAILED','error': "Internal Server Error"}
            return Response(response=json.dumps(response), status=400, mimetype="application/json")

        cn = data["cn"]
        displayName = data["displayName"]
        gidNumber = data["gidNumber"]
        givenName = data["givenName"]
        homeDirectory = data["homeDirectory"]
        loginShell = data["loginShell"]
        role = data["role"]
        sn = data["sn"]
        uid = data["uid"]

        if (iam_object.updateInfo(cn,displayName,givenName,sn)):
            response = {'status': "OK"}
            return Response(response=json.dumps(response), status=200, mimetype="application/json")

    response = {'status': "FAIL"}
    return Response(response=json.dumps(response), status=400, mimetype="application/json")

@app.route("/get-all-users", methods=["GET"])
# @expects_json(request_schema.login)
def get_all_users():
    global iam_object
    if iam_object.role.upper() == "ADMIN":
        users = iam_object.getAllUsers(grouped=False)
        print(users[0])
        return render_template("allusers.html",users=users)
    else:
        response = {'status': 'FAILED','error': "Only admin can access this!"}
        return Response(response=json.dumps(response), status=400, mimetype="application/json")

@app.route("/change-password", methods=["POST"])
@expects_json(request_schema.login)
def change_password():
    pass

@app.route("/unbind", methods=["POST"])
@expects_json(request_schema.login)
def unbind():
    pass

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='localhost',port=port,debug=True)
