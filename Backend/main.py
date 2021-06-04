import os
from flask import Flask, request, Response, render_template
from flask_cors import CORS
import json
from markupsafe import escape
from schema import Schema
from flask_expects_json import expects_json
from utils import *

import sys
sys.path.append('../')
from iam import IAM, Err

app = Flask(__name__)
CORS(app)
request_schema = Schema()

iam_object = None


@app.route("/login", methods=["POST"])
# @expects_json(request_schema.login)
def login():
    data = request.json
    print(data)
    if not (validate_request(data,request_schema.login)): 
        return "-1"

    username = data["username"]
    password = data["password"]
    role = data["role"]

    global iam_object
    try:
        iam_object = IAM(username,password,role)
    except Err as e:
        response = {'status': "FAILED",
                    'error': str(e)}    
        print(str(e))
        return Response(response=json.dumps(response), status=400, mimetype="application/json")


    response = {'status': "OK",
                'role' : iam_object.role}
    return Response(response=json.dumps(response), status=200, mimetype="application/json")

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
@expects_json(request_schema.login)
def update_info():
    pass

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
