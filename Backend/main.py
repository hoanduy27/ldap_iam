import os
from flask import Flask, request, Response, render_template
import json
from markupsafe import escape
from schema import Schema
from flask_expects_json import expects_json
from utils import *

import sys
sys.path.append('../')
from iam import IAM, Err

app = Flask(__name__)
request_schema = Schema()

iam_object = None


@app.route("/login", methods=["POST"])
@expects_json(request_schema.login)
def login():
    data = request.get_json()
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


    response = {'status': "OK",
                'role' : iam_object.role}
    return Response(response=json.dumps(response), status=200, mimetype="application/json")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0',port=port,debug=True)
