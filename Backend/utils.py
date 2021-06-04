from cerberus import Validator


def validate_request(req_data, schema):
    print(req_data,schema)
    if req_data is None or not Validator(schema).validate(req_data):
        print('Wrong Schema')
        return False

    return True
