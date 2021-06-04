class Schema():
    def __init__(self):
        self.hello = {}
        self.login = {
            'username': {'type': 'string', 'required': True},
            'password': {'type': 'string', 'required': True},
            'role': {'type': 'string', 'required': True}
        }