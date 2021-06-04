class Schema():
    def __init__(self):
        self.hello = {}
        self.login = {
            'username': {'type': 'string', 'required': True},
            'password': {'type': 'string', 'required': True},
            'role': {'type': 'string', 'required': True}
        }
        self.updateInfo = {
            'cn': {'type': 'string', 'required': True},
            'displayName': {'type': 'string', 'required': True},
            'gidNumber': {'type': 'string', 'required': True},
            'givenName': {'type': 'string', 'required': True},
            'homeDirectory': {'type': 'string', 'required': True},
            'loginShell': {'type': 'string', 'required': True},
            'role': {'type': 'string', 'required': True},
            'sn': {'type': 'string', 'required': True},
            'uid': {'type': 'string', 'required': True}
        }
