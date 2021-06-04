class Schema():
    def __init__(self):
        self.hello = {}
        self.login = {
            'username': {'type': 'string', 'required': True},
            'password': {'type': 'string', 'required': True},
            'role': {'type': 'string', 'required': True}
        }
        # self.login = {
        #     'type': 'object',
        #     'properties': {
        #         'username': {'type': 'string'},
        #         'password': {'type': 'string'},
        #         'role': {'type': 'string'}
        #     },
        #     'required': ['username', 'password','role']
        # }