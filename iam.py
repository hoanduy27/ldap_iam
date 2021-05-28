from ldap3 import Server, Connection, ALL, SUBTREE
import ldap3
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3.core.tls import Tls
from ldap3.protocol.sasl.sasl import validate_simple_password
import yaml
import ssl

class IAM:
    def __init__(self):
        with open('config.yml', 'r') as f:
            config = yaml.safe_load(f)
        
        self.server_uri = config['serverURI']
        self.search_base = config['searchBase']
        tls_configuration = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
        self.server = Server(self.server_uri, use_ssl=True, tls=tls_configuration)
        
    def authentication(self, method, username, password, role):
        conn = ldap3.Connection(\
            self.server, 
            user=f'uid={username},ou={role},{self.search_base}', 
            password=password
        )        
        if conn.bind():
            print("Logged in")
        else:
            print("Wrong password or usn")
            conn.unbind()

        return conn

app = IAM()
app.authentication(username="duynguyen", password="duynguyen13")