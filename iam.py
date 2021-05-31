from ldap3 import ALL_ATTRIBUTES, Server, Connection, ALL, SUBTREE
import ldap3
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3.core.tls import Tls
from ldap3.protocol.sasl.sasl import validate_simple_password
import yaml
import ssl

class IAM:
    def __init__(self, username, password, role):
        with open('config.yml', 'r') as f:
            config = yaml.safe_load(f)
        
        self.server_uri = config['serverURI']
        self.search_base = config['searchBase']
        tls_configuration = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
        self.server = Server(self.server_uri, use_ssl=True, tls=tls_configuration)
        self.username = username
        self.password = password
        self.role = role
        self.conn = self.authenticate()

    def addUser(self, username, password):
        if(self.role=='admin'):
            #TODO
            pass
    
    def removeUser(self, username, password):
        if(self.role=='admin'):
            #TODO
            pass
    
    def changeRole(self, username, role):
        if(self.role == 'admin'):
            #TODO
            pass
        
    def authenticate(self):
        conn = ldap3.Connection(\
            self.server, 
            user=f'uid={self.username},ou=user,{self.search_base}', 
            password=self.password
        ) if self.role != 'admin' \
        else ldap3.Connection(
            self.server,
            user = f'uid={self.username},{self.search_base}',
            password=self.password
        )
        
        if conn.bind():
            print("Logged in")
        else:
            print("Wrong password or usn")
            conn.unbind()
        
        
        return conn
    
    def changePassword(self, password):
        pass

app = IAM('duynguyen', 'duynguyen123', 'developer')

app.conn.search(search_base=app.conn.user, search_filter=f'(objectClass=*)', attributes=['gidNumber'])
print(app.conn.entries[0])

