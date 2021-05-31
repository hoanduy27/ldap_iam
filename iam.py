from ldap3 import ALL_ATTRIBUTES, Server, Connection, ALL, SUBTREE
import ldap3
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3.core.tls import Tls
from ldap3.protocol.sasl.sasl import validate_simple_password
import yaml
import ssl
import json

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
        self.conn = None
        self.authenticate()

    # def __get_gid(self):
    #     if self.conn.bound:
    #         if self.role != 'admin':
    #             self.conn.search(
    #                 search_base=self.conn.user,
    #                 search_filter='(objectClass=*)',
    #                 attributes=['gidNumber']
    #             )
    #             response = self.conn.entries[0].entry_to_json()
    #             response = json.loads(response)
    #             gid = response['attributes']['gidNumber'][0]

    #             self.conn.search(
    #                 search_base=f'ou=role,{self.search_base}',
    #                 search_filter=f'(&(objectClass=*)(gidNumber={gid}))',
    #                 attributes=['cn']
    #             )
                
    #             response = self.conn.entries[0].entry_to_json()
    #             response = json.loads(response)
    #             return response['attributes']['cn'][0]
    #         else:
    #             return 'admin'
    #     else:
    #         return 'admin'

    def validate_role(self):
        if(self.role != 'admin'):
            # Check whether the role exists
            if not self.conn.search(
                search_base=f'ou=role,{self.search_base}',
                search_filter=f'(&(objectClass=*)(cn={self.role}))',
                attributes=['gidNumber']
            ):
                return False

            # Check whether there is uid with this role
            response = self.conn.entries[0].entry_to_json()
            response = json.loads(response)
            gid = response['attributes']['gidNumber'][0]

            return self.conn.search(
                search_base=f'ou=user,{self.search_base}',
                search_filter=f'(&(objectClass=*)(uid={self.username})(gidNumber={gid}))',
                attributes=['gidNumber']
            )

        return self.conn.search(
            search_base = self.search_base,
            search_filter=f'(&(objectClass=*)(uid={self.username}))'
        )
    
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
        self.conn = ldap3.Connection(\
            self.server, 
            user=f'uid={self.username},ou=user,{self.search_base}', 
            password=self.password
        ) if self.role != 'admin' \
        else ldap3.Connection(
            self.server,
            user = f'uid={self.username},{self.search_base}',
            password=self.password
        )
        
        if self.conn.bind() and self.validate_role():
            print(f"Logged in as {self.role}")
            print(self.conn.entries)
        else:
            print("Wrong password or usn")
            self.conn.unbind()
        
    
    def changePassword(self, password):
        pass

def test_login():
    # Admin
    IAM('admin', 'eladmin', 'admin')
    IAM('admin', 'eladmin', 'developer')
    # Wrong password
    IAM('duynguyen', 'duybingu', 'developer')
    # Wrong usn, password
    IAM('duynguyn', 'duybingu', 'lecturer')
    # Valid usn, password, role
    IAM('cuongnguyen', 'duynguyen123', 'lecturer')
    # Valid usn, password. Wrong role
    IAM('cuongnguyen', 'duynguyen123', 'developer')
    # Valid usn, password. Role does not exists
    IAM('cuongnguyen', 'duynguyen123', 'dev')
test_login()