import re
from ldap3 import ALL_ATTRIBUTES, MODIFY_REPLACE, Server, Connection, ALL, SUBTREE
import ldap3
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3.core.tls import Tls
from ldap3.protocol.sasl.sasl import validate_simple_password
import yaml
import ssl
import json
import os
from functools import reduce

class Err(Exception):
    def __init__(self,text):
        self.message = text
class IAM:
    def __init__(self, username, password, role):
        # with open('config/config.yml', 'r') as f:
        #     config = yaml.safe_load(f)
        
        path = os.path.abspath(__file__)
        with open(os.path.join(path.rsplit(os.path.sep, 1)[0], 'config/config.yml'), 'r') as f:
            config = yaml.safe_load(f)


        self.server_uri = config['serverURI']
        self.search_base = config['searchBase']
        tls_configuration = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
        self.server = Server(self.server_uri, use_ssl=True, tls=tls_configuration, get_info=ldap3.ALL)
        #self.server = Server(self.server_uri, get_info=ldap3.ALL, use_ssl=True)
        self.username = None
        self.password = None
        self.role = None
        self.conn = None
        self.isLoggedIn = False
        self.login(username, password, role)
    def _get_new_uid(self):
        if self.conn.search(
            search_base=f'ou=user,{self.search_base}',
            search_filter=f'(&(objectClass=*))',
            attributes=['uidnumber']
        ):
            responses = self.conn.entries
            def getuid(r):
                entry = json.loads(r.entry_to_json())
                return entry['attributes']['uidNumber'][0]
            uids = list(map(lambda r: getuid(r), responses[1:]))
            return max(uids) + 1
        return None

    def _find_gid(self, role):
        if self.conn.search(
            search_base=f'ou=role,{self.search_base}',
            search_filter=f'(&(objectClass=*)(cn={role}))',
            attributes=['gidNumber']
        ):
            response = self.conn.entries[0].entry_to_json()
            response = json.loads(response)
            return response['attributes']['gidNumber'][0]

        return None

    def _fetch_roles(self):
        if self.conn.search(
            search_base=f'ou=role,{self.search_base}',
            search_filter=f'(objectClass=*)',
            attributes=['gidNumber', 'cn']
        ):
            response = self.conn.entries
            gids ={}
            for entry in response[1:]:
                entry = json.loads(entry.entry_to_json())
                entry = entry['attributes']
                gids.update({entry['gidNumber'][0] : entry['cn'][0]})
            return gids
        return None

    def _find_role(self, gid):
        if self.conn.search(
            search_base=f'ou=role,{self.search_base}',
            search_filter=f'(&(objectClass=*)(gidNumber={gid}))',
            attributes=['cn']
        ):
            response = self.conn.entries[0].entry_to_json()
            response = json.loads(response)
            return response['attributes']['cn'][0]
        return None

    def _validate_role(self):
        if(self.role != 'admin'):     
            # Check whether the role exists
            gid = self._find_gid(self.role)
            if gid is None:
                return False
            return self.conn.search(
                search_base=f'ou=user,{self.search_base}',
                search_filter=f'(&(objectClass=*)(uid={self.username})(gidNumber={gid}))',
            )


        return self.conn.search(
            search_base = self.search_base,
            search_filter=f'(&(objectClass=*)(uid={self.username}))'
        )
    
    
    def add_user(self, givenName, surname, username, password, role):
        if(self.isLoggedIn and self.role=='admin'):
            gid = self._find_gid(role)
            if gid is not None:
                self.conn.add(
                    dn=f'uid={username},ou=user,{self.search_base}',
                    object_class=[
                        'inetOrgPerson', 
                        'posixAccount', 
                        'shadowAccount'],
                    attributes={
                        'cn': f'{givenName} {surname}',
                        'displayname': f'{givenName} {surname}',
                        'gidnumber': gid,
                        'givenname': givenName,
                        'sn': surname,
                        'uid': username,
                        'uidnumber': self._get_new_uid(),
                        'userpassword': password,
                        'homeDirectory': f'/home/{username}',
                        'loginShell': '/bin/bash'
                    }
                )
                ret = self.conn.result
                if(ret['result'] == 0):
                    return True
                else:
                    raise Err(ret['description'])
                
            raise Err('Role not found!')
        raise Err('You do not have permission!')
                
    
    def remove_user(self, username):
        if(self.isLoggedIn and self.role=='admin'):
            self.conn.delete(
                dn=f'uid={username},ou=user,{self.search_base}'
            )
            ret = self.conn.result
            if(ret['result'] == 0):
                return True
            else:
                raise Err(ret['description'])
        else:
            raise Err("You do not have permission!")

    
    def change_role(self, username, role):
        if(self.isLoggedIn and self.role=='admin'):
            gid = self._find_gid(role)
            if gid is not None:
                self.conn.modify(
                    dn=f'uid={username},ou=user,{self.search_base}',
                    changes={'gidNumber': [(MODIFY_REPLACE, [gid])]}
                )
                ret = self.conn.result
                if(ret['result'] == 0):
                    return True
                else:
                    raise Err(ret['description'])
            else:
                raise Err("Role not found!")
        else:
            raise Err("You do not have permission!")
    def authenticate(self):
        def isEmpty(s):
            return s is None or s == ""
        if(isEmpty(self.username) or isEmpty(self.password)):
            raise Err("Username or password must not be empty!")
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
        
        if self.conn.bind() and self._validate_role():
            return True
        else:

            self.conn.unbind()
            return False
    
    def login(self, username, password, role):
        if not self.isLoggedIn:
            self.username = username
            self.password = password
            self.role = role
            self.isLoggedIn = self.authenticate()
            if(self.isLoggedIn):
                print(f"Logged in as {self.role}")
                print(self.conn.entries)
            else:
                raise Err("Wrong password, username or role")
        else:
            print("No need. Already logged in")
            
        
    def updateInfo(self, cn=None, displayName=None, givenName=None, sn=None):
        if(self.isLoggedIn):
            dn=f'uid={self.username},ou=user,{self.search_base}' if self.role!='admin'\
                else f'uid={self.username},{self.search_base}'
            changes = {
                'cn': [(MODIFY_REPLACE, [cn])],
                'displayName': [(MODIFY_REPLACE, [displayName])],
                'givenName': [(MODIFY_REPLACE, [givenName])],
                'sn': [(MODIFY_REPLACE, [sn])]
            }
            changes = {k: changes[k] for k in changes if changes[k][0][1][0] is not None}

            return self.conn.modify(
                dn=dn,
                changes=changes
            )
        else:
            return False

    def changePassword(self, password):
        if self.isLoggedIn:
            dn=f'uid={self.username},ou=user,{self.search_base}' if self.role!='admin'\
                else f'uid={self.username},{self.search_base}'
            
            if self.conn.modify(
                dn=dn,
                changes={
                    'userpassword': [(MODIFY_REPLACE, [password])]
            }):
                self.logout()
                print('Password has changed. Please re-login')
                return True
            else: 
                raise Err("Change failed. Please try again")
        else:
            raise Err("Update password failed. You're not logged in")

    def logout(self):
        if self.isLoggedIn:
            if not self.conn.bound:
                self.conn.unbind()
            self.username = None
            self.password = None
            self.role = None
            self.isLoggedIn = False
            return True
        else:
            print("No need. Already logged out")
            return False

    def getInfo_by_usn(self, username):
        if(self.isLoggedIn):
            search_base = f'uid={username},ou=user,{self.search_base}'
            attributes = ['givenName', 'sn', 'cn', 'displayName', 'homeDirectory', 'loginShell', 'gidNumber'] \
                if self.role=='admin' else ['givenName', 'sn', 'cn', 'displayName','gidNumber']

            self.conn.search(
                search_base=search_base,
                search_filter=f'(objectClass=*)',
                attributes=attributes
            )
            ret = self.conn.result
            if ret['result'] == 0:
                response = self.conn.entries[0].entry_to_json()
                response = json.loads(response)
                response = response['attributes']
                info = {k: response[k][0] for k in response}
                info.update({'uid':self.username, 'role': self._find_role(info['gidNumber'])})
                return info
            else:
                raise Err(ret['description'])
        raise Err("You're not logged in")

    def getInfo(self):
        if(self.isLoggedIn):
            search_base = f'uid={self.username},ou=user,{self.search_base}' if self.role != 'admin' \
                else f'uid={self.username},{self.search_base}'
            attributes = ['givenName', 'sn', 'cn', 'displayName', 'homeDirectory', 'loginShell', 'gidNumber'] \
                if self.role != 'admin' else ['givenName', 'sn', 'cn', 'displayName']
            self.conn.search(
                search_base=search_base,
                search_filter=f'(objectClass=*)',
                attributes=attributes
            )
            response = self.conn.entries[0].entry_to_json()
            response = json.loads(response)
            response = response['attributes']
            info = {k: response[k][0] for k in response}
            info.update({'uid':self.username, 'role': self.role})
            return info
        raise Err("You're not logged in")

    def getAllUsers(self, grouped=False):
        """
            List all users
            Return value: json(data)
                - grouped = False: data = List[{attr: value}]
                - grouped = True: data = {gid: {role: name, users: List{attr: value}}}
            Example:
                - grouped = True:
                {
                    "5000":{
                        "role": "developer",
                        "users": [...]
                    },
                    "5001":{
                        "role": "lecturer",
                        "users": [...]
                    },
                    ...
                }
        """
        if(self.isLoggedIn and self.role == 'admin'):
            self.conn.search(
                search_base=f'ou=user,{self.search_base}',
                search_filter=f'(objectClass=*)',
                attributes=['givenName', 'sn', 'cn', 'displayName', 'homeDirectory', 'loginShell', 'gidNumber']
            )
            response = self.conn.entries
            def getUser(r):
                entry = json.loads(r.entry_to_json())
                entry = entry['attributes']
                return {k: entry[k][0] for k in entry}
            users = list(map(lambda x: getUser(x), response[1:]))
            if not grouped:
                # return json.dumps(users)
                return users
            else:
                roles = self._fetch_roles()
                grouped_users = {}
                for gid, role in roles.items(): 
                    grouped_users.update({
                        gid:{
                            'role': role,
                            'users': list(filter(lambda x: x['gidNumber'] == gid, users))
                        }
                    })
                # return json.dumps(grouped_users)
                return grouped_users
        raise Err("You don't have permission")
    


# def test_login():
#     # Admin
#     admin = IAM('admin', 'eladmin', 'admin')
#     #print(admin.add_user("Vuong", "Hoang", 'hoangvuong', 'hoangvuong123', 'student'))
#     IAM('admin', 'eladmin', 'developer')
#     # Wrong password
#     IAM('duynguyen', 'duynguyen', 'developer')
#     # Wrong usn, password
#     IAM('duynguyn', 'duybingu', 'lecturer')
#     # Valid usn, password, role
#     good = IAM('cuongnguyen', 'duynguyen123', 'lecturer')
#     # Valid usn, password. Wrong role
#     IAM('cuongnguyen', 'duynguyen123', 'developer')
#     # Valid usn, password. Role does not exists
#     IAM('cuongnguyen', 'duynguyen123', 'dev')

# #if __name__ == '__main__':
# test_login()

# app=IAM('admin', 'eladmin', 'admin')
# print(app.add_user('Kim', 'Nguyen', 'kimnguyen', 'kimnguyen', 'student'))
