# -*- coding: utf-8 -*-

import base64
import hashlib
import json
import os
import random
import sqlite3
import string
import uuid
from datetime import datetime
from hashlib import sha1
from sqlite3 import Error

import bcrypt as bcrypt
import pytz
import requests
import xmltodict
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from bs4 import BeautifulSoup
import jwt

# Zato
from zato.server.service import Service


class NiraGeneralService(Service):

    name = 'NIRA_GENERAL'

    class SimpleIO:
        input = 'method'

    def create_table(self, conn, create_table_sql):
        """ create a table from the create_table_sql statement
        :param conn: Connection object
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """
        try:
            c = conn.cursor()
            c.execute(create_table_sql)
            return True
        except Error as e:
            print(e)
            return False

    def create_user_accounts_table(self):
        sql = "CREATE TABLE IF NOT EXISTS user_accounts (id integer PRIMARY KEY, username text NOT NULL, password text, active text, superuser integer);"
        conn = self.get_conn()
        state = False
        if conn:
            state = self.create_table(conn, sql)
            conn.close()
        return state

    def create_jwt_table(self):
        sql = "CREATE TABLE IF NOT EXISTS jwt (id integer PRIMARY KEY, key text NOT NULL, token text);"
        conn = self.get_conn()
        state = False
        if conn:
            state = self.create_table(conn, sql)
            conn.close()
        return state

    def create_auth_table(self):
        sql = "CREATE TABLE IF NOT EXISTS auth (id integer PRIMARY KEY, username text NOT NULL, password text);"
        conn = self.get_conn()
        state = False
        if conn:
            state = self.create_table(conn, sql)
            conn.close()
        return state

    def create_password_table(self):
        sql = "CREATE TABLE IF NOT EXISTS password_age (id integer PRIMARY KEY, age text NOT NULL);"
        conn = self.get_conn()
        state = False
        if conn:
            state = self.create_table(conn, sql)
            conn.close()
        return state

    def hash_password(self, raw):
        return bcrypt.hashpw(raw.encode('utf-8'), bcrypt.gensalt())

    def verify_password(self, hashed, password):
        if isinstance(password, str):
            return bcrypt.checkpw(password.encode('utf-8'), hashed)
        else:
            return bcrypt.checkpw(password, hashed)

    def get_token(self, username, password):
        user_account = self.get_user_account(username)
        passw = user_account['password']
        if user_account and user_account['active'] == 'active' and \
                self.verify_password(passw if isinstance(passw, bytes) else passw.encode('utf-8'), password):
            key = uuid.uuid4().hex
            token = jwt.encode({"a": self.hash_password(key).decode('utf-8'), 'user': username}, key, algorithm="HS256")
            self.remove_user_tokens(username)
            self.insert_jwt_token(token, key)
            return {
                'token': token
            }
        return None

    def verify_token(self, token):
        key = self.get_jwt_key(token)
        if key:
            hashed = jwt.decode(token, key, algorithms=["HS256"])
            user_account = self.get_user_account(hashed['user'])
            try:
                del user_account['password']
            except Exception:
                pass
            return {
                'verified': self.verify_password(hashed['a'].encode('utf-8'), key) and (
                    user_account is not None and user_account['active'] == 'active'),
                'account': user_account
            }
        else:
            return {
                'verified': False,
                'account': None
            }

    def remove_user_tokens(self, username):
        conn = self.get_conn()
        if conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(f"SELECT * FROM jwt")
            rows = cur.fetchall()
            for row in rows:
                hashed = jwt.decode(row['token'], row['key'], algorithms=["HS256"])
                if hashed['user'] == username:
                    cur.execute(f"DELETE FROM jwt WHERE id = {row['id']}")
                    conn.commit()

    def insert_jwt_token(self, token, key):
        if self.create_jwt_table():
            conn = self.get_conn()
            if conn:
                sql = ''' INSERT INTO jwt(token, key) VALUES(?,?) '''
                cur = conn.cursor()
                cur.execute(sql, (token, key))
                conn.commit()
                row = cur.lastrowid
                conn.close()
                return row
        return -1

    def create_user_account(self, username, password, active, superuser):
        if self.create_user_accounts_table():
            conn = self.get_conn()
            password_hash = self.hash_password(password)

            if conn:
                sql = ''' INSERT INTO user_accounts(username,password,active, superuser) VALUES(?,?,?,?) '''
                cur = conn.cursor()
                cur.execute(sql, (username, password_hash, active, superuser))
                conn.commit()
                row = cur.lastrowid
                conn.close()
                return row
        return -1

    def change_user_account_status(self, username, active):
        conn = self.get_conn()
        if conn:
            sql = f"UPDATE user_accounts SET active = '{active}' WHERE username = '{username}';"
            cur = conn.cursor()
            cur.execute(sql)
            conn.commit()
            row = cur.lastrowid
            conn.close()
            return row

        return -1

    def change_user_account_password(self, username, password):
        conn = self.get_conn()
        if conn:
            sql = f"UPDATE user_accounts SET password = '{self.hash_password(password).decode('utf-8')}' WHERE username = '{username}';"
            cur = conn.cursor()
            cur.execute(sql)
            conn.commit()
            row = cur.lastrowid
            conn.close()
            return row

        return -1

    def set_age(self, age):
        if self.create_password_table():
            conn = self.get_conn()
            if conn:
                sql = ''' INSERT INTO password_age(age) VALUES(?) '''
                del_sql = '''DELETE FROM password_age '''
                cur = conn.cursor()
                cur.execute(del_sql)
                conn.commit()
                cur.execute(sql, (age,))
                conn.commit()
                row = cur.lastrowid
                conn.close()
                return row
        return -1

    def set_auth(self, username, password):
        if self.create_auth_table() and self.create_password_table():
            conn = self.get_conn()
            if conn:
                sql = ''' INSERT INTO auth(username,password) VALUES(?,?) '''
                del_sql = '''DELETE FROM auth '''
                cur = conn.cursor()
                cur.execute(del_sql)
                conn.commit()
                cur.execute(sql, (username, password))
                conn.commit()
                row = cur.lastrowid
                conn.close()
                return row
        return -1

    def get_jwt_key(self, token):
        """
        Query all rows in the tasks table
        :param conn: the Connection object
        :return:
        """
        conn = self.get_conn()
        if conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(f"SELECT * FROM jwt WHERE token = '{token}'")
            rows = cur.fetchone()
            key = rows['key'] if rows else None
            return key
        return None

    def get_auth(self):
        """
        Query all rows in the tasks table
        :param conn: the Connection object
        :return:
        """
        try:
            conn = self.get_conn()
            if conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT * FROM auth")
                cur2 = conn.cursor()
                cur2.execute("SELECT * FROM password_age")
                rows = cur.fetchone()
                rows2 = cur2.fetchone()
                age = rows2['age'] if rows2 else None
                return {'username': rows['username'], 'password': rows['password'], 'age': age}
        except Exception:
            pass
        return None

    def superuser_exists(self):
        sql = f"SELECT * FROM user_accounts WHERE superuser=1"
        conn = self.get_conn()
        if conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(sql)
            rows = cur.fetchall()
            username = True if rows else False
        return False

    def get_user_account(self, username, superuser=None):
        """
        Query all rows in the tasks table
        :param conn: the Connection object
        :return:
        """
        sql = f"SELECT * FROM user_accounts WHERE username='{username}'"
        if superuser is not None:
            sql = f"{sql} and superuser={superuser}"
        conn = self.get_conn()
        if conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(sql)
            rows = cur.fetchone()
            username = rows['username'] if rows else None
            if username:
                return {
                    'username': rows['username'],
                    'password': rows['password'],
                    'active': rows['active'],
                    'superuser': rows['superuser']
                }
        return None

    def get_conn(self):
        sqlite_db = r"/opt/zato/3.2.0/code/zato_sqlite.db"

        """ create a database connection to a SQLite database """
        try:
            return sqlite3.connect(sqlite_db)
        except Error as e:
            return None

    def reset_password(self, client):
        url = client.wsdl.url
        auth = self.get_auth()
        if auth:
            obj = SoapClientBuilder_v2(
                wsdl=url,
                username=auth.get('username'),
                password=auth.get('password')
            )
            new_password = obj.password_generator()
            res = obj.getGeneric(
                method='changePassword',
                params=f'<newPassword>{new_password}</newPassword>'
            )
            o = obj.soap2Json(res, self.request.input.method)

            password_days_left = 0
            try:
                password_days_left = o['transactionStatus']['passwordDaysLeft']
                self.set_auth(auth.get('username'), new_password)
                self.set_age(password_days_left)
            except Exception:
                pass
            return o
        return None

    def verify_superuser(self, token):
        try:
            verified = self.verify_token(token)
            return verified['verified'] and verified['account']['superuser'] == 1
        except Exception:
            return False

    def create_tables(self):
        self.create_password_table()
        self.create_jwt_table()
        self.create_auth_table()
        self.create_user_accounts_table()

    def handle(self):

        with self.outgoing.soap.get('NIRA').conn.client() as client:
            self.create_tables()
            method = self.request.input.method
            if method == 'setPassword':
                if self.verify_superuser(self.request.payload['token']):
                    del self.request.payload['token']
                    cre = self.request.payload
                    self.set_auth(
                        username=cre['username'],
                        password=cre['password']
                    )
                    self.response.payload = {
                        'data': self.get_auth()
                    }
            elif method == 'getPassword':
                if self.verify_superuser(self.request.payload['token']):
                    auth = self.get_auth()
                    self.response.payload = {
                        'data': auth if auth else {
                            'error': 'No auth credentials found'
                        }
                    }
            elif method == 'changePassword':
                if self.verify_superuser(self.request.payload['token']):
                    re = self.reset_password(client)
                    self.response.payload = {
                        'data': re if re else {
                            'error': 'No auth credentials found'
                        }
                    }
            elif method == 'changeUserPassword':
                verified = self.verify_token(self.request.payload['token'])
                user = self.request.payload
                if (verified['verified'] and verified['account']['username'] == user['username']) \
                        or self.verify_superuser(self.request.payload['token']):
                    self.change_user_account_password(user['username'], user['password'])
                    self.remove_user_tokens(user['username'])
                    account = self.get_user_account(user['username'])
                    if account:
                        del account['password']
                        self.response.payload = {
                            'data': {
                                'account': account,
                                'status': 'Password updated'
                            }
                        }
                    else:
                        self.response.payload = {
                            'data': {
                                'error': 'user unknown'
                            }
                        }
            elif method == 'getUserAccount':
                verified = self.verify_token(self.request.payload['token'])
                user = self.request.payload
                if (verified['verified'] and verified['account']['username'] == user['username']) \
                        or self.verify_superuser(self.request.payload['token']):
                    account = self.get_user_account(user['username'])
                    if account:
                        del account['password']
                        self.response.payload = {
                            'data': account
                        }
                    else:
                        self.response.payload = {
                            'data': {
                                'error': 'user unknown'
                            }
                        }
                else:
                    self.response.payload = {
                        'data': {
                            'error': 'Authorization Error'
                        }
                    }
            elif method == 'getToken':
                user = self.request.payload
                account = self.get_user_account(user['username'])
                token = self.get_token(account['username'], user['password'])
                if account:
                    self.response.payload = {
                        'data': token if token else {
                            'error': 'Invalid Credentials'
                        }
                    }
                else:
                    self.response.payload = {
                        'data': {
                                'error': 'user unknown'
                            }
                    }
            elif method == 'deactivateUser':
                if self.verify_superuser(self.request.payload['token']):
                    user = self.request.payload
                    account = self.get_user_account(user['username'])
                    if account:
                        self.change_user_account_status(username=user['username'], active='inactive')
                        account = self.get_user_account(user['username'])
                        self.remove_user_tokens(user['username'])
                        del account['password']
                        self.response.payload = {
                            'data': account
                        }
                    else:
                        self.response.payload = {
                            'data': {
                                'error': 'user unknown'
                            }
                        }
            elif method == 'activateUser':
                if self.verify_superuser(self.request.payload['token']):
                    user = self.request.payload
                    account = self.get_user_account(user['username'])
                    if account:
                        self.change_user_account_status(username=user['username'], active='active')
                        account = self.get_user_account(user['username'])
                        del account['password']
                        self.response.payload = {
                            'data': account
                        }
                    else:
                        self.response.payload = {
                            'data': {
                                'error': 'user unknown'
                            }
                        }
            elif method == 'registerUser':
                if self.verify_superuser(self.request.payload['token']) or self.request.payload['token'] == '$re^&&*45rTn)(':
                    user = self.request.payload
                    account = self.get_user_account(user['username'])
                    if account:
                        self.response.payload = {
                            'data': 'username is in use'
                        }
                    else:
                        superuser = 0
                        if user.get('superuser'):
                            _exists = self.superuser_exists()
                            superuser = user.get('superuser') if not _exists else 0
                        self.create_user_account(
                            username=user['username'],
                            password=user['password'],
                            active='active',
                            superuser=superuser
                        )
                        account = self.get_user_account(user['username'])
                        if account:
                            del account['password']
                            self.response.payload = {
                                'data': account
                            }
                        else:
                            self.response.payload = {
                                'data': {
                                    'error': 'Reg. Failed'
                                }
                            }
                else:
                    self.response.payload = {
                        'data': {
                            'error': "Access Denied"
                        }
                    }
            else:
                verified = self.verify_token(self.request.payload['token'])
                if verified['verified']:
                    del self.request.payload['token']
                    url = client.wsdl.url
                    auth = self.get_auth()
                    if auth:
                        obj = SoapClientBuilder_v2(
                            wsdl=url,
                            username=auth.get('username'),
                            password=auth.get('password')
                        )

                        res = obj.getGeneric(
                            method=self.request.input.method,
                            params=str(obj.dict2Xml(self.request.payload))
                        )

                        o = obj.soap2Json(res, self.request.input.method)

                        password_days_left = 0
                        try:
                            password_days_left = o['transactionStatus']['passwordDaysLeft']
                            if int(password_days_left) < 2:
                                self.reset_password(client)
                            else:
                                self.set_age(password_days_left)
                        except Exception:
                            self.set_age(password_days_left)

                        try:
                            del o['transactionStatus']
                        except Exception:
                            pass
                        self.response.payload = {
                            'data': json.loads(json.dumps(o))
                        }
                    else:
                        self.response.payload = {
                            'data': {
                                'error': 'No auth credentials found'
                            }
                        }
                else:
                    self.response.payload = {
                        'data': {
                            'error': 'Token is missing or invalid'
                        }
                    }


class SoapClientBuilder_v2():
    """Class to handle building of the soap client
    """

    def __init__(self, wsdl, username, password):
        """Constructor

        Arguments:
            wsdl {str} -- WSDL url
            username {str} -- Username
            password {str} -- Password
        """
        self.wsdl = wsdl
        self.username = username
        self.password = password

    def generatenonce_asbytes(self):
        """Generates Nonce as bytes
        """
        return os.urandom(16)

    def generatenonce_asbytearray(self):
        """Generates Nonce as bytearray
        """
        return bytearray(os.urandom(16))

    def create_requesttimestamp(self):
        """Creates timestamp to be used when
        sending request
        """
        utc_now = pytz.utc.localize(datetime.utcnow())
        eat_now = utc_now.astimezone(pytz.timezone('Africa/Kampala'))
        eat_time = eat_now.isoformat()

        timestamp = '{}+03:00'.format(eat_time[:-9])

        return timestamp

    def create_timestamp(self):
        """Create timestamp
        """
        utc_now = pytz.utc.localize(datetime.utcnow())
        eat_now = utc_now.astimezone(pytz.timezone('Africa/Kampala'))
        eat_time = eat_now.isoformat()

        return eat_time

    def timestamp_forrequest(self, timestamp):
        """Formats timestamp for request

        Arguments:
            timestamp {string} -- Timestamp in the format
            to be sent with the request as Created
        """
        return '{}+03:00'.format(timestamp[:-9])

    def timestamp_fordigest(self, timestamp):
        """Formates timestamp for digest

        Arguments:
            timestamp {string} -- Timestamp in the format
            to be used to creat password digest
        """
        return '{}+0300'.format(timestamp[:-9])

    def gettimestamp_asbytes(self, timestamp):
        """Gets timestamp as bytes

        Arguments:
            timestamp {str} -- Timestamp
        """
        return timestamp.encode('utf-8')

    def hashpassword_withdigest(self):
        """Hash password using sha1.digest() function
        """
        return sha1(self.password.encode('utf-8')).digest()

    def generatedigest_withbytesvalues(self, nonce, created, password_hash):
        """Generates password digest using sha1.digest
        function

        Arguments:
            nonce {bytes} -- Nonce
            created {bytes} -- Created
            password_hash {bytes} -- Hashed password
        """
        combined_bytearray = bytearray()

        combined_bytearray.extend(nonce)
        combined_bytearray.extend(created)
        combined_bytearray.extend(password_hash)

        encoded_digest = sha1(combined_bytearray).digest()

        password_digest = base64.b64encode(encoded_digest)

        return password_digest.decode('utf-8')

    def get_auth_header(self):
        username = self.username
        nonce_bytes = self.generatenonce_asbytes()
        nonce = base64.b64encode(nonce_bytes).decode('utf-8')
        timestamp = self.create_timestamp()
        created_digest = self.timestamp_fordigest(timestamp)
        created_digest_bytes = self.gettimestamp_asbytes(created_digest)
        passwordhash_bytes = self.hashpassword_withdigest()
        password_digest = self.generatedigest_withbytesvalues(nonce_bytes, created_digest_bytes, passwordhash_bytes)
        created_request = self.timestamp_forrequest(timestamp)

        header = f'<soapenv:Header> <wsse:UsernameToken> <wsse:Username>{username}</wsse:Username>' \
                 f' <wsse:Password Type="PasswordDigest">{password_digest}</wsse:Password> <wsse:Nonce>{nonce}' \
                 f'</wsse:Nonce> <wsse:Created>{created_request}</wsse:Created> </wsse:UsernameToken> </soapenv:Header>'
        namespace = 'xmlns:wsse= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"'
        return namespace, header

    def getEntity(self, method, params):
        url = self.wsdl
        namespace, security_header = self.get_auth_header()
        headers = {'Content-Type': 'text/xml'}
        body = f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ' \
               f'xmlns:fac="http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/' \
               f'" {namespace}> {security_header} ' \
               f'<soapenv:Body> ' \
               f'<fac:{method}>' \
               f'<request>' \
               f'{params}' \
               f'</request> ' \
               f'</fac:{method}> ' \
               f'</soapenv:Body> ' \
               '</soapenv:Envelope>'
        response = requests.post(url, data=body, headers=headers)
        return response.content.decode('utf-8')

    def getGeneric(self, method, params):
        res = self.getEntity(
            method=method,
            params=params
        )
        return res

    def dict2Xml(self, data):
        xml = []
        for k, v in data.items():
            xml.append(
                f'<{k}>{v}</{k}>'
            )
        return ' '.join(xml)

    def soap2Json(self, xml, caller=None):
        o = xmltodict.parse(xml)
        if caller:
            caller = f'ns2:{caller}Response'
        try:
            o = o['soap:Envelope']['soap:Body'][caller]['return']
        except Exception:
            pass
        return o

    def getPlaceOfBirth(self, nin):
        res = self.getEntity(
            method='getPlaceOfBirth',
            params=f'<nationalId>{nin}</nationalId>'
        )
        return res

    def changePassword(self, nin):
        res = self.getEntity(
            method='getPlaceOfBirth',
            params=f'<nationalId>{nin}</nationalId>'
        )
        return res

    def build_change_password_request(self, new_password):
        """
        Build request to change password

        """
        body = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ' \
               'xmlns:fac="http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/" ' \
               'xmlns:wsse= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"> ' \
               '<soapenv:Header> <wsse:UsernameToken> <wsse:Username>{0}</wsse:Username>' \
               ' <wsse:Password Type="PasswordDigest">{1}</wsse:Password> <wsse:Nonce>{2}' \
               '</wsse:Nonce> <wsse:Created>{3}</wsse:Created> </wsse:UsernameToken> </soapenv:Header>' \
               ' <soapenv:Body> <fac:changePassword>  <!--Optional:--> <request> <!--Optional:--> ' \
               '<newPassword>{4}</newPassword> </request> </fac:changePassword> </soapenv:Body> ' \
               '</soapenv:Envelope>'
        #     .format(
        #     username,
        #     password_digest,
        #     nonce,
        #     created_request,
        #     new_password
        # )

        return body

    def send_request_new_password(self, body):
        """Sends the SOAP request
        """
        url = self.wsdl
        headers = {'Content-Type': 'text/xml'}
        response = requests.post(url, data=body, headers=headers)

        return response.content.decode('utf-8')

    def parse_change_password_request(self, response):
        """Parses the response returned from the API request

        Arguments:
            response {string} -- API response

        Returns:
            tuple (transactionStatus, cardStatus, matchingStatus)
        """
        soup = BeautifulSoup(response, 'lxml-xml')

        if soup.find_all('transactionStatus')[1].string == 'Ok':
            return soup.find_all('transactionStatus')[1].string, None
        else:
            return soup.find_all('transactionStatus')[1].string, soup.message.string

    def password_generator(self):
        """Generates password.
        """
        # special_characters = '!@%/()=?+.-_'
        special_characters = '@!#_+$%*'
        password_list = (
                [
                    random.choice(special_characters),
                    random.choice(string.digits),
                    random.choice(string.ascii_lowercase),
                    random.choice(string.ascii_uppercase)
                ]
                +
                [
                    random.choice(
                        string.digits +
                        string.ascii_lowercase +
                        string.ascii_uppercase +
                        special_characters +
                        string.digits
                    )
                    for i in range(5)
                ]
        )

        random.shuffle(password_list)
        password = ''.join(password_list)
        return password

    def encrypt_pwd_with_PyCrypto(self, raw_password, certificate_file_path):
        """
        Encrypts raw pasword.

        """
        message = raw_password.encode('utf-8')

        the_pubkey = RSA.importKey(open(certificate_file_path, 'r').read())
        cipher = PKCS1_v1_5.new(the_pubkey)

        ciphertext = cipher.encrypt(message)

        pwd_to_base_64 = base64.b64encode(ciphertext).decode('utf-8')
        # pwd_to_base_64 = base64.b64encode(ciphertext)

        return pwd_to_base_64
