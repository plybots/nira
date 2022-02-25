# -*- coding: utf-8 -*-

import base64
import json
import os
import random
import sqlite3
import string
from datetime import datetime
from hashlib import sha1
from sqlite3 import Error

import pytz
import requests
import xmltodict
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from bs4 import BeautifulSoup
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

    def create_auth_table(self):
        sql = "CREATE TABLE IF NOT EXISTS auth (id integer PRIMARY KEY, username text NOT NULL, password text);"
        conn = self.get_conn()
        state = False
        if conn:
            state = self.create_table(conn, sql)
            conn.close()
        return state

    def set_auth(self, username, password):
        if self.create_auth_table():
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

    def get_auth(self):
        """
        Query all rows in the tasks table
        :param conn: the Connection object
        :return:
        """
        conn = self.get_conn()
        if conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM auth")
            rows = cur.fetchone()
            return {'username': rows['username'], 'password': rows['password']}
        return None

    def get_conn(self):
        sqlite_db = r"/opt/zato/3.2.0/code/zato_sqlite.db"

        """ create a database connection to a SQLite database """
        try:
            return sqlite3.connect(sqlite_db)
        except Error as e:
            return None

    def handle(self):

        with self.outgoing.soap.get('NIRA').conn.client() as client:
            method = self.request.input.method
            if method == 'setPassword':
                cre = self.request.payload
                self.set_auth(
                    username=cre['username'],
                    password=cre['password']
                )
                self.response.payload = {
                    'data': self.get_auth()
                }
            elif method == 'getPassword':
                self.response.payload = {
                    'data': self.get_auth()
                }
            else:
                url = client.wsdl.url
                auth = self.get_auth()
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
                try:
                    del o['transactionStatus']
                except Exception:
                    pass
                self.response.payload = {
                    'data': json.loads(json.dumps(o))
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