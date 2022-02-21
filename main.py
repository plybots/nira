# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import base64
import datetime
import os
from hashlib import sha1
from math import floor
from pytz import timezone


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    digest()  # Press Ctrl+F8 to toggle the breakpoint.


def gen_nonce(length):
    """ Generates a random string of bytes, base64 encoded """
    if length < 1:
        return ''
    string = base64.b64encode(os.urandom(length), altchars=b'-_')
    b64len = 4 * floor(length)
    if length % 3 == 1:
        b64len += 2
    elif length % 3 == 2:
        b64len += 3
    return string[0:b64len].decode()

def digest():
    # Password_Digest = Base64(SHA-1(Nonce + Created + SHA1(Password)))
    password = sha1(b'57HK!df')
    nonce = gen_nonce(16).encode("utf-8")
    today = datetime.datetime.now(tz=timezone('Africa/Kampala'))
    fmt = '%Y-%m-%dT%H:%M:%S.%f'
    time = f"{today.strftime(fmt)[:-3]}+03:00"
    time_pass = f"{today.strftime(fmt)[:-3]}+0300".encode("utf-8")
    sh1 = sha1(f'{nonce}{time_pass}{password}'.encode("utf-8"))
    digest = base64.b64encode(sh1.digest())
    print(f'time: {time}, nonce: {nonce}, digest: {digest}')


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
