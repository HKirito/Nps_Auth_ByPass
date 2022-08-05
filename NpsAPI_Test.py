import time
from hashlib import md5
import requests
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import hashlib
from crcmod import *
from binascii import *
import binascii
from Crypto.Cipher import AES
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import json

'''
AES/CBC/PKCS7Padding 加密解密
环境需求:
pip3 install pycryptodome
'''


class PrpCrypt(object):

    def __init__(self, key='1234567812345678'):
        self.key = key.encode('utf-8')
        self.mode = AES.MODE_CBC
        self.iv = b'1234567812345678'
        # block_size 128位

    # 加密函数，如果text不足16位就用空格补足为16位，
    # 如果大于16但是不是16的倍数，那就补足为16的倍数。
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        text = text.encode('utf-8')

        # 这里密钥key 长度必须为16（AES-128）,24（AES-192）,或者32 （AES-256）Bytes 长度
        # 目前AES-128 足够目前使用

        text = self.pkcs7_padding(text)

        self.ciphertext = cryptor.encrypt(text)

        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext).decode().upper()

    @staticmethod
    def pkcs7_padding(data):
        if not isinstance(data, bytes):
            data = data.encode()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_data = padder.update(data) + padder.finalize()

        return padded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data)

        try:
            uppadded_data = data + unpadder.finalize()
        except ValueError:
            raise Exception('无效的加密信息!')
        else:
            return uppadded_data

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        #  偏移量'iv'
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(a2b_hex(text))
        # return plain_text.rstrip('\0')
        return bytes.decode(plain_text).rstrip("\x01"). \
            rstrip("\x02").rstrip("\x03").rstrip("\x04").rstrip("\x05"). \
            rstrip("\x06").rstrip("\x07").rstrip("\x08").rstrip("\x09"). \
            rstrip("\x0a").rstrip("\x0b").rstrip("\x0c").rstrip("\x0d"). \
            rstrip("\x0e").rstrip("\x0f").rstrip("\x10")

    def dict_json(self, d):
        '''python字典转json字符串, 去掉一些空格'''
        j = json.dumps(d).replace('": ', '":').replace(', "', ',"').replace(", {", ",{")
        return j





def Get_Time(base_url):
    getime_url = base_url + '/auth/gettime'
    print('--------' + getime_url + '----------')
    time_req = requests.post(url=getime_url, data={})
    time_json = time_req.json()
    print(time_req.json())
    print(time_json['time'])
    return time_json


def Get_Authkey(base_url):
    getAuthkey_url = base_url + '/auth/getauthkey'
    print('========' + getAuthkey_url + '===========')
    authkey_req = requests.post(url=getAuthkey_url, data={})
    print(authkey_req.text)
    print(authkey_req.json()['crypt_auth_key'])
    return authkey_req.json()


def Post_Server(url, auth_key, time):
    print('auth_key: ' + auth_key)
    auth_key2 = hashlib.md5(auth_key.encode(encoding='utf-8')).hexdigest()
    print('md5-2: ' + auth_key2)
    post_time = str(time)
    data2 = 'auth_key=' + auth_key2 + '&timestamp=' + post_time + '&start=0&limit=10'
    print(data2)
    print('-------------------------------------')
    session = requests.session()
    session.post(url=url, data=data2)
    cookie = session.cookies
    print('Cookie: beegosessionID='+cookie['beegosessionID']+';\n\n'+data2)


if __name__ == '__main__':
    base_url = 'http://172.16.25.9:8080'
    times = Get_Time(base_url)['time']+20
    Crypt_AuthKey = Get_Authkey(base_url)['crypt_auth_key']
    # 硬编码auth_key直接伪造凭据
    auth_crypt_key = '1234567812345678'
    print('------------Start Decrypt -----------')
    print('key and iv: ' + auth_crypt_key)
    pc = PrpCrypt(auth_crypt_key)  # 初始化密钥
    auth_key = pc.decrypt(Crypt_AuthKey)
    print('Result: ' + auth_key)
    api_url = base_url + '/client/list'
    auth_key = auth_key + str(times)
    Post_Server(url=api_url, auth_key=auth_key, time=times)
