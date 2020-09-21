#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@File   : coding.py
@Author : DEADF1SH_CAT

Description:
    编解码模块
    目前涵盖base64,base32,unicode,utf-7,utf-8,url,hex,html,rot13,flask session,JSON Web Token等类型

Usage:
    建议配合flask+ajax使用
    
'''

import codecs
import sys
import base64
import urllib
import binascii
import HTMLParser
import cgi
import ast
import zlib
import re
import json
import argparse

from flask.sessions import SecureCookieSessionInterface
from itsdangerous import base64_decode
from itsdangerous import JSONWebSignatureSerializer
from itsdangerous import TimedJSONWebSignatureSerializer

class Codec():
    """
    编解码模块

    :param str string: 需进行编解码的字符串
    :param str codingtype: 编解码类型
    :param str actiontype: 操作类型(Encode/Decode)
    :param str key: 密钥(默认None)
    :param str algorithm: 算法(默认HS512)
    """
    def __init__(self, codingtype="1", actiontype="1", key=None, algorithm="HS256"):
        self.type = self.__switch(str(codingtype),str(actiontype))
        self.secret_key = key
        self.alg = algorithm
 
    def run(self, string):
        """
        处理用户输入，并执行相应函数
        """
        func_name = "%s_%s" % (self.type[0], self.type[1])
        coding = getattr(self,func_name)
        result = coding(str(string))
        if result:
            return result
        else:
            print("Coding ERROR! Please check the data!")

    @staticmethod
    def __switch(codingtype, actiontype):
        """
        将用户输入转换为函数名     
        :param str codingtype: 编解码的类型
        :param str actiontype: 操作类型(Encode/Decode)
        :return: tuple
        """
        typelist = {
            '1': 'base64',
            '2': 'base32',
            '3': 'unicode',
            '4': 'utf7',
            '5': 'utf8',
            '6': 'url',
            '7': 'hex',
            '8': 'html',
            '9': 'rot13',
            '10': 'flask',
            '11': 'jwt'
        }
        actionlist = {
            '1': 'encode',
            '2': 'decode'
        }
        try:
            return typelist[codingtype],actionlist[actiontype]
        except KeyError:
            raise KeyError("Action Error!")

    def base64_encode(self, string):
        """
        base64编码 
        """
        try:
            result = base64.b64encode(string)
            return result
        except UnicodeEncodeError:
            raise UnicodeEncodeError("Data can't be unicode_encoded!")

    def base64_decode(self, string):
        """
        base64解码
        """
        try:
            result = base64.b64decode(string)
            return result
        except TypeError:
            raise TypeError("Data Type Error!")

    def base32_encode(self, string):
        """
        base32编码
        """
        try:
            result = base64.b32encode(string)
            return result
        except UnicodeEncodeError:
            raise UnicodeEncodeError("Data can't be unicode_encoded!")

    def base32_decode(self, string):
        """
        base32解码 
        """
        try:
            result = base64.b32decode(string)
            return result
        except TypeError:
            raise TypeError("Data Type Error!")

    def unicode_encode(self, string):
        """
        unicode编码
        """
        try:
            result = codecs.unicode_escape_encode(string)[0]
            return result
        except UnicodeEncodeError:
            raise UnicodeEncodeError("Data can't be unicode_encoded!")
        
    def unicode_decode(self, string):
        """
        unicode解码
        """
        try:
            result = codecs.unicode_escape_decode(string)[0]
            return result
        except UnicodeDecodeError:
            raise UnicodeDecodeError("Data can't be unicode_decoded!")

    def utf7_encode(self, string):
        """
        utf-7编码 
        """
        try:
            result = codecs.utf_7_encode(string)[0]
            return result
        except UnicodeEncodeError:
            raise UnicodeEncodeError("Data can't be unicode_encoded!")

    def utf7_decode(self, string):
        """
        utf-7解码 
        """
        try:
            result = codecs.utf_7_decode(string)[0]
            return result
        except TypeError:
            raise TypeError("Data Type Error!")

    def utf8_encode(self, string):
        """
        utf-8编码 
        """
        try:
            result = repr(codecs.utf_8_encode(string)[0]).replace("'","")
            return result
        except UnicodeEncodeError:
            raise UnicodeEncodeError("Data can't be unicode_encoded!")

    def utf8_decode(self, string):
        """
        utf-8解码
        """
        try:
            result = codecs.utf_8_decode(string.decode('string-escape'))[0]
            return result
        except TypeError:
            raise TypeError("Data Type Error!")

    def url_encode(self, string):
        """
        url编码
        """
        try:
            result = urllib.quote(string)
            return result
        except KeyError:
            raise KeyError("Key Error!")
    
    def url_decode(self, string):
        """
        url解码
        """
        try:
            result = urllib.unquote(string)
            return result
        except KeyError:
            raise KeyError("Key Error!")

    def hex_encode(self, string):
        """
        hex编码
        """
        try:
            result = binascii.hexlify(string)
            return result
        except TypeError:
            raise TypeError("Data Type Error!")

    def hex_decode(self, string):
        """
        hex解码
        """
        try:
            result = binascii.unhexlify(string)
            return result
        except TypeError:
            raise TypeError("Data Type Error!")

    def html_encode(self, string):
        """
        html编码
        """
        try:
            result = cgi.escape(string)
            return result
        except TypeError:
            raise TypeError("Data Type Error!")

    def html_decode(self, string):
        """
        html解码 
        """
        try:
            result = HTMLParser.HTMLParser().unescape(string)
            return result
        except TypeError:
            raise TypeError("Data Type Error!")


    def rot13_encode(self, string):
        """
        ROT13编码 
        """
        try:
            result = ""
            for temp_str in string: 
                if re.match('[a-zA-Z]+',temp_str):
                    result += temp_str.encode('rot13')
                else:
                    result += temp_str

            return result
        except TypeError:
            raise TypeError("Data Type Error! Letters Only")

    def rot13_decode(self, string):
        """
        ROT13解码 
        """
        try:
            result = ""
            #绕过非字母字符的处理
            for temp_str in string: 
                if re.match('[a-zA-Z]+',temp_str):
                    result += temp_str.encode('rot13')
                else:
                    result += temp_str

            return result
        except TypeError:
            raise TypeError("Data Type Error! Letters Only")

    def flask_encode(self, string):
        """
        flask session编码

        Description：
            通过get_signing_serializer获取签名后的序列化对象
            注意 传入的对象应为JSON字符串
                 签名必须带有secret_key

        Example:
            >>>Codec(key="hello").flask_encode('{"name":"DEADF1SH_CAT","module":"codec"}')
            eyJtb2R1bGUiOnsiIGIiOiJZMjlrWldNPSJ9LCJuYW1lIjp7IiBiIjoiUkVWQlJFWXhVMGhmUTBGVSJ9fQ.X2hcRA.fefBBFWPW96SiC8rhAr6bgLxcHo
        """
        try:
            session_cookie = dict(ast.literal_eval(string))
            if(self.secret_key == None):
                self.secret_key = ""
            sign = SecureCookieSessionInterface()
            serializer = sign.get_signing_serializer(self)
            result = serializer.dumps(session_cookie)

            return result
        except AttributeError:
            raise AttributeError("Secret_key can't be NULL!")
        except ValueError:
            raise ValueError("Data not JSON string!")

    def flask_decode(self, string):
        """
        flask session解码

        Description:
            通过字符串头部是否包含“.”验证是否数据经过压缩，若有，则解压缩
            通过签名对象，直接解码出数据
            注意 不设置密钥时只返回解压缩后加密的data

        Example:
            >>>Code(key="hello").flask_decode('eyJtb2R1bGUiOnsiIGIiOiJZMjlrWldNPSJ9LCJuYW1lIjp7IiBiIjoiUkVWQlJFWXhVMGhmUTBGVSJ9fQ.X2hcdg.z_SIMDwrUNk0OEedqvrbEEF_fGI')
            {"name": "DEADF1SH_CAT", "module": "codec"}
            >>>Codec(key="").flask_decode('eyJtb2R1bGUiOnsiIGIiOiJZMjlrWldNPSJ9LCJzYW5nZm9yIjp7IiBiIjoiVTFKSiJ9fQ.Xfc4bg._sHWpX1GPy0q7qHpJIzqzLDM0TM')
            {"module":{" b":"Y29kZWM="},"name":{" b":"REVBREYxU0hfQ0FU"}}
        """
        try:
            session_cookie_value = string
            if(self.secret_key == None or self.secret_key == ""):
                compressed = False
                payload = session_cookie_value

                #判断payload是否经过压缩    
                if payload.startswith('.'):
                    compressed = True
                    payload = payload[1:]

                data = payload.split(".")[0]
                
                #解压payload数据
                data = base64_decode(data)
                if compressed:
                    data = zlib.decompress(data)

                return data
            else:
                #验证签名
                sign = SecureCookieSessionInterface()
                serializer = sign.get_signing_serializer(self)
                result = json.dumps(serializer.loads(session_cookie_value))

                return result
        except AttributeError:
            raise AttributeError("Secret_key can't be NULL!")

    def jwt_encode(self, string):
        """
        JSON Web Token编码

        Description：
            通过itsdangerous模块内部的JSONWebSignatureSerializer对数据进行序列化,通过序列化对象dumps方法输出编码后结果
            注意 默认算法为HS512，目前仅支持HS512、HS384、HS256算法

        Example:
            >>>Codec(key="hello").jwt_encode('{"name":"DEADF1SH_CAT","module":"codec"}')
            eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiREVBREYxU0hfQ0FUIiwibW9kdWxlIjoiY29kZWMifQ.2GYkiUswkUdNFuA74lW9NKWVwX8KDhLEWf_0L-rSmH0 
        """
        try:
            jwt = dict(ast.literal_eval(string))
            if(self.secret_key == None):
                self.secret_key = ""
            if(self.alg == None):
                sign = JSONWebSignatureSerializer(self.secret_key)
            else:
                sign = JSONWebSignatureSerializer(self.secret_key, algorithm_name=self.alg)
            result = sign.dumps(jwt, header_fields={"typ":"JWT"})

            return result
        except TypeError:
            raise TypeError("Secret_key can't be None!")

    def jwt_decode(self, string):
        """
        JSON Web Token解码

        Description
            通过itsdangerous模块内部的JSONWebSignatureSerializer对数据进行序列化,通过序列化对象loads方法提取反序列化结果
            注意 默认算法为HS512，目前仅支持HS512、HS384、HS256算法

        Example:
            >>>Codec(key="hello").jwt_decode('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiREVBREYxU0hfQ0FUIiwibW9kdWxlIjoiY29kZWMifQ.2GYkiUswkUdNFuA74lW9NKWVwX8KDhLEWf_0L-rSmH0')
            {"alg": "HS256", "typ": "JWT"}
            {"name": "DEADF1SH_CAT", "module": "codec"}
        """
        try:
            jwt = string
            if(self.secret_key == None):
                self.secret_key = ""
            if(self.alg == None):
                sign = JSONWebSignatureSerializer(self.secret_key)
            else:
                #自动识别加密算法
                header = json.loads(base64.b64decode(jwt.split('.')[0]))
                self.alg = header['alg']
                sign = JSONWebSignatureSerializer(self.secret_key, algorithm_name=self.alg)
            #将数据分块输出，顺序为header、payload
            result = json.dumps(sign.loads(jwt,return_header=True)[1]) + "\n" + json.dumps(sign.loads(jwt,return_header=True)[0])

            return result
        except TypeError:
            raise TypeError("Secret_key can't be None!")

if __name__ == "__main__":
    reload(sys)
    sys.setdefaultencoding('utf8')
    
    if len(sys.argv) == 1:
        sys.argv.append('-h')
        print(
            """
Type:
'1': 'base64',
'2': 'base32',
'3': 'unicode',
'4': 'utf7',
'5': 'utf8',
'6': 'url',
'7': 'hex',
'8': 'html',
'9': 'rot13',
'10': 'flask',
'11': 'jwt'
Action:
'1': 'encode',
'2': 'decode'
            """
        )

    parser = argparse.ArgumentParser(description='Codec',add_help=True)
    parser.add_argument('-s','--str',default=None,help='待编/解码的字符串',type=str)
    parser.add_argument('-t','--type',default="1",help='编解码类型(默认Base64)',type=str,choices=("1","2","3","4","5","6","7","8","9","10","11"))
    parser.add_argument('-a','--action',default="1",help='操作类型(Encode/Decode)',type=str,choices=("1","2"))
    parser.add_argument('-k','--key',default=None,help='附加密钥(默认None)--适用于Flaks session与JWT',type=str)
    parser.add_argument('-c','--crypto',default="HS512",help='加密算法(默认HS512)--适用于JWT',type=str)
    args = parser.parse_args()

    if args.str and args.type and args.action:
        if args.type == "10":
            print(Codec(args.type,args.action,args.key).run(args.str))
        elif args.type == "11":
            print(args.key,args.crypto)
            print(Codec(args.type,args.action,key=args.key,algorithm=args.crypto).run(args.str))      
        else:      
            print(Codec(args.type,args.action).run(args.str))
    else:
        print("Args Error!")
        exit()