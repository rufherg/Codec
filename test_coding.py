#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@File   : test_coding.py
@Author : DEADF1SH_CAT
'''

import logging
import coding

string = '{"name":"DEADF1SH_CAT","module":"codec"}'

def test_flask():
    encode = coding.Codec(key="hello").flask_encode(string)
    decode = coding.Codec(key="hello").flask_decode(encode)
    logging.info("flask_encode:  %s\n>>>%s",string,encode)
    logging.info("flask_decode:  %s\n>>>%s",encode,decode)

def test_jwt():
    encode = coding.Codec(key="hello",algorithm="HS384").jwt_encode(string)
    decode = coding.Codec(key="hello").jwt_decode(encode)
    logging.info("jwt_encode:  %s\n>>>%s",string,encode)
    logging.info("jwt_decode:  %s\n>>>%s",encode,decode)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,format='%(asctime)s [%(pathname)s/%(filename)s:%(lineno)d][%(levelname)s]:%(message)s',
                        datefmt='%Y-%m-%d %a %H:%M:%S')
    test_flask()
    test_jwt()