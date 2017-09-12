#!/usr/bin/python
# -*- coding:utf-8 -*-
###############################################
# File Name   : common.py
# Author      : Youner Liu
# Mail        : lewiyon@126.com
# Created Time: Sat 10 Jun 2017 08:18:07 PM CST
# Description : 
###############################################

import os
import sys
import subprocess
import logging
import logging.config

from yerrno import Yerr

import logging
from logging.handlers import RotatingFileHandler

Rthandler = RotatingFileHandler('/var/log/common.log', maxBytes=10*1024*1024, backupCount=5)
Rthandler.setLevel(logging.INFO)
formatter = logging.Formatter('[%(process)5d]%(filename)10s[L%(lineno)4d][%(levelname)7s]%(funcName)s:%(message)s')
Rthandler.setFormatter(formatter)
logging.getLogger('').addHandler(Rthandler)

class ComLib(object):

    @staticmethod
    def comCheckCall(command):
        try:
            logging.debug(command)
            subprocess.check_call(command, \
                                stdout=open('/dev/null','w'), \
                                stderr=subprocess.STDOUT, \
                                shell=True)
        except subprocess.CalledProcessError:
            logging.exception("%s failed" %(command))
            return Yerr.EFAILED
        return Yerr.ESUCCESS

    @staticmethod
    def getCmdOutput(command):
        try:
            logging.debug(command)
            output = subprocess.check_output(command, stderr=open('/dev/null','w'), shell=True)
        except:
            logging.exception("%s failed" %(command))
            return Yerr.EFAILED, ""
        return Yerr.ESUCCESS, output

    @staticmethod
    def open(file_name, mode):
        try:
            fd = open(file_name, os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except:
            logging.exception("Failed to read %s", file_name)
            return Yerr.EFAILED
        if fd < 0:
            return Yerr.EFAILED
        return fd
