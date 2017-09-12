#!/usr/bin/python
# -*- coding:utf-8 -*-
###############################################
# File Name   : nfspy.py
# Author      : Youner Liu
# Mail        : lewiyon@126.com
# Created Time: Sun 14 May 2017 02:27:16 PM CST
# Description : ip routing
###############################################
import os
import sys
import platform
import logging
import logging.config

from yerrno import Yerr
from common import ComLib
from marshal import version

import logging
from logging.handlers import RotatingFileHandler

Rthandler = RotatingFileHandler('/var/log/common.log', maxBytes=10*1024*1024, backupCount=5)
Rthandler.setLevel(logging.INFO)
formatter = logging.Formatter('[%(process)5d]%(filename)10s[L%(lineno)4d][%(levelname)7s]%(funcName)s:%(message)s')
Rthandler.setFormatter(formatter)
logging.getLogger('').addHandler(Rthandler)

class NfsPy(object):

	def __init__(self):
		pass

	@staticmethod
	def cmdNfsSvc(action):
		"""
			do action for nfs service
			"start": start nfs
			"stop" : stop nfs
			"restart": restart nfs
		"""
		pf = platform.dist()[0]
		if pf == "centos":
			if action == "start":
				ret = ComLib.comCheckCall("systemctl start nfs-server.service")
			elif action == "stop":
				ret = ComLib.comCheckCall("systemctl stop nfs-server.service")
			elif action == "restart":
				ret = ComLib.comCheckCall("systemctl restart nfs-server.service")
			else:
				logging.error("Not support this action %s" %(pf))
				ret = Yerr.ENOSUPPORT
		else:
			logging.error("Not support this platform %s" %(pf))
			ret = Yerr.ENOSUPPORT

		return ret

	@staticmethod
	def cmdReloadConfig():
		"""
			do action for nfs service
			"start": start nfs
			"stop" : stop nfs
			"restart": restart nfs
		"""
		pf = platform.dist()[0]
		if pf == "centos":
			ret = ComLib.comCheckCall("exportfs -ra")
		else:
			logging.error("Not support this platform %s" %(pf))
			ret = Yerr.ENOSUPPORT

		return ret

	@staticmethod
	def cmdCheckNfsRpc(version):
		"""
			check rpc for nfs
		"""
		pf = platform.dist()[0]
		if pf == "centos":
			cmd = "rpcinfo -u localhost nfs %s" %(version)
			ret = ComLib.comCheckCall(cmd)
		else:
			logging.error("Not support this platform %s" %(pf))
			ret = Yerr.ENOSUPPORT

		return ret

	@staticmethod
	def cmdNfsRpc(action):
		"""
			do rpc action for nfs service
			"start": start rpcbind
			"stop" : stop rpcbind
			"restart": restart rpcbind
		"""
		pf = platform.dist()[0]
		if pf == "centos":
			if action == "start":
				ret = ComLib.comCheckCall("systemctl start rpcbind.service")
			elif action == "stop":
				ret = ComLib.comCheckCall("systemctl stop rpcbind.service")
				if ret != Yerr.ESUCCESS:
					ComLib.comCheckCall("systemctl stop rpcbind.socket")
					ComLib.comCheckCall("systemctl stop rpcbind.service")
			elif action == "restart":
				ret = ComLib.comCheckCall("systemctl restart rpcbind.service")
			else:
				logging.error("Not support this action %s" %(pf))
				ret = Yerr.ENOSUPPORT
		else:
			logging.error("Not support this platform %s" %(pf))
			ret = Yerr.ENOSUPPORT

		return ret


