#!/usr/bin/python
# -*- coding:utf-8 -*-
###############################################
# File Name   : ippy.py
# Author      : Youner Liu
# Mail        : lewiyon@126.com
# Created Time: Sun 14 May 2017 02:27:16 PM CST
# Description : ip routing
###############################################
import os
import sys
import stat
import re
import socket
import subprocess
import logging
import logging.config

import logging
from logging.handlers import RotatingFileHandler

from yerrno import Yerr
from yheader import Ycon
from common import ComLib


Rthandler = RotatingFileHandler('/var/log/ippy.log', maxBytes=10*1024*1024, backupCount=5)
Rthandler.setLevel(logging.INFO)
formatter = logging.Formatter('[%(process)5d]%(filename)10s[L%(lineno)4d][%(levelname)7s]%(funcName)s:%(message)s')
Rthandler.setFormatter(formatter)
logging.getLogger('').addHandler(Rthandler)


class IpLib(object):

	MAX_IPV4_ADDRESS = 0xffffffff
	TABLE_ID_PREFIX				= "ippy_"
	PER_IP_ROUTING_RULE_PREF	= 10000
	PER_IP_ROUTING_TABLE_ID_LOW	= 10
	PER_IP_ROUTING_TABLE_ID_HIGH	= 250

	def __init__(self):
		if not os.path.isdir(Ycon.YNAS_RUNDIR):
			os.mkdir(Ycon.YNAS_RUNDIR)


	def checkIpv4Valid(self, ip):
		"""
			check ipv4 address valid
			1. 0 =< seg =< 255
		"""
		if len(ip) != len(ip.replace(" ", "")):
			return False
		segs = ip.split(".")
		if len(segs) != 4:
			return False
		for seg in segs:
			try:
				i_seg = int(seg)
			except:
				return False
			if i_seg < 0 or i_seg > 255:
				return False

		return True

	def ipv4AddrToNet(self, ip):
		"""
			This prints the config for an IP, which is either relevant entries
			from the config file or, if set to the magic link local value, some
			link local routing config for the IP.
			ip looks like "192.169.34.211/24"
		"""
		try:
			addr, maskbit = ip.split("/")
		except:
			addr = ip
			maskbit = "32"
		segs = addr.split(".")
		addr_ul = 0
		for seg in segs:
			i_seg = int(seg)
			addr_ul = (addr_ul << 8) + i_seg

		mask = IpLib.MAX_IPV4_ADDRESS << (32 - int(maskbit))
		net_ul = addr_ul & mask
		net_addr = ""
		count = 0
		while count < 4:
			if not net_addr:
				net_addr = str((net_ul & 255))
			else:
				net_addr = str((net_ul & 255)) + "." + net_addr
			net_ul = net_ul >> 8
			count = count + 1
		return net_addr + "/" + maskbit

	def ipHasConfiguration(self, ip):
		try:
			addr, maskbit = ip.split("/")
			if not maskbit.isdigit():
				return False
		except:
			return False
		return True

	def checkIfaceStatus(self, iface):
		"""
			check iface status, False - Down; True - UP
		"""
		cmmd = "ip link show %s | grep 'state UP'" %(iface)
		ret = ComLib.comCheckCall(cmmd)
		if ret != Yerr.ESUCCESS:
			return False
		else:
			return True

	def bringUpIface(self, iface):
		"""
			bring up iface
		"""
		cmmd = "ip link set %s up" %(iface)
		return ComLib.comCheckCall(cmmd)

	def checkIpExists(self, ip, iface):
		"""
			whether ip is on iface;
			if yes return True, else return False
		"""
		if not ip or not iface:
			return False

		cmmd = "ip addr list dev '%s' | grep -Fq 'inet %s '" %(iface, ip)
		ret = ComLib.comCheckCall(cmmd)
		if ret != Yerr.ESUCCESS:
			return False
		else:
			return True

	def addIpToIface(self, ip, iface):
		"""
			add ip to iface
			ip looks like "192.169.34.128/24"
		"""
		if not ip or not self.ipHasConfiguration(ip) or not iface:
			logging.error("ip or iface is invalid")
			return Yerr.EINVALID

		if self.checkIpExists(ip, iface):
			logging.info("%s has been on dev %s" %(ip, iface))
			return Yerr.ESUCCESS

		lockfile = Ycon.YNAS_RUNDIR + "/ippy_iface_%s.flock" %(iface)
		try:
			fd = os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_RDWR)
		except:
			logging.error("race failed for %s" %(iface))
			return Yerr.EFAILED

		# Ensure interface is up
		ret = self.bringUpIface(iface)
		if ret != Yerr.ESUCCESS:
			logging.error("failed to bringup interface %s" %(iface))
		else:
			# add ip address to interface
			cmmd = "ip addr add %s brd + dev %s" %(ip, iface)
			ret = ComLib.comCheckCall(cmmd)
			if ret != Yerr.ESUCCESS:
				logging.error("Failed to add %s on dev %s" %(ip, iface))

		os.close(fd)
		os.unlink(lockfile)
		return ret

	def delIpFromIface(self, ip, iface):
		"""
			delete ip from iface
			ip looks like "192.169.34.128/24"
		"""
		if not ip or not self.ipHasConfiguration(ip) or not iface:
			logging.error("ip or iface is invalid")
			return Yerr.EINVALID

		if not self.checkIpExists(ip, iface):
			logging.info("Could not find %s on dev %s" %(ip, iface))
			return Yerr.ESUCCESS

		lockfile = Ycon.YNAS_RUNDIR + "/ippy_iface_%s.flock" %(iface)
		try:
			fd = os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_RDWR)
		except:
			logging.error("Race failed for %s" %(iface))
			return Yerr.EFAILED

		"""
		"ip addr del" will delete all secondary IPs if this is the
		primary.  To work around this _very_ annoying behaviour we
		have to keep a record of the secondaries and re-add them
		afterwards.  Yuck!
		"""
		secondaries=[]
		cmmd = "ip addr list dev '%s' primary | grep -Fq 'inet %s '" %(iface, ip)
		ret = ComLib.comCheckCall(cmmd)
		if ret != Yerr.ESUCCESS:
			# not primary
			logging.debug("Check secondary addr for %s" %(iface))
			cmmd = "ip addr list dev '%s' secondary | grep 'inet '" %(iface)
			ret, output = ComLib.getCmdOutput(cmmd)
			if ret != Yerr.ESUCCESS:
				logging.error("Failed to list secondary addr for %s" %(iface))
			elif not output:
				logging.error("No secondary addr for %s" %(iface))
			else:			
				lines = output.split("\n")
				for line in lines:
					if not line:
						continue
					try:
						m = re.match("\s+(\S+)\s+(\S+)", line)
						if m.group(1) and m.group(2):
							inet = m.group(1)
							snd_ip = m.group(2)
						else :
							continue					
					except:
						continue
					if inet == "inet":
						secondaries.append(snd_ip)
		else:
			logging.debug("This is as primary addr for %s" %(iface))

		local_rc = 0
		cmmd = "ip addr del '%s' dev '%s'" %(ip, iface)
		ret = ComLib.comCheckCall(cmmd)
		if ret != Yerr.ESUCCESS:
			logging.error("Failed to del %s on dev %s" %(ip, iface))
			local_rc = 1

		for snd_ip in secondaries:
			if snd_ip == ip:
				continue
			cmmd = "ip addr list dev '%s' secondary | grep -Fq 'inet %s'" %(iface, snd_ip)
			ret = ComLib.comCheckCall(cmmd)
			if ret == Yerr.ESUCCESS:
				logging.info("Kept secondary %s on dev %s" %(snd_ip, iface))
			else:
				logging.info("Re-adding secondary address %s to dev %s" %(snd_ip, iface))
				cmmd = "ip addr add %s brd + dev %s" %(snd_ip, iface)
				ret = ComLib.comCheckCall(cmmd)
				if ret != Yerr.ESUCCESS:
					logging.error("Failed to re-add address %s to dev %s" %(snd_ip, iface))
					local_rc = 1
			# end if

		os.close(fd)
		os.unlink(lockfile)
		if local_rc:
			ret = Yerr.EFAILED
		return ret

	def cleanUpTableIds(self):
		"""
			Clean up all the table ids that we might own.
		"""
		file_name = "/etc/iproute2/rt_tables"
		if not os.path.isfile(file_name):
			logging.info("%s not exist." %(file_name))
			return Yerr.ESUCCESS

		try:
			fp = ComLib.open(file_name, "r+")
		except:
			logging.error("Failed to open %s" %(file_name))
			return Yerr.EFAILED

		new_lines = []
		lines = fp.readlines()
		for line in lines :
			if line and line[0] != "#" :
				m = re.search(IpLib.TABLE_ID_PREFIX, line)
				if m:
					continue
			new_lines.append(line)

		fp.seek(0, 0)
		fp.truncate()
		fp.writelines(new_lines)
		fp.flush()
		fp.close()
		return Yerr.ESUCCESS

	def eraseTableIdForIp(self, ip):
		"""
			Clean up all the table ids that we might own.
		"""
		if not ip:
			logging.error("ip or iface is invalid")
			return Yerr.EINVALID

		file_name = "/etc/iproute2/rt_tables"
		if not os.path.isfile(file_name):
			logging.info("%s not exist." %(file_name))
			return Yerr.ESUCCESS

		try:
			fp = open(file_name, "r+")
		except:
			logging.error("Failed to open %s" %(file_name))
			return Yerr.EFAILED

		keywords = IpLib.TABLE_ID_PREFIX + ip
		new_lines = []
		lines = fp.readlines()
		for line in lines :
			if line and line[0] != "#" :
				m = re.search(keywords, line)
				if m:
					continue
			new_lines.append(line)

		fp.seek(0, 0)
		fp.truncate()
		fp.writelines(new_lines)
		fp.flush()
		fp.close()
		return Yerr.ESUCCESS

	def ensureTableIdForIp(self, ip):
		"""
			Setup a table id to use for the given IP.  We don't need to know it,
			it just needs to exist in /etc/iproute2/rt_tables.  Fail if no free
			table id could be found in the configured range.
		"""
		if not ip:
			logging.error("ip or iface is invalid")
			return Yerr.EINVALID

		route_dir = "/etc/iproute2"
		if not os.path.isdir(route_dir):
			os.mkdir(route_dir)

		file_name = route_dir + "/rt_tables"
		try:
			fp = open(file_name, "r+")
		except:
			logging.error("Failed to open %s" %(file_name))
			return Yerr.EFAILED

		new_label = IpLib.TABLE_ID_PREFIX + ip
		id_array = []
		lines = fp.readlines()
		for line in lines :
			# blank line
			if not lines:
				continue
			# Skip comments
			if line[0] == "#":
				continue
			try:
				m = re.match("(\S+)\s+(\S+)", line)
				if m.group(1) and m.group(2):
					t_id = int(m.group(1))
					t_label = m.group(2)
				else :
					continue					
			except:
				continue

			# Found existing: done
			if t_label == new_label:
				logging.info("%s has been in %s" %(new_label, file_name))
				fp.close()
				return Yerr.ESUCCESS
			if IpLib.PER_IP_ROUTING_TABLE_ID_LOW <= t_id and t_id <= IpLib.PER_IP_ROUTING_TABLE_ID_HIGH:
				id_array.append(t_id)

		new_id = IpLib.PER_IP_ROUTING_TABLE_ID_LOW
		while new_id <= IpLib.PER_IP_ROUTING_TABLE_ID_HIGH:
			if new_id not in id_array:
				break
			else:
				new_id = new_id + 1

		# If the new table id is legal then add it to the file and print it.
		if new_id <= IpLib.PER_IP_ROUTING_TABLE_ID_HIGH:
			new_line = "%d %s\n" %(new_id, new_label)
			fp.seek(0, 2) # file end
			fp.write(new_line)
			ret = Yerr.ESUCCESS
		else:
			logging.error("out of table ids in range %d-%d " 
				%(IpLib.PER_IP_ROUTING_TABLE_ID_LOW, IpLib.PER_IP_ROUTING_TABLE_ID_HIGH))
			ret = Yerr.EFAILED

		fp.flush()
		fp.close()
		return ret

	def delRoutingForIp(self, ip):
		"""
			delete route for ip
		"""
		pref = IpLib.PER_IP_ROUTING_RULE_PREF
		table_id = IpLib.TABLE_ID_PREFIX + ip
		cmmd = "ip rule del from %s pref %s table %s" %(ip, pref, table_id)
		if ComLib.comCheckCall(cmmd) != Yerr.ESUCCESS:
			logging.error("[Error]failed to del rule for %s" %(ip))
			#ret_rule = Yerr.EFAILED

		# This should never usually fail, so don't redirect output.
		# However, it can fail when deleting a rogue IP, since there will
		# be no routes for that IP.  In this case it should only fail when
		# the rule deletion above has already failed because the table id
		# is invalid.  Therefore, go to a little bit of trouble to indent
		# the failure message so that it is associated with the above
		# warning message and doesn't look too nasty.
		# ip route flush table $_table_id 2>&1 | sed -e 's@^.@  &@'
		cmmd = "ip route flush table %s" %(table_id)
		if ComLib.comCheckCall(cmmd) != Yerr.ESUCCESS:
			logging.error("Failed to flush rule for deleting %s" %(table_id))
			#ret_route = Yerr.EFAILED

		if self.eraseTableIdForIp(ip) != Yerr.ESUCCESS:
			logging.error("Failed to erase table id for %s" %(ip))
			return Yerr.EFAILED

		return Yerr.ESUCCESS

	def addRoutingForIp(self, ip, iface, gateway=None):
		"""
			add route for ip
		"""
		if self.ensureTableIdForIp(ip) != Yerr.ESUCCESS:
			return Yerr.EFAILED

		#if self.delRoutingForIp(ip):
		#	print("[Error]failed delRoutingForIp for %s " %(ip))

		pref = IpLib.PER_IP_ROUTING_RULE_PREF
		table_id = IpLib.TABLE_ID_PREFIX + ip
		cmmd = "ip rule add from %s pref %s table %s" %(ip, pref, table_id)
		if ComLib.comCheckCall(cmmd) != Yerr.ESUCCESS:
			logging.error("Failed to add rule for %s" %(ip))
			return Yerr.EFAILED

		net_wlan = self.ipv4AddrToNet(ip)
		# Add routes to table for any lines matching the IP.
		if gateway:
			route = "%s +via %s dev %s table %s" %(net_wlan, gateway, iface, table_id)
		else:
			route = "%s dev %s table %s" %(net_wlan, iface, table_id)
		cmmd = "ip route add %s" %(route)
		if ComLib.comCheckCall(cmmd) != Yerr.ESUCCESS:
			logging.error("Failed to add route: %s" %(route))
			cmmd = "ip rule del from %s pref %s table %s" %(ip, pref, table_id)
			ComLib.comCheckCall(cmmd)
			return Yerr.EFAILED
		return Yerr.ESUCCESS

	def flushRulesAndRoutes(self):
		"""
			flush rules and routes
		"""
		cmmd = "ip rule show"
		ret, output = ComLib.getCmdOutput(cmmd)
		if ret != Yerr.ESUCCESS:
			print("[Error] failed to show ip rules")
			return ret
		if not output:
			print("[Error] No ip rules")
			return ret
		lines = output.split("\n")
		for line in lines:
			if not line:
				continue
			try:
				m = re.match("(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", line)
				if not m.group(1) or not m.group(2) \
					or not m.group(3) or not m.group(4) or not m.group(5):
					continue
			except:
				continue

			# Only remove rules that match our priority/preference.
			tb_id_str = "%s:" %(m.group(1))
			if tb_id_str != IpLib.PER_IP_ROUTING_RULE_PREF:
				continue

			ip = m.group(3)
			tb_name = m.group(3)
			print('Removing ip rule for public address %s for routing table %s' %(ip, tb_name))
			cmmd = "ip rule del from %s table %s pref %s" %(ip, tb_name, IpLib.PER_IP_ROUTING_RULE_PREF)
			if ComLib.comCheckCall(cmmd) != Yerr.ESUCCESS:
				print("[Error]failed to delete rule for %s" %(ip))
				ret = Yerr.EFAILED
			cmmd = "ip route flush table %s" %(tb_name)
			if ComLib.comCheckCall(cmmd) != Yerr.ESUCCESS:
				print("[Error]failed to flush table %s" %(tb_name))
				ret = Yerr.EFAILED

		return ret

	def updateArpCache(self, dest_ip, iface, src_ip=None):
		"""
			update arp cache
		"""
		if not dest_ip or not iface:
			return Yerr.EINVALID

		cmmd = "arping -c 1 -I %s" %(iface)
		if src_ip != None:
			cmmd = cmmd + " -s %s" %(src_ip)
		cmmd = cmmd + "  %s" %(dest_ip)

		count = 1
		ret = ComLib.comCheckCall(cmmd)
		while (count < 2) and (ret != Yerr.ESUCCESS):
			count = count + 1
			ret = ComLib.comCheckCall(cmmd)

		return ret

	def getIfaceFromIp(self, ip):
		"""
		"""
		iface = ""
		cmmd = "ip addr show| grep 'inet %s '" %(ip)
		ret, output = ComLib.getCmdOutput(cmmd)
		if ret != Yerr.ESUCCESS or not output:
			logging.error("Failed to find %s in addr list" %(ip))
			return ret, iface
		output = output.replace("\n", "")
		words = output.split(" ")
		index = len(words) - 1
		while (not words[index]) and index >= 0:
			index = index - 1

		if index >= 0:
			iface = words[index]

		return ret, iface
			
	def getPublicIps(self):
		"""
			get public ips via this module
		"""
		ips = []
		file_name = "/etc/iproute2/rt_tables"
		try:
			fp = open(file_name, "r+")
		except:
			print("[Error]open %s failed" %(file_name))
			return ips

		keywords = IpLib.TABLE_ID_PREFIX
		new_lines = []
		lines = fp.readlines()
		for line in lines :
			if line and line[0] != "#" :
				m = re.search(keywords, line)
				if m:
					new_lines.append(line)
			continue
		fp.close()

		for line in new_lines:
			try:
				m = re.match("(\S+)\s+(\S+)", line)
				if m.group(1) and m.group(2):
					arr = m.group(2).split("_")
					ips.append(arr[1])
			except:
				continue

		return ips

	def takePublicIP(self, ip, iface, gateway=None):
		"""
			update public ip address
		"""
		if not ip or not self.ipHasConfiguration(ip) or not iface:
			logging.error("IP is invalid")
			return Yerr.EINVALID

		if self.checkIpExists(ip, iface):
			logging.info("%s has been on dev %s" %(ip, iface))
			return Yerr.ESUCCESS

		# add ip address
		ret = self.addIpToIface(ip, iface)
		if ret != Yerr.ESUCCESS:
			logging.error("Failed to add ip %s to iface %s" %(ip, iface))
		else:
			ret = self.addRoutingForIp(ip, iface, gateway)
			if ret != Yerr.ESUCCESS:
				logging.error("Failed to add route for %s" %(ip))

		return ret

	def releasePublicIP(self, ip, iface, gw=None):
		"""
			release publiclip address
		"""
		if not ip or not self.ipHasConfiguration(ip) or not iface:
			logging.error("IP is invalid")
			return Yerr.EINVALID

		if not self.checkIpExists(ip, iface):
			logging.error("Failed to find %s on dev %s" %(ip, iface))
			ret = Yerr.ESUCCESS
		else:
			# delete ip address
			ret = self.delIpFromIface(ip, iface)
			if ret != Yerr.ESUCCESS:
				logging.error("Failed to delete ip for %s from %s" %(ip, iface))

		# delete route
		if ret == Yerr.ESUCCESS:
			ret = self.delRoutingForIp(ip)
			if ret != Yerr.ESUCCESS:
				logging.error("Failed to delete route for %s" %(ip))

		return ret

	def updatePublicIps(self, new_ips, iface):
		"""
			release all public addresses via ippy
		"""
		last_ret = Yerr.ESUCCESS
		old_ips = self.getPublicIps()

		for ip in old_ips:
			if ip in new_ips:
				continue
			# not belong to new_ips
			ret = self.releasePublicIP(ip, iface)
			if ret != Yerr.ESUCCESS:
				last_ret = ret
			else:
				continue

		for ip in new_ips:
			if ip in old_ips:
				continue
			# new ip in new_ips has not been set
			ret = self.takePublicIP(ip, iface)
			if ret != Yerr.ESUCCESS:
				last_ret = ret
			else:
				continue

		return last_ret

	def releaseAllPublicIps(self):
		"""
			release all public addresses via ippy
		"""
		last_ret = Yerr.ESUCCESS
		ips = self.getPublicIps()
		if not ips:
			print("No ips here")
			return last_ret
		
		for ip in ips:
			ret, iface = self.getIfaceFromIp(ip)
			if ret != Yerr.ESUCCESS:
				last_ret = ret
			elif self.releasePublicIP(ip, iface) != Yerr.ESUCCESS:
				print("[Error]releasePublicIP %s failed" %(ip))
				ret = Yerr.EFAILED
			else:
				continue

		return last_ret

	def checkIpConn(self, ip, iface):
		"""
			check public address status
		"""
		if not self.checkIfaceStatus(iface):
			self.bringUpIface(iface)
			if not self.checkIfaceStatus(iface):
				return False
		
		if self.checkIpExists(ip, iface):
			return True
		elif self.takePublicIP(ip, iface) == Yerr.ESUCCESS:
			return True
		else:
			return False

	def checkIpsConn(self, ips, iface):
		"""
			check public address status
		"""
		if not self.checkIfaceStatus(iface):
			self.bringUpIface(iface)
			if not self.checkIfaceStatus(iface):
				return False

		down = 0
		for ip in ips:
			if self.checkIpExists(ip, iface):
				continue
			elif self.takePublicIP(ip, iface) == Yerr.ESUCCESS:
				continue
			else:
				down = 1
				break

		# some ip coulud not be set
		if down == 1:
			return False

		return True

	def testRaise(self, file_name):
		
		fd = open(file_name)
		fd.close()
