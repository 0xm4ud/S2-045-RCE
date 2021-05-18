# (m4ud) Apache Struts S2-045-RCE  CVE-2017-5638



    NT: Uses powershell, bash or msfvenom create payloads based on chosen OS,
    or you use only the -c flag to issue commands without lhost, lport, and osys!
    
      Options:
      -h, --help            show this help message and exit
      -p RPORT, --port=RPORT
                            RPORT,
      -t TARGET, --target=TARGET
                            Vulnerable Target,
      -d DIRECTORY, --dir=DIRECTORY
                            Struts Application directory,
      -c COMMAND, --command=COMMAND
                            System Command,
      -o OSYS, --os=OSYS    Choose OS: Linux = 1, Windows = 2
      -l LHOST, --lhost=LHOST
                            LHOST
      -P LPORT, --lport=LPORT
                            LPORT
      -s SHELL, --shell=SHELL
                            Shell type: 1 = powershell or bash, and 2 = msfvenom


