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
 
  
now lets walkthough each port and see what we can do :
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

22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
----
trying the same credintial of fttp for ssh it works :D 

  now we can excute files on the machine  
