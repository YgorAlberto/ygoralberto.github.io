## COMANDOS LINUX

	ls - Lista os arquivos do diretório
	
	mkdir -  Cria pasta no diretório.
	
	users - Mostra os usuários logados
	
	top - Mostra os processos que estão rodando
	
	htop - Mostra os processos que estão rodando mais detalhadamente.
	
	history - Mostra os comando digitados anteriormente.
	
	man "comando" - Mostra o manual do comando informado.
	
	cd - Navega nos diretórios.
	
	df - Lista os discos existente no computador
	
	df -h Lista os discos e detalhes de espaço/armazenamento
	
	du -sh * Mostra o tamanha do armazenamento das pastas e arquivos do diretório atual
	
	tail -f - Comando para ver o arquivo com atualização em tempo real
	
	tar -xvjf - Descompacta arquivo .tar.bz2
	
	tar -xf arquivo.tar.zx Descompactar arquivo tar.zx
	
	uname -a - Mostra o Sistema Operacional Rodando
	
	sudo nano /etc/hostname - Trocar nome da maquina
	
	zip -re output_data.zip file.txt file.pdf - criar arquivo zip com senha
	
	sudo wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg - RESOLVE O PROBLEMA DA CHAVE FALTANDO MISSING KEY 997866SD89S67DF6F67S8A9A0H0Y9RTR

	deb [trusted=yes] http://example.com/repo stable main ADICIONA O REPOSITORIO COMO CONFIAVEL CONFIANÇA NO SOURCE LIST /etc/apt/sources.list.d/

	nload iftop bmon vnstat ip -s link - FERRAMENTA DE MONITORAMENTO DE REDE BANDA LINK

	arecord -l | xwininfo | recordmydesktop --x=0 --y=35 --width=2560 --height=1045 --fps 30 --v_quality 63 --s_quality 10 --on-the-fly-encoding --no-frame --device pulse -o gravacao.ogv | echo "Gravar video com area especificada, com base no comando anterior COM AUDIO do PC o PULSE"

	echo "PRINCIPAL" | arecord -l | ffmpeg -f x11grab -s 2560x1045 -i :0.0+0,80 -f pulse -i default -c:v libx264 -c:a aac -r 30 -q:v 63 gravacao.mp4 | echo "Gravar video com area especificada, com base no comando anterior COM AUDIO do PC o PULSE"

	arecord -l | xwininfo | recordmydesktop --x=0 --y=35 --width=2560 --height=1045 --fps 30 --v_quality 63 --s_quality 10 --on-the-fly-encoding --no-frame --device hw:2,0 -o gravacao.ogv | echo "Gravar video com area especificada, com base no comando anterior COM audio USB dispositivo 2 card 0, pode ser escolhido baseado no primeiro comando da linha"

	arecord -l | ffmpeg -f x11grab -s 2560x1045 -i :0.0+0,35 -f alsa -i hw:2,0 -c:v libx264 -c:a aac -r 30 -preset ultrafast -y gravacao.mp4 | echo "Gravar video com area especificada, com base no comando anterior COM audio USB dispositivo 2 card 0, pode ser escolhido baseado no primeiro comando da linha"

	nano /etc/default/grub | echo "ADICIONA AS LINHAS ABAIXO NO ARQUIVO PARA ALTERAR A RESOLUÇÃO DA TELA CASO NAO ESTEJA FUNCIONANDO NO MONITOR #display #monitor #resolucao"
	GRUB_GFXMODE=2560x1080 
	GRUB_GFXPAYLOAD_LINUX=keep

	lsof ~/.xsession-errors | echo "VER QUAL APLICATIVO TA USANDO ESSE ARQUIVO NO MOMENTO"

- Gerenciamento de Usuários no lunux - add - copyuser - del user - change pass - shell

      useradd newuser
      useradd -m copycurruser
      deluser newuser
      sudo passwd newuser
      sudo chsh -s /bin/bash newuser
      sudo useradd -m -d /home/newuser newuser
      sudo usermod -d /home/newuser -m newuser
      sudo usermod -aG group newuser
      sudo adduser <nome_do_usuário> sudo
      cp /etc/skel/.bashrc ~/
      cp /etc/skel/.profile ~/
      source ~/.bashrc
      apt install zsh
	  sudo chsh -s /usr/bin/zsh
      cp ~/.zshrc (copiar de um kali linux)
	  nano ~/.zshrc
      su -
      su - suporte

- Gerenciamento de interfaces de rede network interfaces [Referencias](https://wiki.netbsd.org/tutorials/how_to_use_wpa_supplicant/)

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
 
- Iniciar um serviço junto com boot na inicialização de rede network interfaces

      sudo nano /lib/systemd/system/myscript-script.service

		[Unit]
		Description=Meu script para testes
		Wants=network-online.target
		After=network.target
		
		[Service]
		ExecStart=/bin/bash /diretorio/meu-script.sh
		
		[Install]
		WantedBy=multi-user.target

      sudo systemctl daemon-reload
      sudo systemctl enable myscript-script.service

.

Descobrir IPv4 (meu ip my ip myip meuip)

	curl -s https://meuip.com.br | grep "Meu ip" > .meuip
	cat .meuip | cut -d " " -f 8 > ip.txt
	sed -i 's/<\/h3>/ /g' ip.txt
	cat ip.txt
	rm .meuip
	rm ip.txt

.

      sudo dd bs=4M if=ImageName.iso of=/dev/sdc conv=fdatasync status=progress

Linux Bootable 


	VBoxManage internalcommands sethduuid image.vdi

Trocar UUID VDI VirtualBox Image no WINDOWS

	 C:\Program Files\Oracle\VirtualBox> .\VBoxManage internalcommands sethduuid C:\Users\user\Downloads\kali.vdi	
    Acessar os discos e ir em -> release -> remove e add o disco novamente

Resolver problema de UUID em VirtualBox.xml

Resolver problema do virtualbox-dkms que pede para reinstalar e iniciar o modprob config

Re-install virtualbox-dkms package first

	sudo apt-get autoremove virtualbox-dkms
	sudo apt-get install build-essential linux-headers-`uname -r` dkms virtualbox-dkms

After that You can enable it manually

	sudo modprobe vboxdrv
	sudo modprobe vboxnetflt


Resolver problema da maquina que não inicia por falta de memoria `Out of memory condition when allocating memory with low physical backing. (VERR_NO_LOW_MEMORY).`

	echo 3 > /proc/sys/vm/drop_caches

Manter o openvpn conectado mesmo se o dispositivo desconectar ou reiniciar (Adicionar a segunda linha ANTES do EXIT)

	sudo cp seu-arquivo.ovpn /etc/openvpn/client/
	sudo systemctl enable openvpn-client@nome-do-arquivo
	sudo nano /etc/openvpn/client/auth.txt
	EDITAR O OVPN colocando o PATH na senha: /etc/openvpn/client/auth.txt
	OU
	sudo nano /etc/rc.local
	openvpn --config /caminho/para/seuarquivo.ovpn &

 
## GERENCIAMENTO DE DISCOS
	
	fdisk -l Lista os discos existentes no dispositivo
	
	fdisk -x Lista mais informações
	
	blkid Lista mais formações ainda sobre os discos, mais relacionado label rotulo UUID
	
	fdisk /dev/sda Seleciona o disco (P lista info do disco, D deleta uma partição, W escreve as alterações)
	
	sudo parted /dev/sdX && echo "acessa o uitilitario de patições do disco"
		print
		rm 1 (REPETE ATE DELETAR TODAS AS PARTIÇÕES)
		mklable gpt
	sudo fdisk /dev/sdX
		g (CRIA TIPO GPT)
		w (ESCREVER AS MUDANÇAS)
		n (CRIAR NOVA PARTIÇÃO)
		w (SALVA AS ALTERAÇÕES)
	
	wipe /dev/sda1 Limpa o disco informado
	
	sudo mkfs.ext4 /dev/sda1 Formatar disco informado no comando
	
	sudo mount /dev/sda1 /mnt/Disco Montar disco formatado ou desmontado
	
	mount -t cifs //145.65.89.12\folder\ \mnt\local\pc -o user=<USUARIO>,password=<SENHA>,domain=<DOMINIO> Montar disco compartilhado no domínio
	
	sudo apt install ntfs-3g UTILITARIO PARA MANUTENÇAO EM DISCOS NTFS
	
	sudo ntfsfix -b -d /dev/sdf2 SERVE PARA RODAR QUANDO DER ERRO NA MONTAGEM DO DISCO NTFS (Failed to mount) (Input/output error) (SoftRAID/FakeRAID)
	
	sudo e2label /dev/sdb1 "Dados" | echo "Mudar nome do disco disk renomear disco partição"

- AUTOMATIZANDO A MONTAGEM DE DISCOS SEM O FSTAB

Por exemplo, preciso montar um disco toda vez que o sistema iniciar...


	nano /usr/local/bin/script-for-start-up.sh | echo "START SCRIPT WITH #!/bin/bash"
	chmod +x /usr/local/bin/script-for-start-up.sh
	sudo nano /etc/systemd/system/script-for-startup.service
	PASTE CODE
		[Unit]
		Description=Mount Additional Disks
		After=multi-user.target
		Requires=network.target
		
		[Service]
		Type=oneshot
		ExecStart=/usr/local/bin/script-for-startup.sh
		RemainAfterExit=yes
		TimeoutSec=0
		
		[Install]
		WantedBy=multi-user.target
	sudo systemctl enable script-for-startup
	journalctl -u mount-disks.service -xe | echo "FOR TROUBLESHOOTING"

## Compartilhamento no LINUX

sudo apt install samba
sudo nano /etc/samba/smb.conf
    [global]

        workgroup = servidor01.acme.corp
        netbios name = servidor01

    [publica]
    
        path = /compartilhamento/publica
        browseable = yes
        writable = yes
        read only = no

smbpasswd -a user
systemctl restart smb.service
systemctl restart nmb.service
smbclient //192.168.2.10/ -U user
smb://192.168.2.10 Via interface

	Para descompactar rar: unrar x nomedoarquivo.rar.
	Para descompactar tar: tar -xvf nomedoarquivo.tar.
	Para descompactar tar.gz: tar -vzxf nomedoarquivo.tar.gz.
	Para descompactar bz2: bunzip nomedoarquivo.bz2.
	Para descompactar tar.bz2: tar -jxvf nomedoarquivo.
	Para descompactar gz: gunzip nomedoarquivo.gz
	unzip arquivo.zip
	tar -xf arquivo.tar
	tar -xzf arquivo.tar.gz
	tar -xzf arquivo.tgz
	tar -xjf arquivo.tar.bz2
	tar -xJf arquivo.tar.xz
	gunzip arquivo.gz
	bunzip2 arquivo.bz2
	unrar x arquivo.rar
	7z x arquivo.7z
	ar x arquivo.deb
	dpkg-deb -x arquivo.deb diretorio
	cabextract arquivo.cab
	uncompress arquivo.Z
	lzma -d arquivo.lzma

xfreerdp /u:user@domain.com /v:192.168.2.11 Conectar com RDP em modo gráfico
ls --block-size=M Imprime os tamanhos em megabytes
du -a Imprime os tamanhos em MB

    Reparticionar DISCO LINUX

Aumentar Volume Linux

	sudo lvextend -l+100%FREE /dev/ubuntu-vg/ubuntu-lv 
 
 Libera 100% para uso

	sudo resize2fs /dev/ubuntu-vg/ubuntu-lv 
 
 Aumenta o disco para o uso

Criar partição no linux:
sudo fdisk /dev/sda
m For help n cria partição p primaria 3 numero da partição.

sudo timedatectl set-timezone America/Araguaina Setar a data / o fuso horário do servidor/sistema

Cron Example: https://crontab.guru/examples.html

 

Adicionar montagem automática de partição

echo '/dev/hdd/hdd /mnt/hdd ext4 defaults 0 2' >> /etc/fstab

 

 Reparo de erro da VM no Hyper-V

Erro: blk_update_request: I/O error, dev fd0, sector 0

Rode os comandos a seguir:

sudo rmmod floppy

echo "blacklist floppy" | sudo tee  /etc/modprobe.d/blacklist-floppy.conf

sudo dpkg-reconfigure initramfs-tools

lsmod | grep -i floppy

echo "blacklist floppy" | sudo tee /etc/modprobe.d/blacklist-floppy.conf

sudo rmmod floppy

sudo dpkg-reconfigure initramfs-tools

sudo reboot

-- Trocar o IP do Servidor LINUX


Lista de Comandos:

Passo 01:

->cd /etc/netplan

->ls

Se não tiver nenhum arquivo

    ->sudo netplan generate

Se aparecer um arquivo .yaml

Passo 02:

Edita o arquivo:

->sudo nano nome-do-arquivo.yaml

Passo 03:

Adicionando o Código abaixo (troca IP definitivamente pelo de sua preferência):

 This is the network config written by 'subiquity'

network:

	# This is the network config written by 'subiquity'
	network:
	  ethernets:
	    enp0s3:
	      addresses:
	      - 192.168.2.15/24
	      nameservers:
	        addresses:
	        - 1.1.1.1
	        search:
	        - 8.8.8.8
	      routes:
	      - to: default
	        via: 192.168.2.1
	  version: 2

Ativar modo DHCP:

	network:
	  version: 2
	  ethernets:
	    enp6s0:
	      dhcp4: true
  
Legenda:
renderer : Renderizador (daemon de rede) Aceita os valores NetworkManager e networkd. O padrão é networkd. Pode ser aplicada globalmente ou para um dispositivo específico. 
ethernets : Seção das interfaces de rede a configurar enp0s3 : Nome de uma interface de rede a configurar
dhcp4 : Propriedades da interface para o DHCP versão 4
dhcp6 : Propriedades da interface para o DHCP versão 6
addresses : Lista de IPs a serem atribuídos 
gateway4 : Endereço do gateway padrão da rede nameservers : Seção de Servidores DNS e domínios de busca a usar.

[See MANUAL](https://manpages.ubuntu.com/manpages/bionic/man5/netplan.5.html)
[NETPLAN](https://netplan.readthedocs.io/en/stable/netplan-tutorial/#using-static-ip-addresses)

Passo 04:

Para testar se Funcionou:
$sudo netplan apply
$sudo netplan try

Bônus!

Trocar ip temporariamente:

	sudo ifconfig eth0 192.168.0.1 netmask 255.255.255.0
	sudo route add default gw 192.168.0.253 eth0

Referência: http://www.bosontreinamentos.com.br/linux/como-configurar-endereco-ip-estatico-no-linux-ubuntu-18-04-com-netplan/

	upower -i /org/freedesktop/UPower/devices/battery_BAT0

Saber informacões vida útil bateria healthy lifecycle

	sudo nmcli connection show
	sudo nmcli connection delete ab0b9039-c4b1-48af-b30c-adcbea993643

Deletar interface de rede 

## COMANDOS ALEATORIOS

Se der o erro `(eval):1: _python-argcomplete: function definition file not found` ao tentar completar com tab, rode isso:

	sudo apt install python3-argcomplete
	sudo activate-global-python-argcomplete

## COMANDOS WINDOWS

Comando para abrir o gerenciamento de usuários no WINDOWS

	netplwiz OU lusrmgr.msc
	rundll32.exe keymgr.dll,KRShowKeyMgr ABRE JANELA DE AUTENTICACAO PARA CONFIGURAR COMPARTILHAMENTO DE PASTAS
	net use * \\IP_DO_PC\NomeDaPasta /user:NOME-PC\share senha@aqui
	control /name Microsoft.CredentialManager
	

Reseta senha dos usuarios do Windows com o HD conectado ao Linux

	sudo apt install chntpw        # se não estiver instalado
	sudo mount /dev/sdXN /mnt      # substitua sdXN pela partição do Windows
	cd /mnt/Windows/System32/config
	sudo chntpw -i SAM

Instalar ativar baixar windows e office [AQUI](https://massgrave.dev/)

	irm https://get.activated.win | iex

Rodar o comando acima com o POWERSHELL e como ADMINISTRADOR

wmic bios get serialnumber = Ver numero de série do PC

Tips: Barra de tarefas transparente
REGEDIT: Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced Criar arquivo com o nome TaskbarAcrylicOpacity

MSINFO32 Informações do Computador
COPY Copia arquivos
TYPE Semelhante ai cat no terminal

wusa /kb:5009543 /uninstall Desinstala atualização passada

	fsutil behavior query DisableDeleteNotify

 Comando para verificar se o SSD está em seu fucionamento pleno

Ativar windows via CMD

Type the below command and press Enter.

slmgr /ipk kmsclientkey

    Windows Home: TX9XD-98N7V-6WMQ6-BX7FG-H8Q99
    Windows Home N: 3KHY7-WNT83-DGQKR-F7HPR-844BM
    Windows Pro: W269N-WFGWX-YVC9B-4J6C9-T83GX
    Windows Pro N: MH37W-N47XK-V7XM9-C7227-GCQG9
    Windows Education: NW6C2-QMPVW-D7KKK-3GKT6-VCFB2
    Windows Education N: 2WH4N-8QGBV-H22JP-CT43Q-MDWWJ

For example, if you want to activate Windows 11 Pro, use the command ‘slmgr /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX.’

Refer: https://www.guidingtech.com/how-to-activate-windows-11-for-free/

## LISTAS USUARIOS DO ACTIVE DIRECTORY
	
	Get-ADUser -Filter {Enabled -eq $true} -Property MemberOf | ForEach-Object {
	    $user = $_
	    $groups = $user.MemberOf | ForEach-Object { (Get-ADGroup -Identity $_).Name }
	    [PSCustomObject]@{
	        UserName = $user.SamAccountName
	        DisplayName = $user.DisplayName
	        Groups = $groups -join ', '
	    }
	} | Format-Table -AutoSize

Second option

	Get-ADUser -Filter {Enabled -eq $true} -Property SamAccountName, DisplayName, EmailAddress | 
	Select-Object SamAccountName, DisplayName, EmailAddress | 
	Export-Csv -Path "C:\AD_UsuariosAtivos.csv" -NoTypeInformation -Encoding UTF8


## WINDOWS WSL COM QUALQUER DISTRO LINUX

  WINDOWS SUBSYSTEM FOR LINUX


Modo fácil e descomplicado de instalar o linux no windows usando o WSL
Full tutorial HERE! https://docs.microsoft.com/en-us/windows/wsl/install-win10

Abra o CMD como ADM e rode o seguinte comando:

    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

Download o pacote de instalação do WSL:
Instale o pacote de UPDATE do WSL;
          
    https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi
    shutdown -r -t 1

Rode o comando:

    wsl --set-default-version 2

Instale a Distro que preferir, usando a loja da Microsoft;
Inicie a Distro e Configure-a;
Habilite a distro para usar a versão 2 do WSL

    wsl --set-version kali-linux 2

DENTRO da DISTRO

-> sudo apt update

>sudo apt install kali-linux-default    (instala todas as ferramentas do kali)

->sudo apt install kali-tools-top10      (instala as principais ferramentas do kali)

Instale o Kex se preferir (Interface Gráfica)

->sudo apt install -y kali-win-kex

Dentro do Kali digite kex para iniciar o modo gráfico

Dica: 

Acessar os arquivos do windows pelo linux, caminho:
/mnt/c/

REFERENCES:

https://www.kali.org/blog/kali-on-the-windows-subsystem-for-linux/

https://docs.microsoft.com/en-us/windows/wsl/install-win10


## INSTALAR TELA LCD NO RAPBERRYPI
    
Tutorial rápido e fácil de fazer.

Primeiro faça a clonagem do repositório para o Raspberry com o Raspbian instalado e funcionando através do comando: Repositório

Depois dê permissão de edição e execução para a pasta:
    $chmod -R 755 LCD-show

Acesse a pasta:
    $cd LCD-show

Instale o driver:
    $./LCD35-show

O comando abaixo permite girar a tela em 90º:
    $sudo ./XXX-show 90

Se necessário, poderá listar as opções de resolução e ajustar no tamanho desejado:

$xrandr

Selecione a resolução desejada:

$xrandr -s 1 (número representa a opção da listagem mostrada com o comando acima)

Pronto, reinicie seu Raspberry e terá sua TELA LCD configurada
    
## INSTALAR GUI NO RASPBERRYPI


Nesta lista de comandos você irá conectar-se ao WIFI e rodar o comando para instalar o GUI no seu Raspberry Pi

    sudo iwlist wlan0 scan
    sudo nano /etc/wpa_supplicant/wpa_supplicant.conf

        network={

          ssid="YOUR_SSID"

          psk="YOUR_PASSWORD"

        }

    sudo apt-get update && sudo apt-get -y dist-upgrade && sudo apt-get install raspberrypi-ui-mods rpi-chromium-mods
    sudo reboot
    sudo raspi-config

## SISTEMA DE VIGILÂNCIA COM RASPBERRY PI

 Monitorando sua casa com Raspberry PI

Faça o monitoramento da sua casa em tempo real acessando diretamente do celular computador ou TV!

Materiais necessários: Raspberry PI com o SO (Raspberry Pi OS 32BITS )e uma Câmera para Raspberry.

Passo 01:

	raspi-config 

Procure por câmera (varia de versão para versão do Raspberry PI OS). E habilite a mesma.

Passo 02:
Atualize o Raspbian com o famoso

	sudo apt-get update
	sudo apt-get upgrade

Passo 03:
Vá no seguinte repositório do GitHub e faça o 
	
 	git clone: https://github.com/silvanmelchior/RPi_Cam_Web_Interface

Passo 04:
Vá para a pasta que foi feita o download e execute o instalador

	./install.sh

Dê Ok e Yes no que aparecer e pronto!

Acesse o ip do seu RASPBERRY e clique em HTML!

O sistema conta com várias funcionalidades e personalizações.
Use sua imaginação e monitore sua casa...

Bônus 01: Entre nas configurações do seu roteador e adiciona uma rota apontando para o IP e porta do Raspberry para acessar sua câmera de onde estiver usando seu IP público. Mas CUIDADO! O sistema não faz autenticação, sendo assim qualquer pessoa com o IP Público vai ter acesso à sua câmera!

Bônus 02: 
Vá para a pasta 

    $cd /var/www/
    
E crie um arquivo com o nome index.php.

    $nano index.php 
            Cole essa linha de código dentro do arquivo index nas pasta WWW
  
      <meta http-equiv="refresh" content="0;url=html">


Pronto, basta acessar o seu IP e conseguirá acessar sua câmera.

Referência: https://www.hostinger.com.br/tutoriais/redirecionamento-php

- Raspberry com bloqueio de root locked root não inicia

  Coloca o cartão no pc monta e no disco de boot procura por `cmdline.txt` e adiciona ao final da linha `init=/bin/sh`
  Salva e liga o raspberry novamente e com acesso ao CLI desfaça as modificaçoes feitas anteriormente que fizeram dar erro

[Reference](https://samx18.io/blog/2017/11/05/piBootIssue.html)

## DEPLOY RAPIDO DE UM SIEM WAZUH


 Olá, comandos rápidos para configurar um WAZUH sem complicação.

Após o servidor [LINUX Debian Based] estiver configurado e pronto para uso, rode os seguintes comandos:

REF: https://documentation.wazuh.com/4.3/quickstart.html


        curl -sO https://packages.wazuh.com/4.3/wazuh-install.sh && sudo bash ./wazuh-install.sh -a 

        Vai aparecer o login e senha -> anote-os


Vai no navegador e acesse: https://<server-ip> Coloque o login e senha anteriormente anotado.

Ao acessar o dashboard, vai em Agents e configure de acordo com o ser server a ser monitorado, exemplo de Linux 64bits Ubuntu

Antes de rodar o comando abaixo, trocar o IP par ao IP do seu servidor WAZUH
Obs.: Repetir este processo para a config dos demais servers que deseja monitorar

    curl -so wazuh-agent-4.3.10.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.3.10-1_amd64.deb && sudo WAZUH_MANAGER='192.168.2.100' WAZUH_AGENT_GROUP='default' dpkg -i ./wazuh-agent-4.3.10.deb

    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent


Caso apresente algum erro, olhar:

    sudo cat /var/ossec/logs/ossec.log


Se o erro for relacionado ao MANAGER_IP
Acessar:

    sudo nano /var/ossec/etc/ossec.conf

    E trocar o MANAGER_IP Pelo ip do servidor WAZUH

Modificar o arquivo para habilitar alertas adicionais

    nano /var/ossec/etc/ossec.conf

   
 ## COMANDOS DOCKER
    
 Alguns comandos do Docker para relembrar (em construção)


Matar todos os Containers: docker kill $(docker ps -q)

docker-compose build: Construir um container

No diretório startar o docker: docker-compose up -d

Gerar uma BUILD: docker-compose build --no-cache

Docker rodando: docker ps

Trocar de branch: git checkout branch-nome


Certificado SSL:

Dentro da aplicação: openssl req -x509 -nodes -newkey rsa:2048 -keyout cert.key -out cert.crt -days 365

docker-compose.yml 

        Add embaixo do Volumes:        

         - ./certs:/etc/nginx/certs

site.conf     

        Add embaixo de "Listen 80;"

        listen 443 ssl;

        ssl_certificate /etc/nginx/certs/cert.crt;     

        ssl_certificate_key /etc/nginx/certs   

## SERVIDOR DE GTA 5 RP

Passo 1

    Criar VM na Amazon EC2 no modelo elegível gratuito com regra de entrada na porta 30190 de forma a deixar aberto para toda internet

Passo 2

    Instalar os arquivos do servidor e de configuração.
        mkdir -p /home/username/FXServer/server
        cd /home/username/FXServer/server
    Acessa o link copia o link https://runtime.fivem.net/artifacts/fivem/build_proot_linux/master/ e copia o link do arquivo de download mais recente.
        wget link.com/arquivos/recente
        tar xf fx.tar.xz
        Criar pasta de configuração do servidor
        cd /home/username/server-data
        git clone https://github.com/Ziraflix/vrpex-zirix-v2.git (Pegar mais recente)
    Criar chaves do FiveM e da Steam:
        https://keymaster.fivem.net/login
        https://steamcommunity.com/login/home/?goto=%2Fdev%2Fapikey
    Troca as keys de sv_licenseKey e set steam_webApiKey pelas chaves criadas no passo acima
        nano /vrpex-zirix-v2/zirix-data/config/keys.cfg
        Trocar as chaves criadas no arquivo
    Rode o servidor txAdmin
        FXServer/soBesteiraCity/alpine/run.sh
    Acesse o navegador para finalizar a config

Passo 3

    Trocar o nome do servidor, nome do projeto e descrição do projeto
        Em sv_hostname “Coloque o nome de preferência”
        Em sets sv_projectName “Coloque o nome do servidor do projeto”
        Em sets sv_projectDesc “Escreva a descrição do projeto”

Passo 4

    Instalar o banco de dados MySql > 5.1 - sudo apt install mysql-server
    OU
    sudo apt install mariadb-server
    Criar usuário e senha para o banco:

Comando do Mysql para criar o usuário e dar permissão:

    Criar um banco de dados com o nome zirix:
    NO ZIRIX O aquivo de conf do db fica no caminho vrp>modules>db.lua
    mysql --host=localhost --user=root --password= -e "zirix.sql"
    OU
    source /home/server-data/vrpex-zirix-v2/zirix-data/zirix.sql
    create user 'username'@'localhost' identified by 'senha123';
    GRANT ALL PRIVILEGES ON *.* TO 'username'@'localhost' WITH GRANT OPTION;
    GRANT ALL PRIVILEGES ON database_name. * TO 'username'@'localhost';
    NAO LEMBRO PRA QUE SERVE alter user 'root'@'localhost' identified with mysql_native_password by 'root';
    
String de conexão do FIVEM Server com o banco de dados local:

    set mysql_connection_string "server=127.0.0.1;database=DBNAME;userid=USERNAME;password=p@ssw0rd;persistsecurityinfo=true;"

Autorizar usuário na WL dentro do banco:

	Adicionar user à WL:  update vrp_users set whitelisted = 1 where id=1;

Passos seguintes:

Fazer alterações e customizações na BASE:

    Resources/[VRP]/vrp/queue.lua -> Setar requireSteam para FALSE
    base-data/resources/[System]/vrp/loading -> Alterar o banner de carregamento (tela de loading enquanto entra no servidor) e troca a musica de apresentação.
    /server-data/BaseFreeTrinksStudio/base-data/resources/[Scripts]/hud/nui/assets/logo.png -> trocar a logo de dentro do game (logo que aparece enquanto joga)
    /server-data/BaseFreeTrinksStudio/base-data/config/server.cfg -> Trocar o Icone do servidor (que aparece quando lista os servers no FiveM)

COMO SE CONECTAR AO SERVIDOR?

1 - Voce precisa de um pc que rode GTA V (pago)
2 - Baixa o FIVEM e cria uma conta
3 - Com o FIVEM aberto pressione F8 e cole: connect 143.198.190.184:50120
OU
4 - Com o FIVEM aberto pesquise pelo nome da sua cidade (So Besteira City)

Commands para usar dentro de algumas bases (precisa ser ADM):

	/nc - voar pela city
	/car zentorno | t20 | rhino
	/tpway Ir para marcação mapa
	/tpto ID is para ID passado
	H Agarra o player
	/reviver ID Revive o ID
	/group ID administrador Coloca o ID como admin
	/ungroup ID administrador
	/tuning 
	/god ID
	/arma NOME
	/dv Guarda carro
	/group id dono
	/group {id} policia 
 
	bind keyboard "tecla" "comando; comando"
	unbind keyboard "tecla"

	item WEAPON_ASSAULTRIFLE 1 ;
	item WEAPON_ASSAULTSMG 1 ;
	item WEAPON_BAT 1 ;
	item WEAPON_BATTLEAXE 1 ;
	item WEAPON_BOTTLE 1 ;
	item WEAPON_CARBINERIFLE_MK2 1 ;
	item WEAPON_COMBATPDW 1 ;
	item WEAPON_COMBATPISTOL 1 ;
	item WEAPON_COMPACTRIFLE 1 ;
	item WEAPON_CROWBAR 1 ;
	item WEAPON_DAGGER 1 ;
	item WEAPON_GOLFCLUB 1 ;
	item WEAPON_GUSENBERG 1 ;
	item WEAPON_HAMMER 1 ;
	item WEAPON_HATCHET 1 ;
	item WEAPON_KNIFE 1 ;
	item WEAPON_MACHETE 1 ;
	item WEAPON_MACHINEPISTOL 1 ;
	item WEAPON_MICROSMG 1 ;
	item WEAPON_MUSKET 1 ;
	item WEAPON_PISTOL 1 ;
	item WEAPON_PISTOL_MK2 1 ;
	item WEAPON_POOLCUE 1 ;
	item WEAPON_REVOLVER 1 ;
	item WEAPON_REVOLVER_MK2 1 ;
	item WEAPON_SMG 1 ;
	item WEAPON_STONE_HATCHET 1 ;
	item WEAPON_STUNGUN 1 ;
	item WEAPON_SWITCHBLADE 1 ;
	item WEAPON_VINTAGEPISTOL 1 ;
	item WEAPON_WRENCH 1 ;
	
	item WEAPON_PISTOL_AMMO 99999;
	item WEAPON_RIFLE_AMMO 99999;
	item WEAPON_SHOTGUN_AMMO 99999;
	item WEAPON_SMG_AMMO 99999;




- DICAS QUE VALEM SER LEMBRADAS

	2 - Para adicionar alguem como `ADM`, ela precisa já ter logado e estar com a Wl habilitada e criado o personagem, depois basta ir no banco de dados e na tabela `vrp_user_data` (geralmente) haverá dados do jogador como características, inventário, roupas e etc. É possível modificar esse campo da tablea. Para isso deve-se estar deslogado do ame em muitos dos casos. Nesse campo pode-se, dar permissão de ADM, inserir dinheiro, vida, roupa etc.

	1 - Para adicionar armas, precisa seguir a documentação do game junto com as opções dentro da base. No caso da arma, pesquise dentro do servidor na base se há armas presente no codigo, pegue esses nomes e tente adicionar como por exemplo `item WEAPON_MINISMG 1` e para add balas precisa também pesquisar na documentação e no código como faz isso, por exemplo  `item WEAPON_PISTOL_AMMO 999`. Esse comando pode ser dodado pressionando F8 entro do FiveM
    

## TIRAR REMOVER REPARO DE DISCO 
    
 Remover o reparo automático de disco na inicialização do Windows 10


1° Passo: Rodar esse comando no CMD como ADM:

fsutil dirty query c:


2° Passo: Rodar esse comando 3x:

chkntfs /x c:


3° Passo: Rodas esses dois comandos

fsutil dirty query c:

chkdsk C: /f /r


Referência:

https://answers.microsoft.com/en-us/windows/forum/all/to-skip-disk-checking-press-any-key-pops-up-on/ad32da92-1df8-4f98-904e-4d020c4ffa5a
    
## MONTANDO PROJETO EM LARAVEL
    
MONTANDO AMBIENTE DE PROGRAMAÇÃO LARAVEL


#___Windows____#


Baixa e instala o XAMPP; (fique a vontade para instalar outro)

Baixa e instala o GIT; (fique a vontade para instalar outro)

Baixa e instala o Visual Studio Code (VS code); (fique a vontade para instalar outro)

Baixa e instala o Composer; Restart Your computer;

Roda o comando:
        ->composer global require laravel/installer

Vá para o diretório que queres adicionar o repositório dos arquivos (Geralmente na pasta XAMPP)

    Para um projeto NOVO rode o comando:
    ->laravel new NomedoProjeto

    Iniciar a aplicação:
    ->php artisan serve

     Feito, ambiente para desenvolvimento feito!


    Para um projeto EXISTENTE Faça o clone do projeto. Caso tenha esquecido dos comandos básicos do GIT acesse: Comandos GIT

    ->git clone linkdorepositorio.github.com

    ->composer install

    ->php -r "copy('.env.example', '.env');"

    ->php artisan key:generate

#Coloque as informações do banco;

#Crie o banco de dados;

Rode o comando:

    ->php artisan migrate

    ->php artisan db:seed

    Pronto para desenvolver!


CRIANDO UM CRUD

php artisan make:model contribuinte

php artisan make:controller Contribuintes

php artisan make:controller ContribuintesController

php artisan make:migration create_contribuintes_table
    
-- CONTINUANDO PROJETO EM LARAVEL
    
Após instalado o LARAVEL e criado o projeto..


Primeiro Passo
Modifique o arquivo .env 
Atualizar dados do banco de dados que será utilizado e posteriormente criar o banco de dados lá no SGBD. (Ex.: phpMyadmin)


	#Dicas: Session drive é a melhor forma de salvar é em banco de dados
                     O CRUD é feito no controller
                     Com o comando artisan, é possível criar migrations, controller, seed..
                     O Controller recebe as requisições: Não coloca instruções SQL 

                     php artisan lista os comandos do artisan
                     Syntax: php artisan + comando_desejado

 Lista de Comandos

-> php artisan make:migration create_projeto_table
                     Modela a Migration de acordo com o banco de dados do projeto;

-> php artisan migration
                    Criar as tabelas no bando de dados

-> php artisan make:model
                    Adiciona dentro da model o fillable com o array de variaveis da migration

-> insert
                    Adiciona os usuários da Tabela padrão no bando de dados 

-> php artisan make:controller nomedocontroller


Para Adicionar as Rotas

	Nos arquivo de rotas, add o caminho (ex. /projeto), o controller (ex. projetoController), e o metodo do controller (ex. index) a ser usado.


Dicas para criar as Views

	O foreach chama os dados do banco de dados

	Criar as tags html pra apresentar os dados relacionando-os com os campos do banco de dados.
    
    
## COMANDOS DO GIT
    
Comandos Básicos do GIT

	Primeiro commit
	git init
	git add *
	git commit -m "initial commit"
	git push origin master
	
	Adicionando mudanças realizadas
	git add *
	git commit -m "add xxxx funcionalidade"
	git push origin master
	
	Pegando do repositório as últimas mudanças
	git pull (link)
	Clonando do repositório todo o projeto
	git clone (link)

## Anydesk com problemas de biblioteca libgtkglext1

	sudo wget -qO - https://keys.anydesk.com/repos/DEB-GPG-KEY | apt-key add -
	sudo echo "deb http://deb.anydesk.com/ all main" > /etc/apt/sources.list.d/anydesk-stable.list
	sudo apt update
	wget "http://ftp.us.debian.org/debian/pool/main/libw/libwebp/libwebp6_0.6.1-2+deb10u1_amd64.deb"
	wget "http://ftp.us.debian.org/debian/pool/main/g/gtkglext/libgtkglext1_1.2.0-11_amd64.deb"
	wget "http://ftp.us.debian.org/debian/pool/main/g/gtk+2.0/libgtk2.0-0t64_2.24.33-6_amd64.deb"
	wget "http://ftp.us.debian.org/debian/pool/main/p/pangox-compat/libpangox-1.0-0_0.0.2-5+b2_amd64.deb"
	wget "http://ftp.us.debian.org/debian/pool/main/t/tiff/libtiff5_4.1.0+git191117-2~deb10u4_amd64.deb"
	 
	echo " "
	echo "INSTALANDO LIB-WEBP"
	echo " "
	 
	sudo dpkg -i libwebp6_0.6.1-2+deb10u1_amd64.deb
	 
	echo " "
	echo "INSTALANDO LIB-TIFF"
	echo " "
	 
	 
	sudo dpkg -i libtiff5_4.1.0+git191117-2~deb10u4_amd64.deb
	 
	echo " "
	echo "INSTALANDO LIB-PANGOX"
	echo " "
	 
	 
	sudo dpkg -i libpangox-1.0-0_0.0.2-5+b2_amd64.deb
	 
	echo " "
	echo "INSTALANDO LIB-GTK2"
	echo " "
	 
	sudo dpkg -i libgtk2.0-0t64_2.24.33-6_amd64.deb
	 
	echo " "
	echo "INSTALANDO LIB-GTK"
	echo " "
	 
	 
	sudo dpkg -i libgtkglext1_1.2.0-11_amd64.deb
	 
	echo " "
	echo "FINALIZADO AS LIBS"
	echo " "
	 
	sudo apt install anydesk
	rm lib*
	sudo apt --fix-broken install -y

FAÇA MANUAL

[Baixa o .deb](http://ftp.us.debian.org/debian/pool/main/g/gtkglext/)
Instala as dependências caso precise, e caso nao encontrar, procurar no link acima as dependêcias correspondentes

[1-libwebp](http://ftp.us.debian.org/debian/pool/main/libw/libwebp/libwebp6_0.6.1-2+deb10u1_amd64.deb)

[2-libtiff](http://ftp.us.debian.org/debian/pool/main/t/tiff/libtiff5_4.1.0+git191117-2~deb10u4_amd64.deb)

[3-pangox](http://ftp.us.debian.org/debian/pool/main/p/pangox-compat/libpangox-1.0-0_0.0.2-5+b2_amd64.deb)

[4-pixpuf](http://ftp.us.debian.org/debian/pool/main/g/gdk-pixbuf/libgdk-pixbuf-2.0-0_2.42.12+dfsg-1_amd64.deb)

[5-libgtk](http://ftp.us.debian.org/debian/pool/main/g/gtkglext/libgtkglext1_1.2.0-11_amd64.deb)

Instala as dependências caso precise, e caso nao encontrar, procurar no link acima as dependêcias correspondentes



## SETUP ANDROID VISTUALBOX

[Donload OVA](https://www.osboxes.org/android-x86/)

Create a MACHINE using the VDI image downloaded

If it is on CLI mode, try this:
	Turn it OFF, an go Settings -> Display -> graphic controller set to -> VBoxVGA. Turn off Enable 3D Acceleration.

## INSTALAR DRIVER VIDEO NVIDIA RX4070 ALIEWARE

	#!/bin/bash
	# ==================================================
	# Script de Instalação do Driver NVIDIA
	# Para: Kali Linux com RTX 4070 Max-Q
	# Criado: 2026-01-29
	# ==================================================
	
	set -e
	
	echo "========================================"
	echo "🎮 Instalação do Driver NVIDIA"
	echo "========================================"
	echo ""
	
	# Verificar se está rodando como root/sudo
	if [ "$EUID" -ne 0 ]; then 
	    echo "❌ Execute com sudo: sudo ./install-nvidia-driver.sh"
	    exit 1
	fi
	
	echo "📋 Sistema detectado:"
	cat /etc/os-release | grep PRETTY_NAME
	uname -r
	echo ""
	
	echo "🔍 GPU NVIDIA detectada:"
	lspci | grep -i nvidia || echo "⚠️  Nenhuma GPU NVIDIA encontrada!"
	echo ""
	
	echo "📦 Instalando pacotes..."
	apt update
	apt install -y nvidia-driver nvidia-cuda-toolkit
	
	echo ""
	echo "========================================"
	echo "✅ INSTALAÇÃO CONCLUÍDA!"
	echo "========================================"
	echo ""
	echo "⚠️  IMPORTANTE: Reinicie o computador agora!"
	echo ""
	echo "   sudo reboot"
	echo ""
	echo "Após o reboot, verifique com:"
	echo "   nvidia-smi"
	echo ""


## DRIVER NVIDIA E DUAL MONITOR RX 4070 ALIENWARE

[X11 no linux](https://pt.wikihow.com/Configurar-o-X11-no-Linux#:~:text=Execute%20o%20comando%20sudo%20Xorg,ser%C3%A3o%20adicionadas%20automaticamente%20ao%20arquivo)

[Lista de repositórios](https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/)

[Script que funcionou: Kali-Parrot_Dual_Monitor](https://github.com/IhsanMowaket/Kali-Parrot_Dual_Monitor)

[Doc Do KALI para instala a Nvidea](https://www.kali.org/docs/general-use/install-nvidia-drivers-on-kali-linux/)

[Video com tutorial no comentário](https://www.youtube.com/watch?v=JfneGOU5VoI)

Script Display_ON (FUNCIONA)

	#!/bin/bash
	sudo apt install linux-headers-$(uname -r)
	sudo echo "blacklist nouveau options nouveau modeset=0" > /etc/modprobe.d/blacklist-nouveau.conf
	
	sudo update-initramfs -u
	
	apt install nvidia-driver nvidia-xconfig nvidia-cuda-toolkit
	
	sudo modprobe nvidia-drm
	
	nvidia-xconfig --query-gpu-info
	 Similar --> PCI BusID: PCI:1:0:0
	
	sudo echo 'Section "ServerLayout"
	        Identifier "layout"
	        Screen 0 "nvidia"
	        Inactive "intel"
	EndSection
	 
	Section "Device"
	        Identifier "nvidia"
	        Driver "nvidia"
	        BusID "PCI:1:0:0"
	EndSection
	 
	Section "Screen"
	        Identifier "nvidia"
	        Device "nvidia"
	        Option "AllowEmptyInitialConfiguration"
	EndSection
	 
	Section "Device"
	        Identifier "intel"
	        Driver "modesetting"
	EndSection
	 
	Section "Screen"
	        Identifier "intel"
	        Device "intel"
	EndSection
	
	' > /etc/X11/xorg.conf.d/xorg.conf
	
	sudo echo '
	[Desktop Entry]
	Type=Application
	Name=Optimus
	Exec=sh -c "xrandr --setprovideroutputsource modesetting NVIDIA-0; xrandr --auto"
	NoDisplay=true
	X-GNOME-Autostart-Phase=DisplayServer' > /etc/xdg/autostart/optimus.desktop 
	
	
	sudo echo '
	[Desktop Entry] 
	Type=Application
	Name=Optimus
	Exec=sh -c "xrandr --setprovideroutputsource modesetting NVIDIA-0; xrandr --auto"
	NoDisplay=true
	X-GNOME-Autostart-Phase=DisplayServer' > /usr/share/gdm/greeter/autostart/optimus.desktop

Esse script funcionou da forma que está


Tutorial do comentário do video acima
	
	I finally found and fixed my Linux. The NVIDIA driver installed successfully without needing "nvidia-detect."
	
	 Connect your monitor with HDMI cable to your GPU.
	
	1. Find "contrib non-free" in your sources list:
	
	grep "contrib non-free" /etc/apt/sources.list
	
	2. Update your package list:
	
	sudo apt update
	
	3. Upgrade all installed packages:
	
	sudo apt -y full-upgrade
	
	4. Install Linux headers for your kernel:
	
	sudo apt install linux-headers-$(uname -r) -y
	
	5. Reboot if necessary after updates:
	
	[ -f /var/run/reboot-required ] && sudo reboot -f
	
	6. Check your VGA compatible controller:
	
	lspci | grep -i vga
	
	In my case:
	
	01:00.0 VGA compatible controller: NVIDIA Corporation GA104 [GeForce RTX 3070 Lite Hash Rate] (rev a1)
	
	7. View detailed info about your GPU:
	
	lspci -s 01:00.0 -v
	
	8. Install AMD64 headers:
	
	sudo apt install -y linux-headers-amd64
	
	9. Install NVIDIA drivers and CUDA toolkit:
	
	sudo apt install -y nvidia-driver nvidia-cuda-toolkit
	
	10. Reboot your system:
	
	sudo reboot -f
	
	My terminal looks like this (kalihunterbrimstone)-[~]. After a reboot, my "brimstone" user is missing, causing a login loop. To fix this, switch to the terminal with CTRL + ALT + F3, log in with your "kalihunter" user, and then:
	
	1. Reconfigure LightDM (install if needed):
	
	dpkg-reconfigure lightdm
	
	2. Edit LightDM configuration:
	
	sudo nano /etc/lightdm/lightdm.conf
	
	Add and save:
	
	[Seat:*]
	autologin-user=kalihunter
	autologin-user-timeout=0
	greeter-session=lightdm-gtk-greeter
	session-wrapper=/etc/X11/Xsession
	
	3. Reboot again:
	
	sudo reboot
	
	4. Log in with your configured user, and your NVIDIA driver should be installed successfully.
	
	5. I haven't installed "nvidia-detect". I can add a screenshot if needed. https://i.ibb.co/RT4ZmQ7/Screenshot-20240629-075917.png

O script acima não funcionou, porém está registrado caso funcione alguma vez

 ## INSTALANDO WIFI ALIENWARE

[Repositorio com o arquivo `iwlwifi-gl-c0-fm-c0-86.ucode`](https://gitlab.com/kernel-firmware/linux-firmware)

[Repositorio com o arquivo `iwlwifi-gl-c0-fm-c0-86.ucode`](https://github.com/pop-os/linux-firmware/tree/master)

Baixa todos com o início `iwlwifi-gl-c0-fm`
	
	cp iwlwifi-gl-c0-fm* /lib/firmware/.

Baixa o arqivos e coloca na pasta `/lib/firmware`

`dmesg` Lista os erros dos componentes de hardware

[Nao funcionou](https://mirror2.openwrt.org/sources/compat-wireless-2010-06-28.tar.bz2)

## INSTLANDO O AUDIO NO ALIENWARE

[Doc Kali](https://www.kali.org/docs/troubleshooting/no-sound/)

## INSTLANDO OPEN RGP PARA TECLADO

[source .deb](http://ftp.us.debian.org/debian/pool/main/m/mbedtls/)

Baixa o instalador [OpenRGB](https://openrgb.org/releases/release_0.9/openrgb_0.9_amd64_buster_b5f46e3.deb)

Instala primeiro o `libhidapi-hidraw0`

Depois o [libmbedcrypto3_2.16.0-1_amd64.deb](http://ftp.us.debian.org/debian/pool/main/m/mbedtls/libmbedcrypto3_2.16.0-1_amd64.deb)

Depois o [libmbedtls12_2.16.0-1_amd64.deb](http://ftp.us.debian.org/debian/pool/main/m/mbedtls/libmbedtls12_2.16.0-1_amd64.deb)

Depois o [libmbedx509-0_2.16.0-1_amd64.deb](http://ftp.us.debian.org/debian/pool/main/m/mbedtls/libmbedx509-0_2.16.0-1_amd64.deb)

E agora o `sudo dpkg -i openrgb_0.9_amd64_buster_b5f46e3.deb`

TUTO ACIMA NAO FUNCIONOU - RGB NAO TROUXE OS DISPOSITIVOS'


Parece que você quis dizer "linguagem de marcação pura" (talvez um erro de digitação). Vou assumir que você quer o tutorial em uma linguagem de marcação como Markdown, que é comum e legível. Se você tinha outra coisa em mente (como HTML ou algo diferente), por favor, me avise! Aqui está o primeiro tutorial reescrito em Markdown:

LINKS UTEIS ALIENWARE INSTALL DRIVER

Instalar o ADAPTADOR WIFI https://medium.com/@suryateja233/installing-wifi-drivers-in-kali-linux-and-or-linux-distribution-s-7e01e7d730a3
Driver NVIDIA https://www.kali.org/docs/general-use/install-nvidia-drivers-on-kali-linux/
DRIVER WIFI https://www.youtube.com/redirect?event=video_description&redir_token=QUFFLUhqa016dDN5REtBQk8wOUNsQjhDNUM2cVZWb2QzZ3xBQ3Jtc0tsVXZxY0lVdUtjdnJIektXV2I3R2NSUVV4dkFQeG56MUhxMk1Qa3FRWmZkVWx6UUxFLVVqNzlBdVBQbUhPSlhBWmpCOWl4emtCWGhKLUhKZWlUYWJKTjM1empqMTdmeGtEcmd2WWdaeGtXbDc1bEpJTQ&q=https%3A%2F%2Fmirror2.openwrt.org%2Fsources%2Fcompat-wireless-2010-06-28.tar.bz2&v=FRO7bJXbmuw
DRIVER CLEAN WIFI https://mirror2.openwrt.org/sources/compat-wireless-2010-06-28.tar.bz2


---

# Erro no update do kali Erro Problem parsing dependendcy

	sudo mv /var/lib/apt/lists /var/lib/apt/lists-old
	sudo apt clean
	sudo apt update

# Aumentar o Swap em um Servidor Ubuntu

Para aumentar o espaço de swap em um servidor Ubuntu, siga os passos abaixo. Este guia assume que você quer criar ou expandir um arquivo de swap, o método mais comum no Ubuntu.

## 1. Verificar o Swap Atual
Confira quanto swap você já tem disponível:

```
sudo swapon --show
```

Se não houver swap ou ele for insuficiente, siga os próximos passos.

## 2. Desativar o Swap Existente (se houver)
Caso já exista um swap ativo, desative-o temporariamente:

```
sudo swapoff -a
```

## 3. Criar um Novo Arquivo de Swap
Defina o tamanho desejado. Por exemplo, para criar um arquivo de 4 GB:

```
sudo fallocate -l 4G /swapfile
```

Se o `fallocate` não estiver disponível, use:

```
sudo dd if=/dev/zero of=/swapfile bs=1M count=4096
```

## 4. Definir Permissões
Ajuste as permissões para segurança:

```
sudo chmod 600 /swapfile
```

## 5. Configurar o Arquivo como Swap
Formate o arquivo para uso como swap:

```
sudo mkswap /swapfile
```

## 6. Ativar o Swap
Habilite o novo swap:

```
sudo swapon /swapfile
```

## 7. Tornar Permanente
Para garantir que o swap persista após reinicializações, edite o arquivo `/etc/fstab`:

```
sudo nano /etc/fstab
```

Adicione a linha abaixo ao final do arquivo:

```
/swapfile none swap sw 0 0
```

Salve (Ctrl+O, Enter, Ctrl+X no nano).

## 8. Verificar Novamente
Confirme que o novo swap está ativo:

```
sudo swapon --show
```

Ou cheque a memória total:

```
free -h
```


## Técnica de prova estudo simulado

Cada questão, encontrar a alternativa correta, e justificar todas as outras alternativas.

## PACOTE QUEBRADO APT --fix-broken install

    apt clean
    apt autoclean
    apt install -f
