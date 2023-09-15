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

tail -f - Comando para ver o arquivo com atualização em tempo real

tar -xvjf - Descompacta arquivo .tar.bz2

tar -xf arquivo.tar.zx Descompactar arquivo tar.zx

uname -a - Mostra o Sistema Operacional Rodando

sudo nano /etc/hostname - Trocar nome da maquina

- Gerenciamento de Usuários no lunux - add - copyuser - del user - change pass - shell

      useradd newuser
      useradd -m copycurruser
      deluser newuser
      sudo passwd newuser
      sudo chsh -s /bin/bash newuser
      sudo useradd -m -d /home/newuser newuser
      sudo usermod -d /home/newuser -m newuser
      sudo usermod -aG group newuser

- Gerenciamento de interfaces de rede network interfaces

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

Linux Bootable sudo dd bs=4M if=ImageName.iso of=/dev/sdc conv=fdatasync status=progress

    VBoxManage internalcommands sethduuid image.vdi

Trocar UUID VDI VirtualBox Image

    Acessar os discos e ir em -> release -> remove e add o disco novamente

Resolver problema de UUID em VirtualBox.xml

	sudo nano /etc/rc.local
	openvpn --config /caminho/para/seuarquivo.ovpn &

Manter o openvpn conectado mesmo se o dispositivo desconectar ou reiniciar (Adicionar a segunda linha ANTES do EXIT)

fdisk -l Lista os discos existentes no dispositivo

fdisk /dev/sda Seleciona o disco (P lista info do disco, D deleta uma partição, W escreve as alterações)

wipe /dev/sda1 Limpa o disco informado

sudo mkfs.ext4 /dev/sda1 Formatar disco informado no comando

sudo mount /dev/sda1 /mnt/Disco Montar disco formatado ou desmontado

mount -t cifs //145.65.89.12\folder\ \mnt\local\pc -o user=<USUARIO>,password=<SENHA>,domain=<DOMINIO> Montar disco compartilhado no domínio

    Compartilhamento no LINUX

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

echo "blacklist floppy" | sudo tee /etc/modprobe.d/blacklist-floppy.conf

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

## COMANDOS WINDOWS

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

Passo 3

    Trocar o nome do servidor, nome do projeto e descrição do projeto
        Em sv_hostname “Coloque o nome de preferência”
        Em sets sv_projectName “Coloque o nome do servidor do projeto”
        Em sets sv_projectDesc “Escreva a descrição do projeto”

Passo 4

    Instalar o banco de dados MySql > 5.1
    Criar usuário e senha para o banco:

Comando do Mysql para criar o usuário e dar permissão:

    Criar um banco de dados com o nome zirix:
    O aquivo de conf do db fica no caminho vrp>modules>db.lua
    create user 'username'@'localhost' identified by 'senha123';
    GRANT ALL PRIVILEGES ON *.* TO 'username'@'localhost' WITH GRANT OPTION;
    GRANT ALL PRIVILEGES ON database_name. * TO 'username'@'localhost';
    alter user 'root'@'localhost' identified with mysql_native_password by 'root';

Alternativa

Comando para criar o banco de dados usando o aquivo.sql:

    mysql --host=localhost --user=root --password= -e "zirix.sql"
        Se não funcionar, acessa o mysql...
    source /home/server-data/vrpex-zirix-v2/zirix-data/zirix.sql

String de conexão do FIVEM Server com o banco de dados local:

    set mysql_connection_string "server=127.0.0.1;database=DBNAME;userid=USERNAME;password=p@ssw0rd;persistsecurityinfo=true;"


Passos seguintes:

Tirar a necessidade da steam  para entrar na City

    Resources/[VRP]/vrp/queue.lua -> Setar requireSteam para FALSE

Commands:
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


## SETUP ANDROID VISTUALBOX

[Donload OVA](https://www.osboxes.org/android-x86/)

Create a MACHINE using the VDI image downloaded

If it is on CLI mode, try this:
	Turn it OFF, an go Settings -> Display -> graphic controller set to -> VBoxVGA. Turn off Enable 3D Acceleration.
