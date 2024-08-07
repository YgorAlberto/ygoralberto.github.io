#!/usr/bin/env bash

# Descomentar as 2 linhas abaixo para entrar em modo debug
#set -x
#trap read debug

# Busca caminho do home do usuário
# HOME_USUARIO=$(xdg-user-dir)

#Cores 
#vermelho="\e[00;31mVERMELHO\e[00m"
#verde="\e[00;32mVERDE\e[00m"
#pisca-vermelho="\033[5;30mPiscando\033[0m"


# Exemplos:
# Configs de REDE
##PLACAREDE='enp0s3'
##MEUIP='192.168.0.50/24'
##OSTNAME='aula.local'
##SERVERIP='192.168.0.50'
##GRUPOAD='SERVIDORESLINUX'
##GATEWAY='192.168.0.1'

#Bem vindo ao script
echo -e "\e[00;32m#############################################################################################
##  Bem vindo ao script de instalação do ActiveDirectory desenvolvido por Harrison Mattos  ##
#############################################################################################\e[00m"

echo -e "A seguir faremos a instalação da biblioteca que integra o AD ao linux!"
read -p "Deseja prosseguir com a instalação? [ y / n ]: " BEMVINDO

if [[ $BEMVINDO != y ]]; then
    echo -e "\e[00;31mEncerrando sem modifições\e[00m"
    exit
fi

# Testa se existem atualizações em andamento
if lsof /var/lib/dpkg/lock 2> /dev/null | grep '(apt|dpkg)'; then
  echo -e "\e[00;31mO computador iniciou a atualização automática em segundo plano, aguarde alguns minutos e tente novamente!\e[00m"
  exit
fi

#Verifica qual sua interface de rede
for i in $( ifconfig | grep eth | cut -d ":" -f1 ); do
    # Pega o nome da interface de rede usada atualmente.
    INTERFACE=$i
done

for i in $( ifconfig | grep enp0 | cut -d ":" -f1 ); do
    # Pega o nome da interface de rede usada atualmente.
    INTERFACE=$i
done

# Pergunta se deseja ip fixo ou dhcp
echo -e "\e[00;31m###############################################################################################################################
##  O script configura o ip fixo pelo NETPLAN, se caso não utilize poderá prosseguir a instalação configurando manualmente!  ##
###############################################################################################################################\e[00m"
read -p "Deseja configurar IP FIXO [ y / n ]: " perg1


    # Verifica se foi inserido fixo
    if [[ $perg1 == y ]]; then

      #Verifica se pode fixar ip pelo netplan
      if [ -f /etc/netplan/00-installer-config.yaml ]; then

        #Pergunta se deseja fazer backup das configs de rede antigas
        read -p "Fazer backup das configs de rede? (Será gerado um arquivo 00-installer-config.yaml.bkp) [ y / n ]: " BACKUP

        if [[ $BACKUP == y ]]; then
          #Cria um backup do netplan
          cp -a /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.bkp

          if [ -f /etc/netplan/00-installer-config.yaml.bkp ]; then
            echo -e "\e[00;32mArquivo de backup criado com sucesso\e[00m"
          else
            echo -e "\e[00;31mArquivo de backup com erro\e[00m"
            read -p "Deseja prosseguir sem fazer backup? [ y / n ]: " ERROBACKUP

            if [[ $ERROBACKUP != y ]]; then
              echo -e "\e[00;31mEncerrando sem modifições\e[00m"
              exit
            fi
          fi

        fi

        #echo "Nome da placa de rede: [enp0s3] Verificar digitando: ip a"
        read -p "Nome da placa de rede: [$INTERFACE]: " PLACAREDE

        #echo "Digite seu ip: [192.168.0.12/24]"
        read -p "Digite seu ip [192.168.0.12/24]: " MEUIP

        #echo "Digite o HOSTNAME: [aula.local]"
        read -p "Digite o HOSTNAME [aula.local]: " HOSTNAME

        #echo "Digite o ip do servidor ActiveDirectory: [192.168.0.200]"
        read -p "Digite o ip do servidor ActiveDirectory [192.168.0.200]: " SERVERIP

        #echo "Digite o nome do dominio: [SERVIDORESLINUX]"
        read -p "Digite o nome do dominio [SERVIDORESLINUX]: " GRUPOAD

        #echo "Digite o GATEWAY : [192.168.0.1]"
        read -p "Digite o GATEWAY [192.168.0.1]: " GATEWAY

        #echo "Concluir a configuração de ip fixo? [y / n]"
        read -p "Concluir a configuração de ip fixo? [ y / n ]: " CORRETO

        # Pergunta se deseja concluir a configuracao inserido, dando mais uma chance de nao inserir dados errados
        if [[ $CORRETO != y ]]; then
          echo -e "\e[00;31mEncerrando sem modifições\e[00m"
          exit
        fi

#Seta Ip Fixo no netplan
cat <<EOF | tee /etc/netplan/00-installer-config.yaml
  network:
    version: 2
    renderer: networkd
    ethernets:
      $PLACAREDE:
        addresses: [$MEUIP]
        nameservers:
          search: [$HOSTNAME]
          addresses: [$SERVERIP]
        routes:
          - to: default
            via: $GATEWAY
EOF

      #Atualiza o netplan
      netplan apply

        else
              #Pergunta se deseja seguir sem fixar ip
              echo -e "\e[00;31mArquivo de configuração do netplan não encontrado!\e[00m"
              read -p "Deseja prosseguir com a instalação sem fixar ip? [ y / n ]: " NAOENCONTRADO  
              if [[ $NAOENCONTRADO != y ]]; then
                echo -e "\e[00;31mEncerrando sem modifições\e[00m"
                exit
              fi
          fi
    
    #else
      
      # Verifica se não foi inserido y
      #if [[ $perg1 != y ]]; then
      #  echo -e "\e[00;31mEncerrando sem modifições\e[00m"
      # exit
      #fi

    fi
    

#Solicita grupo com permissao
#echo "Configure o grupo do AD que tem permissão para logar via ssh: [aula\SERVIDORESLINUX]"
read -r -p "Configure o grupo do AD que tem permissão para logar via ssh [aula\SERVIDORESLINUX]: " GRUPOADPERM


# Testa conexão com repositório do Ubuntu
if { apt-get update 2>&1 || echo E: update failed; } | grep -q '^[WE]:'; then
  echo -e "\e[00;31mNão foi possível conectar com o repositório, verifique sua conexão com a internet\e[00m"
  exit
fi

# Atualiza o sistema
apt update && apt upgrade -y
apt autoremove -y

#Seta Data de São paulo
timedatectl set-timezone America/Sao_Paulo

# Instala ferramentas padroes
apt install vim htop ssh net-tools wget inetutils-tools -y


#### Link GITHUB https://github.com/BeyondTrust/pbis-open/releases ####

if [ -f ./pbis-open-9.1.0.551.linux.x86_64.deb.sh ]; then
  echo -e "\e[00;32mUtilizando o arquivo de binario já baixado!\e[00m"
else
  #Baixa a biblioteca do Pbis
  wget https://github.com/BeyondTrust/pbis-open/releases/download/9.1.0/pbis-open-9.1.0.551.linux.x86_64.deb.sh

  #Troca a permissao do arquivo
  chmod 700 pbis-open-9.1.0.551.linux.x86_64.deb.sh
fi

#Instala a biblioteca do Pbis
./pbis-open-9.1.0.551.linux.x86_64.deb.sh

#Entra na pasta do binario
cd /opt/pbis/bin/

#Cria o arquivo txt do regshell
touch modifica-regshell.txt

#Insere os sets do regshell
cat <<EOF | tee modifica-regshell.txt
cd HKEY_THIS_MACHINE\Services\lsass\Parameters\Providers\ActiveDirectory
set_value LoginShellTemplate /bin/bash
set_value AssumeDefaultDomain 1
set_value RequireMembershipOf $GRUPOADPERM
exit
EOF

#Chama o binario passando por parametro um arquivo txt com os sets
./regshell --file modifica-regshell.txt

#Restarta o lWSMD
systemctl restart lwsmd

#Inicia o servidor passando alguns parametros
/opt/pbis/bin/domainjoin-cli join --ou $GRUPOAD $HOSTNAME administrator