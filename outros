>> instalar o GUI no seu Raspberry Pi
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
    
    
    ========================================
   
>> DEPLOY RAPIDO DE UM SIEM WAZUH


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


