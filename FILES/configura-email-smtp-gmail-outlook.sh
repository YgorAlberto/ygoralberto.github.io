#!/bin/bash
# ==============================================================================
# CONFIGURAÇÃO DE E-MAIL EM CLI - KALI LINUX (UNIFICADO)
# Suporta: Google Workspace/Gmail e Microsoft 365/Outlook
# Protocols: Outgoing SMTP (Port 587 TLS) & Incoming IMAP (Port 993 SSL)
# ==============================================================================

clear
echo "=================================================================="
echo "    CONFIGURADOR DE E-MAIL VIA TERMINAL (KALI LINUX)             "
echo "=================================================================="
echo ""
echo "Selecione o provedor do seu e-mail:"
echo "1) Google Workspace / Gmail"
echo "2) Microsoft 365 / Outlook"
echo ""
read -p "Digite a opção desejada (1 ou 2): " PROVEDOR_OPCAO

# Validação da escolha do provedor
if [ "$PROVEDOR_OPCAO" = "1" ]; then
    PROVEDOR="Google"
    SMTP_HOST="://gmail.com"
    IMAP_HOST="://gmail.com"
elif [ "$PROVEDOR_OPCAO" = "2" ]; then
    PROVEDOR="Microsoft"
    SMTP_HOST="://office365.com"
    IMAP_HOST="://office365.com"
else
    echo "[-] Opção inválida. Encerrando o script."
    exit 1
fi

echo ""
echo "[*] Configurando ambiente para: $PROVEDOR"
echo "------------------------------------------------------------------"
read -p "Digite seu e-mail completo (ex: nome@mailsp.com.br): " EMAIL
read -s -p "Digite sua Senha de Aplicativo (App Password - sem espaços): " APP_PASSWORD
echo "" # Apenas pula uma linha após a senha oculta

# Validação básica de preenchimento
if [ -z "$EMAIL" ] || [ -z "$APP_PASSWORD" ]; then
    echo "[-] Erro: E-mail e senha não podem estar vazios."
    exit 1
fi

echo ""
echo "[*] 1/4 Atualizando repositórios e instalando utilitários (msmtp, getmail6, mutt)..."
sudo apt update && sudo apt install msmtp msmtp-mta getmail6 mutt -y

echo "[*] 2/4 Criando estruturas de diretórios locais para armazenamento de e-mails..."
mkdir -p ~/.getmail
mkdir -p ~/Mail/{cur,new,tmp}

echo "[*] 3/4 Gerando arquivo de configuração de envio (~/.msmtprc)..."
cat << EOF > ~/.msmtprc
defaults
auth             on
tls              on
tls_trust_file   /etc/ssl/certs/ca-certificates.crt
logfile          ~/.msmtp.log

account          default
host             $SMTP_HOST
port             587
from             $EMAIL
user             $EMAIL
password         $APP_PASSWORD
EOF

# Aplicando permissão restrita de segurança exigida pelo msmtp
chmod 600 ~/.msmtprc

echo "[*] 4/4 Gerando arquivo de configuração de recebimento (~/.getmail/getmailrc)..."
cat << EOF > ~/.getmail/getmailrc
[options]
verbose = 1
read_all = false
delete = false

[retriever]
type = SimpleIMAPSSLRetriever
server = $IMAP_HOST
port = 993
username = $EMAIL
password = $APP_PASSWORD

[destination]
type = Maildir
path = ~/Mail/
EOF

clear
echo "=================================================================="
echo "    [+] AMBIENTE CONFIGURADO COM SUCESSO!                        "
echo "=================================================================="
echo ""
echo "COMO CAPTURAR E LER SEUS E-MAILS AGORA:"
echo ""
echo "1. Para CAPTURAR/BAIXAR todos os novos e-mails do servidor:"
echo "   Execute o comando abaixo no seu terminal:"
echo "   👉 getmail"
echo ""
echo "2. Para LER os e-mails baixados localmente:"
echo "   Abra a interface visual do terminal usando o comando:"
echo "   👉 mutt -f ~/Mail"
echo ""
echo "------------------------------------------------------------------"
echo "DENTRO DA INTERFACE DO MUTT:"
echo " • Use as setas do teclado (Seta para Cima / Baixo) para navegar."
echo " • Pressione [Enter] para abrir e ler o e-mail selecionado."
echo " • Pressione [i] para fechar o e-mail e voltar para a lista."
echo " • Pressione [q] para sair do Mutt."
echo "=================================================================="
