## Guia para iniciantes em Cyber Security

Este guia é para quem está perdido, mas quer começar em Cyber Security com foco em **pentest, segurança ofensiva e red team**.

Antes de sair comprando curso, instalando Kali Linux ou decorando ferramenta, pare um pouco e responda:

- Eu gosto de entender como sistemas quebram?
- Tenho paciência para pesquisar, testar, errar, documentar e tentar de novo?
- Quero aprender sistemas operacionais, redes, web e programação o suficiente para explorar falhas com responsabilidade?
- Consigo estudar de forma constante, mesmo sem resultado imediato?

Se a resposta for "sim", este guia pode te dar um caminho inicial. Se você quer outra área de Cyber Security, como blue team, GRC, forense, cloud security, AppSec defensivo ou privacidade, este não é o melhor roteiro principal para você.

Para uma visão mais ampla de várias áreas, veja também o [RoadMap do Arthur](https://github.com/arthurspk/guiadecybersecurity).

> Importante: pentest e red team devem ser praticados somente em ambientes próprios, laboratórios, CTFs ou com autorização formal. O objetivo aqui é formar base técnica e ética.

---

## Por onde começar

Se você está começando do zero, siga esta ordem:

1. Aprenda o básico de computador, arquivos, navegador e internet.
2. Entenda como sistemas operacionais funcionam.
3. Use Windows e Linux com mais consciência.
4. Aprenda redes, web e terminal.
5. Pratique em laboratórios guiados.
6. Monte anotações, relatórios e pequenos projetos.
7. Só depois aprofunde em ferramentas, exploração e Active Directory.

O erro mais comum é pular direto para ferramentas. Ferramenta sem fundamento vira tentativa e erro sem direção.

---

## Escolha sua direção primeiro

Cyber Security tem muitas trilhas. Algumas pessoas entram achando que querem "hackear", mas descobrem que gostam mais de defesa, governança, investigação ou cloud.

Use este filtro rápido:

- **Quero encontrar e explorar falhas:** siga neste guia, focado em pentest/red team.
- **Quero monitorar ataques e responder incidentes:** procure trilhas de blue team, SOC e incident response.
- **Quero trabalhar com políticas, risco e conformidade:** procure trilhas de GRC.
- **Quero investigar evidências e ataques depois que aconteceram:** procure trilhas de forense digital.
- **Quero proteger aplicações durante o desenvolvimento:** procure trilhas de AppSec e DevSecOps.
- **Quero proteger ambientes AWS, Azure ou Google Cloud:** procure trilhas de cloud security.

Se você ainda não sabe, estude os fundamentos abaixo por algumas semanas. Eles servem para quase toda área de Cyber.

---

## Trilha de estudo recomendada

### Fase 0: Nunca tive muito contato com computador

Para quem só sabe navegar na internet, usar redes sociais ou mexer no celular, este é o começo certo. Não pule esta fase por vergonha. Ela evita muita frustração depois.

Aprenda:

- O que é hardware e software.
- Como arquivos, pastas, extensões e downloads funcionam.
- Como instalar e remover programas.
- Como usar navegador, e-mail, busca e armazenamento em nuvem.
- Noções de segurança no uso diário: senha, autenticação em dois fatores, golpes e privacidade.
- Pacote Office ou ferramentas equivalentes.

Cursos e conteúdos gratuitos:

- [Cultura Digital - Fundação Bradesco](https://www.ev.org.br/cursos/cultura-digital)
- [Fundamentos de TI: Hardware e Software - Fundação Bradesco](https://www.ev.org.br/cursos/fundamentos-de-ti-hardware-e-software)
- [Computer Hardware Basics - Cisco NetAcad](https://www.netacad.com/courses/computer-hardware-basics)
- [Operating Systems Basics - Cisco NetAcad](https://www.netacad.com/courses/operating-systems-basics)
- [Pre Security - TryHackMe](https://tryhackme.com/path/outline/presecurity)

Quantidade mínima recomendada: faça **2 a 3 conteúdos gratuitos** desta fase antes de avançar. Se você já usa computador bem, pode fazer apenas o curso de sistemas operacionais da Cisco ou o de Fundamentos de TI da Fundação Bradesco como revisão.

Meta da fase: conseguir usar um computador sem medo, organizar arquivos, instalar programas, entender o que é um sistema operacional e explicar a diferença entre hardware e software.

---

### Fase 1: Sistemas operacionais primeiro

Para pentest/red team, sistemas operacionais vêm antes de ferramentas. Você precisa entender o ambiente onde tudo acontece: processos, arquivos, usuários, permissões, serviços, logs e comandos.

No Windows, aprenda:

- Usuários, grupos e permissões.
- Painel de controle, configurações, serviços e eventos.
- Compartilhamentos de rede.
- PowerShell básico.
- Conceitos iniciais de domínio e Active Directory.

No Linux, aprenda:

- Terminal e comandos essenciais.
- Estrutura de diretórios.
- Permissões, donos e grupos.
- Processos, serviços e logs.
- Gerenciamento de pacotes.
- Bash básico.

Cursos gratuitos:

- [Operating Systems Basics - Cisco NetAcad](https://www.netacad.com/courses/operating-systems-basics)
- [Fundamentos de TI: Hardware e Software - Fundação Bradesco](https://www.ev.org.br/cursos/fundamentos-de-ti-hardware-e-software)
- [OverTheWire Bandit](https://overthewire.org/wargames/bandit/) para treinar terminal Linux do absoluto básico.

Cursos pagos opcionais:

- [Curso de Windows](https://www.udemy.com/course/curso-de-windows-10-completo)
- [Curso de Linux](https://www.udemy.com/course/linux-ubuntu/)

Pratique:

- Instale Linux em uma máquina virtual ou use WSL.
- Crie, mova, copie e apague arquivos pelo terminal.
- Crie usuários locais no Windows e no Linux.
- Veja logs do sistema.
- Use `cd`, `ls`, `pwd`, `cat`, `grep`, `find`, `ip`, `ss`, `ps`, `chmod` e `sudo`.

Meta da fase: conseguir se movimentar em Windows e Linux entendendo o que está fazendo.

---

### Fase 2: Redes de computadores

Depois de entender sistemas operacionais, redes começam a fazer mais sentido. Pentest sem redes vira chute.

Aprenda:

- TCP/IP, portas, protocolos e serviços.
- DNS, HTTP, HTTPS, SSH, FTP, SMB e SMTP.
- IP, máscara, gateway, NAT, firewall e VPN.
- Modelo OSI e encapsulamento.
- Como usar `ping`, `traceroute`, `nslookup`, `dig`, `netstat`, `ss`, `tcpdump` e Wireshark.

Cursos gratuitos:

- [Networking Basics - Cisco NetAcad](https://www.netacad.com/courses/networking-basics)
- [Networking Devices and Initial Configuration - Cisco NetAcad](https://www.netacad.com/courses/networking-devices-and-initial-configuration)
- [Pre Security - TryHackMe](https://tryhackme.com/path/outline/presecurity), principalmente os módulos de Network Fundamentals.

Pratique:

- Descubra o IP da sua máquina.
- Entenda sua rede local.
- Use `ping` e `traceroute`.
- Observe tráfego com Wireshark.
- Faça pequenos mapas da sua rede doméstica.

Meta da fase: conseguir explicar o que acontece, em rede, quando você acessa um site.

---

### Fase 3: Web e programação básica

Grande parte das vagas e laboratórios de pentest passam por aplicações web. Você não precisa virar desenvolvedor agora, mas precisa entender como aplicações funcionam.

Aprenda web:

- Como uma requisição HTTP funciona.
- Métodos HTTP, headers, cookies, sessões e códigos de resposta.
- HTML, CSS e JavaScript no nível necessário para ler uma página.
- APIs, JSON e autenticação.
- Banco de dados e SQL básico.

Aprenda programação:

- Python básico.
- Bash básico.
- PowerShell básico.
- Git e GitHub.
- Leitura de código em JavaScript, PHP ou outra linguagem comum em aplicações web.

Cursos gratuitos:

- [Web Fundamentos](https://www.udemy.com/course/curso-gratuito-de-html/)
- [Crie um site simples usando HTML, CSS e JavaScript - Fundação Bradesco](https://www.ev.org.br/cursos/crie-um-site-simples-usando-html-css-e-javascript)
- [Web Security Academy - PortSwigger](https://portswigger.net/web-security), para quando já souber o básico de HTTP.

Pratique:

- Crie uma página HTML simples.
- Use o DevTools do navegador.
- Faça requisições e observe headers, cookies e respostas.
- Escreva scripts simples em Python para ler arquivos e fazer requisições HTTP.

Meta da fase: entender como uma aplicação web conversa com navegador, servidor e banco de dados.

---

### Fase 4: Introdução à Cyber e ao pentest

Aqui você começa a conectar fundamentos com segurança ofensiva. Ainda é começo, então o objetivo não é "invadir tudo", é aprender metodologia.

Aprenda:

- O que é segurança ofensiva.
- Ética, autorização e escopo.
- Metodologia de pentest.
- Reconhecimento e enumeração.
- Varredura de portas.
- Vulnerabilidades web comuns.
- Exploração em ambiente controlado.
- Escrita de relatório.

Cursos gratuitos:

- [Introdução à Cibersegurança - Cisco NetAcad](https://www.netacad.com/courses/introduction-to-cybersecurity)
- [Endpoint Security - Cisco NetAcad](https://www.netacad.com/courses/endpoint-security)
- [Network Defense - Cisco NetAcad](https://www.netacad.com/courses/network-defense)
- [Introdução ao Pentest - DESEC](https://desecsecurity.com/cart/introducao-pentest/pentest)
- [Cyber para iniciantes - EC-Council](https://www.eccouncil.org/cybersecurity-exchange/cyber-novice/free-cybersecurity-courses-beginners/)
- [Introdução ao Pentest - Solyd](https://solyd.com.br/cursos/introducao-ao-hacking-e-pentest-2/)
- [Introdução ao Pentest - ACADI](https://acaditi.com.br/essentials-series/)

Pratique:

- Faça salas iniciantes no TryHackMe.
- Resolva máquinas fáceis com writeups depois da tentativa.
- Documente o passo a passo como se fosse entregar para alguém.

Meta da fase: fazer uma máquina iniciante entendendo o motivo de cada comando.

---

### Fase 5: Pentest web, Linux, Windows e Active Directory

Agora você aprofunda nos temas que aparecem com frequência em pentest real e em laboratórios.

Aprenda:

- OWASP Top 10.
- Enumeração Linux.
- Enumeração Windows.
- Privesc básica.
- Serviços comuns: SMB, FTP, SSH, HTTP, bancos de dados.
- Noções de Active Directory.
- Uso de proxy web, fuzzing e exploração controlada.

Cursos e laboratórios gratuitos:

- [Web Security Academy - PortSwigger](https://portswigger.net/web-security)
- [Lista de máquinas gratuitas no TryHackMe](../THM-LIST)
- [Pre Security - TryHackMe](https://tryhackme.com/path/outline/presecurity)
- [Penetration Tester Path - HTB Academy](https://academy.hackthebox.com/path/preview/penetration-tester)
- [OverTheWire Bandit](https://overthewire.org/wargames/bandit/)

Cursos pagos opcionais:

- [Solyd One / SYCP](https://solyd.com.br/)
- [Trilha certificação DCPT - DESEC](https://desecsecurity.com/cart/DESECPRO1X)
- [Pós em Cyber da ACADI](https://acaditi.com.br/pos-graduacao-em-ciberseguranca-ofensiva/)

Também vale pesquisar escolas como `FIAP`, `Crowsec`, `Pato Academy` e outras opções do mercado.

Pratique:

- Labs de web vulnerável.
- Máquinas fáceis e intermediárias.
- Análise de writeups de pessoas experientes.
- Relatórios curtos com evidência, impacto e recomendação.

Meta da fase: deixar de apenas "seguir receita" e começar a criar hipóteses durante a enumeração.

---

### Fase 6: Portfólio e carreira

Esta fase é contínua. Não espere "terminar tudo" para começar a mostrar evolução.

Faça:

- Publique anotações e writeups permitidos.
- Monte um GitHub com scripts simples e estudos.
- Atualize seu LinkedIn.
- Faça networking com pessoas da área.
- Treine explicação técnica, não só execução de comando.
- Estude como se sair bem em entrevistas.

Conteúdos úteis:

- [Como Conseguir um Novo Emprego - Fundação Bradesco](https://www.ev.org.br/cursos/como-conseguir-um-novo-emprego)
- [IA para seu novo emprego: Do currículo à entrevista - Fundação Bradesco](https://www.ev.org.br/cursos/ia-para-seu-novo-emprego-do-curriculo-a-entrevista)

Meta da fase: mostrar evolução, raciocínio e consistência.

---

## Resumo de conteúdos gratuitos recomendados

Se você quer uma sequência objetiva e não exaustiva, faça nesta ordem:

1. [Cultura Digital - Fundação Bradesco](https://www.ev.org.br/cursos/cultura-digital)
2. [Fundamentos de TI: Hardware e Software - Fundação Bradesco](https://www.ev.org.br/cursos/fundamentos-de-ti-hardware-e-software)
3. [Operating Systems Basics - Cisco NetAcad](https://www.netacad.com/courses/operating-systems-basics)
4. [OverTheWire Bandit](https://overthewire.org/wargames/bandit/)
5. [Networking Basics - Cisco NetAcad](https://www.netacad.com/courses/networking-basics)
6. [Networking Devices and Initial Configuration - Cisco NetAcad](https://www.netacad.com/courses/networking-devices-and-initial-configuration)
7. [Crie um site simples usando HTML, CSS e JavaScript - Fundação Bradesco](https://www.ev.org.br/cursos/crie-um-site-simples-usando-html-css-e-javascript)
8. [Introdução à Cibersegurança - Cisco NetAcad](https://www.netacad.com/courses/introduction-to-cybersecurity)
9. [Introdução ao Pentest - DESEC](https://desecsecurity.com/cart/introducao-pentest/pentest)
10. [Web Security Academy - PortSwigger](https://portswigger.net/web-security)
11. [Pre Security - TryHackMe](https://tryhackme.com/path/outline/presecurity)

Quantidade sugerida: estes **11 conteúdos gratuitos** cobrem o início de computador, sistemas operacionais, redes, web, cyber e prática. Não precisa fazer tudo ao mesmo tempo. Faça por fase.

---

## Laboratórios e prática

Prática é onde o estudo começa a fazer sentido.

- [Lista de máquinas gratuitas no TryHackMe](../THM-LIST)
- TryHackMe para salas guiadas e trilhas iniciantes.
- Hack The Box Academy para fundamentos mais estruturados.
- PortSwigger Web Security Academy para segurança web.
- OverTheWire para Linux e lógica de terminal.
- DVWA, Juice Shop e Metasploitable para laboratório local.

Como praticar melhor:

- Tente antes de ver writeup.
- Anote tudo: hipótese, comando, resultado e próximo passo.
- Depois de resolver, refaça sem consultar.
- Escreva um resumo do que aprendeu.
- Separe comandos úteis por tema, mas entenda o que cada um faz.

---

## Ferramentas que você vai encontrar

Não tente dominar todas de uma vez. Aprenda conforme a necessidade.

- `nmap`: varredura e enumeração inicial.
- `Burp Suite`: análise e teste de aplicações web.
- `Wireshark`: análise de tráfego.
- `Gobuster` ou `ffuf`: descoberta de diretórios e arquivos.
- `Netcat`: conexões, testes e shells em laboratório.
- `Metasploit`: exploração e estudo de módulos conhecidos.
- `BloodHound`: análise de caminhos em Active Directory.
- `Impacket`: interação e exploração em ambientes Windows/AD.

O foco não é decorar ferramenta. O foco é entender o problema que ela ajuda a investigar.

---

## Conteúdos complementares

### Canais do YouTube

- [NetworkChuck](https://www.youtube.com/@NetworkChuck)
- [Gabriel Pato](https://www.youtube.com/@GabrielPato)

### Vídeos úteis

- [Docker Networking](https://www.youtube.com/watch?v=bKFMS5C4CG0)
- [Docker Containers](https://www.youtube.com/watch?v=eGz9DS-aIeY)
- [Load Balancing `cloudflare kemp freenom`](https://www.youtube.com/watch?v=LlbTSfc4biw)
- [ZeroTrust](https://www.youtube.com/watch?v=IYmXPF3XUwo)
- [Hospedar na DARKWEB](https://www.youtube.com/watch?v=CurcakgurRE)
- [DockerCompose `máquinas vulneráveis, WordPress e MySQL`](https://youtu.be/DM65_JyGxCo?si=dCfgQkA6EBKk26f_)
- [Ansible](https://youtu.be/5hycyr-8EKs?si=6dfufzOJn-RrmORt)
- [3 Levels of Wifi Hacking](https://www.youtube.com/watch?v=dZwbb42pdtg)
- [Hacking Commands You NEED to Know](https://www.youtube.com/watch?v=gL4j-a-g9pA)
- [Run your own AI (but private)](https://www.youtube.com/watch?v=WxYC9-hBM_g)

### Curso opcional

- [Wazuh no YouTube](https://www.youtube.com/watch?v=wT_z5fRnoXc&list=PLYwuH4Jfk8_Gzwsvf0irpB0baCBX4t4cB)

Wazuh é mais ligado a monitoramento e defesa, então trate como conteúdo complementar se você quiser entender o outro lado da segurança.

---

## LinkedIn, comunidade e empregabilidade

Invista tempo no LinkedIn desde o começo:

- Crie um perfil claro e profissional.
- Conecte-se com pessoas da área, recrutadores, empresas, líderes técnicos e comunidades.
- Curta e comente posts com intenção real, não só para aparecer.
- Publique o que está estudando, suas anotações e aprendizados.
- Mostre evolução com pequenos projetos, labs e resumos.
- Estude como se sair bem em entrevistas.

Para vagas iniciais, saber se comunicar pesa muito. Aprenda a explicar:

- O que você testou.
- Como encontrou o problema.
- Qual é o impacto.
- Como corrigir.
- Quais foram suas limitações durante o teste.

---

## Checklist do primeiro mês

Use este checklist para sair da inércia:

- [ ] Fazer 1 curso de cultura digital ou fundamentos de TI.
- [ ] Fazer 1 curso de sistemas operacionais.
- [ ] Instalar Linux em VM ou usar WSL.
- [ ] Aprender comandos essenciais de terminal.
- [ ] Fazer 1 curso básico de redes.
- [ ] Estudar HTTP, DNS, portas e protocolos.
- [ ] Criar conta no TryHackMe.
- [ ] Fazer 3 a 5 salas iniciantes.
- [ ] Criar um arquivo de anotações.
- [ ] Publicar um resumo simples do que aprendeu.
- [ ] Atualizar o LinkedIn.
- [ ] Escolher o próximo tópico: Linux, redes ou web.

---

## Caminho recomendado em uma frase

Aprenda computador e sistemas operacionais primeiro, depois redes e web, pratique em laboratório, documente o raciocínio e avance para pentest/red team com ética, paciência e consistência.
