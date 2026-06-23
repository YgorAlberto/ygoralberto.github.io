## Guia para iniciantes em Cyber Security

Este guia é para quem está perdido, mas quer começar em Cyber Security com foco em **pentest, segurança ofensiva e red team**.

Antes de sair comprando curso, instalando Kali Linux ou decorando ferramenta, pare um pouco e responda:

- Eu gosto de entender como sistemas quebram?
- Tenho paciência para pesquisar, testar, errar, documentar e tentar de novo?
- Quero aprender redes, Linux, web, Windows e programação o suficiente para explorar falhas com responsabilidade?
- Consigo estudar de forma constante, mesmo sem resultado imediato?

Se a resposta for "sim", este guia pode te dar um caminho inicial. Se você quer outra área de Cyber Security, como blue team, GRC, forense, cloud security, AppSec defensivo ou privacidade, este não é o melhor roteiro principal para você.

Para uma visão mais ampla de várias áreas, veja também o [RoadMap do Arthur](https://github.com/arthurspk/guiadecybersecurity).

> Importante: pentest e red team devem ser praticados somente em ambientes próprios, laboratórios, CTFs ou com autorização formal. O objetivo aqui é formar base técnica e ética.

---

## Por onde começar

Se você está começando do zero, siga esta ordem:

1. Entenda o que é segurança ofensiva.
2. Aprenda os fundamentos de redes, sistemas e web.
3. Use Linux no dia a dia ou em uma máquina virtual.
4. Pratique em laboratórios guiados.
5. Monte anotações, relatórios e pequenos projetos.
6. Só depois aprofunde em ferramentas, exploração e Active Directory.

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

## Fundamentos essenciais

### 1. Redes de computadores

Você não precisa virar engenheiro de redes no início, mas precisa entender bem:

- TCP/IP, portas, protocolos e serviços.
- DNS, HTTP, HTTPS, SSH, FTP, SMB e SMTP.
- Roteamento, NAT, firewall e VPN.
- Modelo OSI e encapsulamento.
- Como usar `ping`, `traceroute`, `nslookup`, `dig`, `netstat`, `ss` e `tcpdump`.

Curso sugerido:

- [Curso de Redes](https://www.udemy.com/course/curso-gratuito-de-redes/)

### 2. Sistemas operacionais

Pentest exige conforto com Windows e Linux.

No Linux, aprenda:

- Terminal, permissões, processos, serviços e logs.
- Estrutura de diretórios.
- Gerenciamento de pacotes.
- Bash básico.
- Edição de arquivos com `nano`, `vim` ou outro editor.

No Windows, aprenda:

- Usuários, grupos e permissões.
- PowerShell básico.
- Serviços, registro, eventos e compartilhamentos.
- Conceitos iniciais de domínio e Active Directory.

Cursos sugeridos:

- [Curso de Linux](https://www.udemy.com/course/linux-ubuntu/)
- [Curso de Windows](https://www.udemy.com/course/curso-de-windows-10-completo)

### 3. Web

Grande parte das vagas e labs de pentest passam por aplicações web. Você precisa entender:

- Como uma requisição HTTP funciona.
- Métodos HTTP, headers, cookies, sessões e códigos de resposta.
- HTML, CSS e JavaScript no nível necessário para ler uma página.
- APIs, JSON e autenticação.
- Banco de dados e SQL básico.

Curso sugerido:

- [Web Fundamentos](https://www.udemy.com/course/curso-gratuito-de-html/)

### 4. Programação e automação

Você não precisa começar como dev, mas precisa conseguir ler e escrever scripts simples.

Priorize:

- Python básico.
- Bash básico.
- PowerShell básico.
- Git e GitHub.
- Leitura de código em JavaScript, PHP ou outra linguagem comum em aplicações web.

Objetivo inicial: automatizar tarefas pequenas, tratar arquivos, fazer requisições HTTP e entender scripts de exploração em laboratórios.

---

## Plano de estudo enxuto

Este plano é uma sugestão para quem quer estudar sem se perder. Adapte ao seu ritmo.

### Fase 1: Base técnica

Duração sugerida: 4 a 8 semanas.

Estude:

- Redes.
- Linux.
- Windows.
- Web básica.
- Git e terminal.

Pratique:

- Instale uma máquina virtual Linux.
- Faça comandos básicos todos os dias.
- Use Wireshark ou tcpdump para observar tráfego.
- Suba uma aplicação simples localmente e veja as requisições no navegador.

Meta da fase: conseguir explicar, com suas palavras, o que acontece quando você acessa um site.

### Fase 2: Introdução ao pentest

Duração sugerida: 4 a 8 semanas.

Estude:

- Metodologia de pentest.
- Reconhecimento e enumeração.
- Varredura de portas.
- Vulnerabilidades web comuns.
- Exploração em ambiente controlado.
- Escrita de relatório.

Pratique:

- Faça salas iniciantes no TryHackMe.
- Resolva máquinas fáceis com writeups depois da tentativa.
- Documente o passo a passo como se fosse entregar para alguém.

Meta da fase: conseguir fazer uma máquina iniciante entendendo o motivo de cada comando.

### Fase 3: Web, Linux e Windows com mais profundidade

Duração sugerida: 2 a 4 meses.

Estude:

- OWASP Top 10.
- Enumeração Linux.
- Enumeração Windows.
- Privesc básica.
- Serviços comuns: SMB, FTP, SSH, HTTP, bancos de dados.
- Noções de Active Directory.

Pratique:

- Labs de web vulnerável.
- Máquinas fáceis e intermediárias.
- Análise de writeups de pessoas experientes.
- Relatórios curtos com evidência, impacto e recomendação.

Meta da fase: deixar de apenas "seguir receita" e começar a criar hipóteses durante a enumeração.

### Fase 4: Portfólio e carreira

Duração sugerida: contínua.

Faça:

- Publique anotações e writeups permitidos.
- Monte um GitHub com scripts simples e estudos.
- Atualize seu LinkedIn.
- Faça networking com pessoas da área.
- Treine explicação técnica, não só execução de comando.

Meta da fase: mostrar evolução, raciocínio e consistência.

---

## Cursos gratuitos de Cyber

Comece por cursos introdutórios e escolha um por vez. Terminar um curso com prática vale mais do que abrir dez abas.

- [Introdução ao Pentest - DESEC](https://desecsecurity.com/cart/introducao-pentest/pentest)
- [Introdução a Cibersegurança - CISCO](https://www.netacad.com/courses/cybersecurity/introduction-cybersecurity)
- [Fundamentos em Cyber - eSecurity](https://esecurity.com.br/cursos/fundamentos-em-cyber-security/)
- [Cyber para iniciantes - EC-Council](https://www.eccouncil.org/cybersecurity-exchange/cyber-novice/free-cybersecurity-courses-beginners/)
- [Introdução ao Pentest - Solyd](https://solyd.com.br/treinamentos/introducao-ao-hacking-e-pentest-2/)
- [Introdução ao Pentest - ACADI](https://acaditi.com.br/essentials-series/)

---

## Cursos pagos

Cursos pagos podem acelerar o caminho, mas não substituem prática. Antes de comprar, confira a ementa, veja se o conteúdo é atualizado e procure relatos de alunos.

- [Trilha certificação DCPT - DESEC](https://desecsecurity.com/cart/DESECPRO1X)
- [Curso Pentester Cert. SYCP - Solyd](https://solyd.com.br/treinamentos/pentest-do-zero-ao-profissional-v2023/)
- [Pós em Cyber da ACADI](https://acaditi.com.br/pos-graduacao-em-ciberseguranca-ofensiva/)

Também vale pesquisar escolas como `FIAP`, `Crowsec`, `Pato Academy` e outras opções do mercado.

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

- [ ] Instalar Linux em VM ou usar WSL.
- [ ] Fazer um curso básico de redes.
- [ ] Aprender comandos essenciais de terminal.
- [ ] Estudar HTTP, DNS, portas e protocolos.
- [ ] Criar conta no TryHackMe.
- [ ] Fazer 5 salas iniciantes.
- [ ] Criar um arquivo de anotações.
- [ ] Publicar um resumo simples do que aprendeu.
- [ ] Atualizar o LinkedIn.
- [ ] Escolher o próximo tópico: web, Linux ou Windows.

---

## Caminho recomendado em uma frase

Aprenda fundamentos, pratique em laboratório, documente o raciocínio, aprofunde em web/Linux/Windows e avance para pentest/red team com ética, paciência e consistência.
