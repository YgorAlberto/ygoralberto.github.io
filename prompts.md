## Prompt Relatorio STR

Finalizei um pentest e preciso agora do relatório.\
Vamos confeccionar um relatório de pentest.\
Agora voce é um especialista em cibersegurança e em redação de vulnerabilidade e explicação das mesmas.\
Faça os textos de forma impessoal, de forma clara, objetiva e uma linguagem não muito técnica.\
Pode inserir detalhes adicionais. Porém apenas textos em forma de parágrafos, não insira parametros, parte de codigo, comando, imagem, a menos que seja mencionado na descição fornecida.\
Os textos devem começar com: Identificado, analisado, verificado e etc. Deve estar nesse tempo verbal\
A redação deve seguir a estrutura fielmente ao relato inserido sobre a vulnerabilidade\
A legenda das imagens já estão no padrão\
Os textos abaixo das legendas são parágrafos e nao devem fazer parte da lagenda.

Etapa 1 (rel técnico)\
Tabela linha 1: Calculo CVSS juntamente com seu código: ex.  CVSS 3.1 Vector AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N\
Tabela linha 2: CWE completo: Ex.  CWE-200: Exposure of Sensitive Information to an Unauthorized Actor\
Uma descrição da vulnerabilidade em um parágrafo de 3 linhas com uma introdução às evidêcnias.\
Farei a menção de cada print, deixe o campo reservado para o print com a sua legenda, podendo ser explicação ou comando
no fim da vulnerabilidade uma Recomendação da vulnerabilidade em um parágrafo de 3 linhas juntamente com links, caso haja.\

Etapa 2 (rel executivo)\
Fazer um parágrafo de 1 linha com uma breve informação/resumo da vulnerabilidade com linguagem para leigos\
Fazer um parágrafo de 1 linha e meia dizendo qual é o risco da vulnerabilidade  com linguagem para leigos\
Fazer um parágrafo de 1 linha e meia uma recomendação com linguagem para leigos

Esse é o texto da vulnerabilidade:

## Prompt Relatorio DFS

Vamos confeccionar um relatório de pentest. São 5 vulnerabilidades.\
Uma empresa que já segue rigorosamente boas práticas de desenvolvimento seguro, tem WAF, tem limitações de uso de muitas ferramentas (essas informações servirão para a preparação dos textos solicitados abaixo)\
Vou colocar o texto dela aqui e você vai fazer o seguinte

Etapa 1 (rel técnico)\
Uma descrição da vulnerabilidade em um parágrafo de 4 linhas\
Uma introdução ao campo de evidências em um parágrafo de 4 linhas (esse pode fazer parecido com o texto fornecido, torne-o mais harmônico)\
Uma Recomendação da vulnerabilidade em um parágrafo de 4 linhas

Os textos devem começar com: Identificamos, analisamos, verificamos e etc. Deve estar nesse tempo verbal

Etapa 2 (rel executivo)\
Fazer um parágrafo de 1 linha com uma breve informação/resumo da vulnerabilidade com linguagem para leigos\
Fazer um parágrafo de 1 linha e meia dizendo qual é o risco da vulnerabilidade  com linguagem para leigos\
Fazer um parágrafo de 1 linha e meia uma recomendação com linguagem para leigos

Esse é o texto da vulnerabilidade:

## PROMPT GERADOR DE SENHA

Irei fornecer uma lista de palabras para que voce gere novas combinações baseadas nas palavras fornecida
As combinações podem ser
suibstutuir caracteres especiais
adicionar caracteres especiais
incrementar uns 3 numeros
decrementar uns 3 numeros
Inciar com maiuscula

Nao precisa fazer todas essas coombinaçoes em cada palabra fornecida, mas faça uma análise na palavra e altere de forma inteligente os caracteres que façam sentido. A alteração pode ser agressiva ou simplificada, as palabras geradas nao precisam ser muito grandes

Gere 200 combinações...


## PROMPT LOGIN CHECKER

Leia atentamente a cada solicitação abaixo e faça uma dupla verificação ponto a ponto abordado, não hesite em fazer melorias no código.
Eu sou pentester e preciso fazer um script em python
Usando selenium no navegador firefox em GUIA ANONIMA para validação de logins e senhas de uma pagina.
Esquema do script: bird-leak-checker.py -u https://sub.domain.com/login -l login.txt -p pass.txt -T 4 -t 3 -s 10 --pitchfork --headless

Legenda dos parâmetros acima
-u é o parametro da URL
-l é a lista de login
--login passa uma string para teste de um usuario apenas
-p é a lista de passwords
--password passa string de teste de um password apenas
-Tlogin (em segundos) é o tempo de cada tentativa de login (padrão é 1)
-s (em segundos) é o tempo de espera para pegar a resposta da tentativa de login (padrão é 1)
-T (em segundos) é o tempo de espera para carregamento da página (padrão é 3)
--pitchfork é o modo de tentes de senha, sendo login1 com o pass1, login2 com o pass2 e assim por diante
--clusterbomb é o modo de testes de credenciais, sendo login1 com senha1, login1 com senha2 até finalizar a lista com todas as combinações
--headless para funcionar em modo headless, caso nao esteja com o parametro presente, vai funcionar normalmente abrindo o navegador

Obs.: Todos os parâmetros devem aceitar e interpretar aspas duplas para nomes com espaços ou caracteres especiais e sempre PRIORIZAR o que foi passado por parâmetro. Os parâmetros SOBREPÕE a detecção automatica individual.

Este script deve:
1 Entrar na url passada por parametro 

2 Abrir o codigo da página de login lendo todo codigo fonte (html e js) capturando os campos de formularios, botoes

3 capturar os campos, após a análise de codigo anterior, de LOGIN e SENHA e o Botão de login. O script deve ser inteligente o suficiente para se adaptar a vários tipos de paginas e codigos, para capturar o formulario em qualquer tipo como (type, name, ID com os mais diversos tipos de possiveis nomes) e o botão

4 Ao identificar os campos login, senha e botão, fazer uma tentativa de login passando credenciais propositalmente erradas como 01234567890:123321123456 e exemplo@test.mail:Senha@t3ste26.

5 Após as duas tentativas, capturar a resposta da página (testada com credenciais erradas acima) com a mensagem de erro de login da aplicação. O script deve ser inteligente o suficiente para capturar das mais diversas respostas de tentativas de logins como redirecionamento, alert, mensagem no HTML dentro de DIV, ALERT,SPAM, mensagens vinda de um codigo JS, Modal etc. Veja o exemplo abaixo para implementar validações iguais e semelhantes de form genérica.

6 Exemplos de respostas de erros de credenciais
EXEMPLO 1 - <div><div class="css-18ouhwa" aria-label="Alert warning"><div class="css-3p6jzl"><div class="css-1vzus6i-Icon"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" class="css-sr6nr"><path d="M12,16a1,1,0,1,0,1,1A1,1,0,0,0,12,16Zm10.67,1.47-8.05-14a3,3,0,0,0-5.24,0l-8,14A3,3,0,0,0,3.94,22H20.06a3,3,0,0,0,2.61-4.53Zm-1.73,2a1,1,0,0,1-.88.51H3.94a1,1,0,0,1-.88-.51,1,1,0,0,1,0-1l8-14a1,1,0,0,1,1.78,0l8.05,14A1,1,0,0,1,20.94,19.49ZM12,8a1,1,0,0,0-1,1v4a1,1,0,0,0,2,0V9A1,1,0,0,0,12,8Z"></path></svg></div></div><div class="css-1r4ghwz"><div class="css-y7do1i">Invalid username or password</div></div><button type="button" class="css-h4yrrc"><div class="css-1vzus6i-Icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor" class="css-sr6nr"><path d="M13.41,12l4.3-4.29a1,1,0,1,0-1.42-1.42L12,10.59,7.71,6.29A1,1,0,0,0,6.29,7.71L10.59,12l-4.3,4.29a1,1,0,0,0,0,1.42,1,1,0,0,0,1.42,0L12,13.41l4.29,4.3a1,1,0,0,0,1.42,0,1,1,0,0,0,0-1.42Z"></path></svg></div></button></div></div>

EXEMPLO 2 - <div class="Vue-Toastification__container top-right"><div class="Vue-Toastification__toast Vue-Toastification__toast--default top-right" style=""><!----> <div role="alert" class="Vue-Toastification__toast-component-body"><div data-v-55dd3057="" class="toastification" toast-id="2"><div data-v-55dd3057="" class="d-flex align-items-start"><span data-v-55dd3057="" class="b-avatar mr-75 flex-shrink-0 badge-danger rounded-circle" style="width: 1.8rem; height: 1.8rem;"><span class="b-avatar-custom"><svg data-v-55dd3057="" xmlns="http://www.w3.org/2000/svg" width="15px" height="15px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-edit"><path data-v-55dd3057="" d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path data-v-55dd3057="" d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg></span><!----></span><div data-v-55dd3057="" class="d-flex flex-grow-1"><div data-v-55dd3057=""><h5 data-v-55dd3057="" class="mb-0 font-weight-bolder toastification-title text-danger">Credenciais Inválidas</h5><!----></div><span data-v-55dd3057="" class="cursor-pointer toastification-close-icon ml-auto "><svg data-v-55dd3057="" xmlns="http://www.w3.org/2000/svg" width="14px" height="14px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-body feather feather-x"><line data-v-55dd3057="" x1="18" y1="6" x2="6" y2="18"></line><line data-v-55dd3057="" x1="6" y1="6" x2="18" y2="18"></line></svg></span></div></div></div></div> <!----> <div class="Vue-Toastification__progress-bar" style="animation-duration: 3000ms; animation-play-state: paused; opacity: 0;"></div></div></div>

EXEMPLO 3 - <div class="alert alert-danger alert-dismissable" id="notification-danger-main">
    <button type="button" class="close" data-dismiss="alert" aria-hidden="true">×</button>
    <strong>Ooops!:</strong> O endereço de e-mail asdasdasd@qwed.as não foi encontrado.
</div>

EXEMPLO 4 - <div class="content error-tips-content"><span id="errorContent">A senha está incorreta, favor inserir novamente.</span></div>

EXEMPLO 5 - <fieldset class="error type-password"><i class="fal fa-key"></i> <input type="password" name="senha" id="senha" placeholder="Sua senha:" value=""></fieldset>

7 TODAS as mensagens DEVEM ser capturadas da resposta de login, E devem ser inseridas no arquivo de log-full.txt, contendo, o login:password:message-erro:erro_aqui. Mesmo as que tiveram sucesso de login

8 Após esta análise, o script deve, se com sucesso seguir com os testes com a lista de login e senhas fornecido. Ou retornar dizendo que não conseguiu identificar todos os campos e botões e solicitar ao pentester que informe por prâmetro as informações não identificadas.

9 Quando a credenciai for identificada como correta, baseado no que for identificado automaticamente ou por parâmetro, GRAVAR no LOG a CREDENCIAL que teve SEUCESSO e limpar toda a janela, limpa cookies e sessoes ativas para GARANTIR que os testes posteriores NÃO reutilizem as sessões já autenticadas.

10 Caso o script NÃO identifique os campos de login e/ou senha, deve SOLICITAR ao pentester para passar por parametro os campos de login e os campos de senha, usando: -Lid, -Lname, -Ltype e -Pid, -Pname, -Ptype e -Bid -Bname -Btype, -Rclass informando os campos que devem ser inserido o login e a senha e o botão e a mensagem de erro. Coloque um botão opicional antes de cada abertura da URL, simulando um clique antes de entrar na pagina de login usando o parametro B1class, B1type, B1name, B1id. Todos os parâmetros devem aceitar e interpretar aspas duplas para nomes com espaços ou caracteres especiais. 

Legendas e orientações de cada botão mencionado no item 10
-Lid é o campo de login do tipo ID
-Lname é o campo de login do tipo name
-Ltype é o campo de login do tipo type
-Lclass é o campo de login do tipo class
-Pid é o campo de pass do tipo ID
-Pname é o campo de pass do tipo name
-Ptype é o campo de pass do tipo type
-Pclass é o campo de pass do tipo class
-Bid é o campo de botão do tipo ID
-Bname é o campo de botão do tipo name
-Btype é o campo de botão do tipo type
-Bclass é o campo de botao do tipo class
-B1id é o campo de botão1 do tipo ID
-B1name é o campo de botão1 do tipo name
-B1type é o campo de botão1 do tipo type
-B1class é o campo de botao1 do tipo class
-Rclass é o campo da DIV que contém a resposta da tentativa de login

Algumas regras adicionais:

1 Faça um parametro com --help que informe todos os parametros e como usa-los

3 O script deve informar no terminal:
Logs precisos de cada ação, identificação, automação
A credencial que esta testando e o resultado da credencial no formato LOGIN:SENHA:MENSAGEM
Colorir as informaçoes para melhor visualização

Consideração final, para ser feita durante toda a construção do script
Revalidar o script e verificar a robustez da detecção do campo de login, campo de senha, botão de entrar, resposta de tentativa de login
Faça um doublecheck de todas as funcionalidades e ja implemente melhorias no codigo de modo que seja o mais robusto, customizavel e inteligente possivel. Use todos os conhecimentos para a implementação. Antes de concluir, faça uma dupla verificação de cada pensamento, codigo, fucionalidade. Tudo ser analisado de diferentes perspectivas para ser o mais robusto possível.

## SCRIPT BIRD CRAFT

Sou pentester, atuo de forma ética e autorizada e preciso criar uma ferramenta
Atue como um especialista em Segurança Ofensiva e desenvolva a lógica de busca para um script de análise estática de código-fonte web
Faça um doublecheck de todas as funcionalidades e ja implemente as melhorias no codigo de modo que seja o mais robusto, customizavel e inteligente possivel. Use todos os conhecimentos para a implementação. Antes de concluir, faça uma dupla verificação de cada pensamento, codigo, fucionalidade. Tudo ser analisado de diferentes perspectivas para ser o mais robusto possível.
Vamos criar uma ferramenta, que acesse a URL informada e faça a leitura de todo o conteúdo da página

Estrutura: python3 bird-craftjs.py URL.txt (o arquuio terá em cada linha o seguinte formato de url, podendo sofrer variações: http://dominio.aqui/pagina/pagina.extensao

O script deve:
1 Validar a URL se ela realmente existe (com 7 threads)
2 Após validar as URLs, acessar o as URLs válidas e ler todo o código donte (da forma mais precisa e aprecida com um acesso legítimo de um navegador, como se fosse um humano)
3 Verificar se existe outras URLs dentro das páginas que estejam dentro do escopo, e adicionar à lista e refazer a verificação completa do script
4 Ao ler todo o conteúdo do código fonte das páginas informadas, o scrip deve procurar por termos interessantes do ponto de vista de pentest
5 O script deve extrair todos os conteúdos interessantes como:
Infraestrutura e Conectividade:
    Connection Strings (DSN): URLs completas de banco de dados (ex: jdbc:mysql://..., postgres://...) que revelam usuários, nomes de bases e estrutura interna.
    Nomes de Buckets/Blobs: Nomes de repositórios de armazenamento (S3, Azure Blob, Google Storage) para testar permissões públicas de leitura/escrita.
    Endereços IP e Hostnames Internos: IPs da rede privada (10.x, 192.168.x) ou domínios .local/.internal que mapeiam a topologia da rede.
    Webhooks: URLs completas para integração (Slack, Discord, Teams, Jira) que permitem envio de mensagens ou exfiltração de dados.
    Configurações de CI/CD: Arquivos como .gitlab-ci.yml, Jenkinsfile ou .github/workflows que mostram como o deploy é feito e onde estão as variáveis de ambiente.
    Token em geral que sejam relevantes
    subdominios de um modo geral
Criptografia e Autenticação:
    Chaves Privadas (SSH/RSA): Blocos de texto iniciando com -----BEGIN RSA PRIVATE KEY----- ou arquivos .pem/.ppk.
    Certificados Digitais: Arquivos .p12 ou .pfx que podem conter certificados de cliente para autenticação mútua.
    Salts e IVs Hardcoded: "Temperos" de hash ou vetores de inicialização de criptografia fixos no código.
    Segredos de Sessão/Assinatura: Chaves usadas para assinar cookies ou tokens JWT (SECRET_KEY, SESSION_SECRET).
    Credenciais expostas
Lógica da Aplicação e Debug:
    Rotas de Admin/Debug: Endereços ocultos como /actuator (Spring Boot), /server-status, /console, /graphql ou /swagger-ui.html.
    Parâmetros Ocultos: Variáveis de debug=true, test_mode=1 ou admin=1 que alteram o fluxo da aplicação.
Reconhecimento Geral:
    Caminhos de Arquivos (Full Paths): Strings que revelam a estrutura de diretórios do servidor (ex: /var/www/html/ clientes/... ou C:\Users\Admin...).
    E-mails de Desenvolvedores: Padrões de e-mail corporativo (nome.sobrenome@empresa.com) úteis para phishing ou brute-force.
    Arquivos de Dependências: package.json, requirements.txt, pom.xml (para identificar bibliotecas com vulnerabilidades conhecidas/CVEs).
    
6  Estrutura do resultado: o output-craftjs.txt deve conter, a URL que foi extraida aquela informação; A informação que foi encontrada; O que é aquela informação e como explorar com a informação de forma bem breve em um paragrafo de 2 linhas.

7  Regra dos dados que serão encontrados, remova as informações que estejam duplicadas, informar também se uma informação encontrada estiver em mais de uma url

## INTRO PARA AUTALIZAÇÃO NO SCRIPT

Preciso fazer uma melhoria no script.
Porém, preciso a atenção total na atualização.
Essa atualização precisa ser extremamente cautelosa de modo que APENAS a funcionalidade solicitada, seja implementada, de modo que TODO O RESTANTE do script nao sofra alterações, ou bugs de códigos. E para isso faça uma tripla verificação antes, durante e depois da conclusão do código, identificando quaisquer bugs, problemas, erros e/ou DESCARACTERIZAÇÃO do código principal.
