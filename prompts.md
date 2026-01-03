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

Preciso fazer um script
usando selenium no navegador firefox para validação de logins e senhas de uma pagina
esquema do script: bird-leak-checker.py -u https://sub.domain.com/login -l login.txt -p pass.txt -t 3 -s 10 --pitchfork --headless

-u é o parametro da URL
-l é a lista de login
--login passa uma string para teste de um usuario apenas
-p é a lista de passwords
--password passa string de teste de um password apenas
-t (em segundos) é o tempo de cada tentativa de login
-s (em segundos) é o tempo de espera para pegar a resposta da tentativa de login
--pitchfork é o modo de tentes de senha, sendo login1 com o pass1, login2 com o pass2 e assim por diante
--clusterbomb é o modo de testes de credenciais, sendo login1 com senha1, login1 com senha2 até finalizar a lista com todas as combinações
--headless para funcionar em modo headless, caso nao esteja com o parametro presente, vai funcionar normalmente abrindo o navegador

Este script deve primeiramente:
1 Entrar na url passada por parametro 
2 analisar a página de login (html, JS...)
3 capturar os campos de LOGIN e SENHA e o Botão de login/entrar/acessa/enter, etc... o script deve ser inteligente o suficiente para se adaptar a vários tipos de paginas e codigos, para capturar o formulario em qualquer tipo como (type, name, ID com os mais diversos tipos de possiveis nomes) e o botão
4 fazer uma tentativa de login passando credenciais propositalmente erradas como um UUID
5 caprturar a resposta da página com a mensagem de erro da aplicação. O script deve ser inteligente o suficiente para capturar das mais diversas respostas de tentativas de logins como redirecionamento, alert, mensagem no HTML, mensagens vinda de um codigo JS, Modal etc.
6 Após esta análise, o script deve, se com sucesso seguir com os testes com a lista de login e senhas. 
7 Caso o script nao identifique os campos de login, deve pedir ao usuario para passar por parametro os campos de login e os campos de senha, usando: -Lid, -Lname, -Ltype e -Pid, -Pname, -Ptype informando os campos que devem ser inserido o login e a senha

-Lid é o campo de login do tipo ID
-Lname é o campo de login do tipo name
-Ltype é o campo de login do tipo type
-Pid é o campo de pass do tipo ID
-Pname é o campo de pass do tipo name
-Ptype é o campo de pass do tipo type

Por padrão, para garantir os que a mensagem é capturada pelo script, deve-se esperar 7 segundos pela resposta da primeira tentativa de login com o UUID.

Faça um parametro com --help que insine os parametros e como usa-los

Os resultados e logs do script deve ser salvo em:
error.log
e logins-sucesso.txt no formato login:senha
