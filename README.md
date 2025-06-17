# BloggySource
## Um SaaS de blog pra deixar tudo sob controle!

Bem vindo(a) a esta documentação técnica, antes de começarmos, gostaria de dizer que caso você queira apenas **realizar a execução do BloggySource** e não precisa entender sobre cada detalhe do serviço, recomendo dar uma olhadinha no [Tutorial de Uso](#). Dito isso, vamos continuar!

## Índice
- Introdução (BloggySource)
- Índice
- Como funciona (Código)
- Como funciona (Plataforma)
- Possiveis alterações no código
- Créditos
- Finalização


# Introdução (BloggySource)
Bom, já dei bem vindo(a), mas não custa falar denovo, Bem vindo(a) ao BloggySource. O Bloggysource é basicamente uma plataforma de blog, que basicamente é uma junção do twitter com um blog. O objetivo, é ter um canal de comunicação aberto, onde qualquer um possa compartilhar informações, e tenha um certo nivel de moderação, que é interessante pra ambientes empresariais por exemplo, já que esta plataforma é de código-aberto e portanto, é permitido o uso do BloggySource em ambientes empresariais gratuitamente.

# Como funciona (Código)
Meu código, é feito em NodeJS, utilizando basicamente de recursos medianos para tentar fazer um bom papel se comunicando com o frontend, neste serviço em especifico foi implementado alguns recursos de segurança pra garantir que nada saia do controle, e que seja seguro, além de uma configuração relativamente simples (Linhas 16 a 31).

# Como funciona (Plataforma)
A plataforma se comunica com o backend de forma integral, e é servido também pelo backend. Ele é um SPA (Single Page Application) o que significa que a renderização dos elementos são dinamicas o que trás uma performance muito boa pro frontend.
## Como usar a plataforma
Simples, ao acessar uma conta administrativa, você poderá ver todos os comentários realizados e em quais posts, você pode aprovar ou rejeitar os comentários, além disso, você pode deletar os posts que você acha ofensivo, ou enfim, sua plataforma, suas regras. E pro usuário comum, ele pode gerar categorias (pros posts), posts, e comentários que precisam da autorização dos moderadores e moderadoras.

# Possiveis alterações no código
## 1°:
Linhas de 16 a 31 (Configurações gerais)

## 2°:
Linhas de 38 a 65 (Configurações e middlewares de segurança)

## 3°:
Linha 100 (Configuração de diretório da database)

## 4°:
Linhas 201 e 202 - Comentar linha 202 e descomentar linha 203 (Senha fixa do admin) // Descomentar linha 202 e comentar 203 (Senha variável do admin)

# Créditos
Este código está sob a licença [MIT](https://github.com/Hsyst/BloggySource/blob/main/LICENSE) e foi criado pela Thais [(op3n/op3ny)](https://github.com/op3ny)

# Finalização
Agradeço por estar interessado(a) neste código, e espero ter contribuido de alguma forma, bom proveito, e até mais!
