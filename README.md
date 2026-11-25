# ʙʟᴀᴄᴋ ᴢᴏɴᴇ Estúdio

Painel web em português para organizar projetos de bots Discord e seus módulos.

## Produção na Vercel

- `index.html`: interface responsiva e página pública do estúdio.
- `api/[...path].js`: API Node.js para cadastro, login, sessões e gestão dos projetos no PostgreSQL.
- `@neondatabase/serverless`: conexão serverless com PostgreSQL (Neon).
- `schema.postgres.sql`: esquema relacional do banco.
- `robots.txt` e `sitemap.xml`: arquivos de descoberta para mecanismos de busca.

O esquema PostgreSQL é inicializado automaticamente na primeira chamada à API.

## Tokens de cada bot Discord

A criação de cada projeto solicita o token do bot Discord correspondente. O token é enviado ao backend e salvo criptografado com AES-GCM na coluna `bots.discord_token_enc`. A API retorna apenas o indicador `hasDiscordToken`; nunca devolve o segredo ao navegador. O token pode ser substituído na configuração do projeto, deixando o campo vazio mantém o token atual.

Esse token é a credencial do bot para autenticar no Discord. Ele não é uma chave de API de hospedagem. Nunca coloque tokens em HTML, JavaScript público, logs ou no repositório.

## Autenticação e proteção

As senhas são derivadas com PBKDF2-SHA-256 (210.000 iterações); os tokens de sessão são armazenados apenas como hash e os cookies são HttpOnly, Secure e SameSite=Lax. O primeiro cadastro válido recebe o papel owner, com reivindicação atômica da instalação; os seguintes recebem member.

A frase de entrada é opcional no backend. Quando configurada, ela é validada pelo servidor antes do login/cadastro. Nunca coloque a frase no HTML ou no GitHub.

## Workspace e execução

Os usuários podem criar projetos e organizar módulos sem conectar uma chave individual de Bot-Hosting. Projetos e preferências são guardados na tabela `bots`.

**Importante:** guardar o token do Discord não inicia o processo do bot. A produção atual ainda não tem um executor persistente conectado. Inicialização, logs, terminal, métricas, envio de arquivos e execução 24/7 só devem ser habilitados depois de conectar um executor de processos real; a API responde com `runtime_not_connected` em vez de simular execução.

## OAuth Discord

O login OAuth por conta Discord é opcional e depende de `DISCORD_CLIENT_ID` e `DISCORD_CLIENT_SECRET`. O token individual do bot não substitui essas credenciais de OAuth.

## Descoberta em mecanismos de busca

A página inicial possui title, descrição, canonical, Open Graph, WebSite JSON-LD, `robots.txt` e `sitemap.xml`. A indexação e a apresentação do nome são decisões automáticas dos buscadores e não têm prazo ou posição garantidos.

## Arquivos legados Cloudflare

`functions/api/[[path]].js`, `schema.sql` e `wrangler.toml` são mantidos como material da implementação anterior Cloudflare Pages/D1. A produção atual na Vercel utiliza `api/[...path].js` e PostgreSQL/Neon.

Nunca coloque `.env`, tokens Discord, chaves API ou credenciais no repositório.
