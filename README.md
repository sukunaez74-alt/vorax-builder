# ʙʟᴀᴄᴋ ᴢᴏɴᴇ Estúdio

Painel web em português para organizar projetos de bots Discord e seus módulos.

## Produção na Vercel

- `index.html`: interface responsiva e página pública do estúdio.
- `api/[...path].js`: API Node.js para cadastro, login, sessões e gestão dos projetos no PostgreSQL.
- `@neondatabase/serverless`: conexão serverless com PostgreSQL (Neon).
- `schema.postgres.sql`: esquema do banco PostgreSQL.
- `robots.txt` e `sitemap.xml`: arquivos de descoberta para mecanismos de busca.

O esquema PostgreSQL é inicializado automaticamente na primeira chamada à API.

## Autenticação e proteção

As senhas são derivadas com PBKDF2-SHA-256 (210.000 iterações); os tokens de sessão são armazenados apenas como hash e os cookies são HttpOnly, Secure e SameSite=Lax. O primeiro cadastro válido recebe o papel owner, com reivindicação atômica da instalação; os seguintes recebem member.

A frase de entrada é opcional no backend. Quando configurada, ela é validada pelo servidor antes do login/cadastro. Nunca coloque a frase no HTML ou no GitHub.

## Workspace sem chave de API

O usuário pode criar e organizar projetos sem conectar uma chave individual de Bot-Hosting. Os projetos são guardados na tabela `bots`, com dono, linguagem, estado de preparação e preferências de módulos.

A API não simula execução. Inicialização, logs, terminal, métricas de CPU/RAM e envio de arquivos retornam `runtime_not_connected` até que exista um executor de processos real. Para manter bots Discord Gateway ativos 24/7, a aplicação precisa de um serviço persistente separado; a hospedagem estática/serverless do painel não substitui esse executor.

As rotas legadas da API Bot-Hosting não são exibidas no fluxo principal do usuário.

## OAuth Discord

O botão OAuth fica condicionado a configurar `DISCORD_CLIENT_ID` e `DISCORD_CLIENT_SECRET` como variáveis seguras na Vercel. Redirect URL:

`https://black-zone-estudio.vercel.app/api/auth/discord/callback`

O cadastro e login por e-mail/usuário e senha não dependem do OAuth Discord.

## Descoberta em mecanismos de busca

A página inicial possui title, descrição, canonical, Open Graph, WebSite JSON-LD, `robots.txt` e `sitemap.xml`. Isso permite que mecanismos de busca descubram a página e recebam a preferência de nome do site. A indexação e a apresentação do nome na pesquisa são decisões automáticas dos buscadores e não têm prazo ou posição garantidos.

## Arquivos legados Cloudflare

`functions/api/[[path]].js`, `schema.sql` e `wrangler.toml` são mantidos como material da implementação anterior Cloudflare Pages/D1. A produção atual na Vercel utiliza `api/[...path].js` e PostgreSQL/Neon.

Nunca coloque `.env`, tokens Discord, chaves API ou credenciais no repositório.
