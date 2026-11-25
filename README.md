# ʙʟᴀᴄᴋ ᴢᴏɴᴇ Estúdio

Painel web em português para organizar contas, bots Discord e operações da hospedagem.

## Produção na Vercel

- `index.html`: interface responsiva.
- `api/[...path].js`: API Node.js para autenticação, sessões, Discord OAuth e integração com Bot-Hosting.
- `@neondatabase/serverless`: conexão serverless com PostgreSQL (Neon).
- `schema.postgres.sql`: esquema relacional usado pela versão Vercel.

O esquema PostgreSQL é inicializado automaticamente na primeira chamada à API, com criação idempotente das tabelas e índices.

### Variáveis do projeto

Configure no projeto Vercel, em Production, Preview e Development:

- `DATABASE_URL`: connection string do Neon.
- `APP_GATE_PHRASE`: frase de entrada privada.
- `APP_SESSION_SECRET`: segredo aleatório e exclusivo para assinar o cookie de acesso.
- `APP_ENCRYPTION_KEY`: segredo aleatório e exclusivo para criptografar as chaves do Bot-Hosting.
- `DISCORD_CLIENT_ID` e `DISCORD_CLIENT_SECRET`: credenciais OAuth, quando a opção de login Discord for habilitada.

Não compartilhe nem registre os valores dessas variáveis em arquivos do repositório.

### Autenticação e proteção

As senhas são derivadas com PBKDF2-SHA-256 (210.000 iterações); os tokens de sessão são armazenados apenas como hash e os cookies são HttpOnly, Secure e SameSite=Lax. Chaves Bot-Hosting são criptografadas com AES-GCM antes de serem salvas no PostgreSQL. O primeiro cadastro válido recebe o papel owner, com reivindicação atômica da instalação; os seguintes recebem member.

A frase de entrada é opcional no backend. Quando configurada, ela é validada pelo servidor antes do login/cadastro. Nunca coloque a frase no HTML ou no GitHub.

### OAuth Discord

No Discord Developer Portal, adicione esta OAuth2 Redirect URL:

`https://black-zone-estudio.vercel.app/api/auth/discord/callback`

O login Discord só fica ativo depois de configurar `DISCORD_CLIENT_ID` e `DISCORD_CLIENT_SECRET`.

## Integração de hospedagem

O painel permite guardar uma chave de API por usuário, criptografada no servidor, e acionar rotas de implantação, logs, energia, recursos, arquivos, terminal e variáveis de ambiente. A integração consulta `https://bot-hosting.net/api/v1`.

A compatibilidade de cada endpoint e escopo da API do Bot-Hosting precisa ser confirmada com uma chave de teste na conta do proprietário antes de considerar todas as operações validadas. Não conceda permissões de gastos/créditos à chave para testes.

## CAOS

O bot original permanece no repositório privado `sukunaez74-alt/cao`. O painel ainda não sincroniza esse código privado automaticamente para novas implantações: o fluxo inicial é enviar um pacote ZIP pela área de arquivos. A lógica de `CAOS_MODULES` deve continuar sendo testada no runtime do bot com combinações reais de módulos.

## Arquivos legados Cloudflare

`functions/api/[[path]].js`, `schema.sql` e `wrangler.toml` são mantidos como material da implementação anterior Cloudflare Pages/D1. A produção atual na Vercel utiliza `api/[...path].js` e PostgreSQL/Neon.

Nunca coloque `.env`, tokens Discord, chaves Bot-Hosting, dumps de banco ou credenciais no repositório.
