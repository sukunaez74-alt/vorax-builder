# ʙʟᴀᴄᴋ ᴢᴏɴᴇ Estúdio

Painel web para organizar contas, bots Discord e operações da hospedagem.

## Estrutura

- `index.html`: interface em português brasileiro, tema cósmico responsivo.
- `functions/api/[[path]].js`: API Cloudflare Pages Functions para sessão, cadastro, login, Discord OAuth e integração Bot-Hosting.
- `schema.sql`: tabelas do banco Cloudflare D1.

## Publicação na Cloudflare Pages

1. Crie um projeto Pages conectado ao repositório `sukunaez74-alt/vorax-builder`, branch `main`.
2. Sem framework/build: deixe o comando de build vazio e use `.` como diretório de saída.
3. Crie um banco D1 e execute o conteúdo de `schema.sql`.
4. Em Settings > Functions > D1 database bindings, crie o binding com o nome `DB`.
5. Em Settings > Variables and Secrets, cadastre como secrets:
   - `APP_GATE_PHRASE`: a chave de entrada que o proprietário escolheu.
   - `APP_SESSION_SECRET`: uma chave aleatória longa, exclusiva.
   - `APP_ENCRYPTION_KEY`: outra chave aleatória longa, exclusiva, para criptografar chaves do Bot-Hosting.
   - `DISCORD_CLIENT_ID` e `DISCORD_CLIENT_SECRET`: credenciais da aplicação Discord.
6. No Discord Developer Portal, adicione como OAuth2 Redirect URL:
   `https://SEU-DOMINIO/api/auth/discord/callback`
7. Faça um novo deploy depois de criar o binding e os secrets.

O primeiro cadastro no banco recebe o papel owner. Os cadastros seguintes recebem member. Senhas são derivadas com PBKDF2; sessões usam cookies HttpOnly, Secure e SameSite=Lax. Chaves do Bot-Hosting são criptografadas com AES-GCM antes de serem gravadas no D1.

## Bot-Hosting

Crie uma API key em Account > Developer no Bot-Hosting. Para os recursos iniciais, conceda apenas os escopos necessários:
- `deployments:read`
- `deployments:write`
- `deployments:power`
- `files:write`
- `env:write`

Conecte essa chave na tela Configurações. O backend valida e guarda a chave criptografada por usuário; ela não fica no HTML nem no armazenamento do navegador.

## Estado atual e itens que ainda exigem configuração

A interface e a API estão versionadas no GitHub. O painel só funcionará com autenticação real depois da publicação Pages, binding D1 e secrets configurados.

A conexão Discord OAuth exige criar a aplicação Discord e cadastrar o callback da URL definitiva. A integração de hospedagem exige uma chave Bot-Hosting do próprio usuário.

O CAOS original está em outro repositório privado (`sukunaez74-alt/cao`). O código Python recebeu o primeiro filtro de `CAOS_MODULES`: comandos identificados por módulo são removidos antes da sincronização e eventos/painéis principais são bloqueados quando desativados. Esse ajuste ainda precisa ser validado executando o bot com combinações reais de módulos. O painel ainda não transfere automaticamente o código do repositório privado para uma implantação vazia; por enquanto, a área de Arquivos prepara o envio de um pacote ZIP pela interface do navegador.

Não coloque `.env`, tokens Discord, chaves Bot-Hosting, banco SQLite ou credenciais em repositórios.
