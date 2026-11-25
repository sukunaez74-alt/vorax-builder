# ʙʟᴀᴄᴋ ᴢᴏɴᴇ Estúdio

Painel web em português para criar e gerenciar bots Discord com a identidade visual anime/cósmica do Estúdio.

## Produção

- Hospedagem da interface e API: Vercel.
- Dados de contas, sessões e bots: PostgreSQL/Neon.
- index.html: site público, painel e controles de bots.
- studio-ui.css, studio-dashboard.css, studio-extra.css: tema e componentes.
- api/[...path].js: API de conta, credenciais, projetos, hospedagem, arquivos, shell, agendamento e backups.
- api/bridge.js e vercel.json: roteamento de chamadas /api/*.

O esquema PostgreSQL é criado e atualizado pela API. A produção não deve receber tokens ou códigos privados pelo repositório público.

## Bot Token do Discord

O usuário cola o Bot Token da seção Bot do Discord Developer Portal. A API aceita o token puro ou o exemplo com prefixo Bot, normaliza esse prefixo, valida com GET /api/v10/users/@me, criptografa com AES-GCM e confirma a gravação por leitura de volta do banco. A rota GET /api/bot-token/status abre a credencial protegida e verifica novamente com o Discord, sem devolver o segredo ao navegador.

O painel mostra o token apenas mascarado. Campo vazio significa manter a credencial atual. Um token novo só substitui o anterior depois que o Discord o valida e a gravação é confirmada.

Nunca registre tokens em HTML, JavaScript público, logs ou repositórios.

## Execução do CAOS

A integração automática prepara o modelo CAOS em Python 3.11, obtido do repositório privado na etapa de publicação, sem incluir o código-fonte privado no repositório público.

Ao iniciar, a API:
1. Confere novamente o Bot Token salvo.
2. Cria ou reutiliza uma implantação Python no Bot-Hosting.
3. Envia main.py, requirements.txt e o supervisor de agenda.
4. Define DISCORD_TOKEN como variável secreta e configura módulos e horários.
5. Configura o comando de inicialização e solicita que o provedor ligue o container.
6. Consulta diagnóstico e o heartbeat caos-status.json para diferenciar container iniciado de sessão Discord realmente online.

O botão de iniciar não deve apresentar o bot como conectado só porque o container iniciou. A confirmação de Discord depende do heartbeat do próprio CAOS.

**Limite atual:** o fluxo automático do CAOS é Python 3.11. Outros runtimes não são apresentados como executáveis pelo criador enquanto não houver um fluxo próprio para implantar seus arquivos.

## Hospedagem e OAuth

A conexão com Bot-Hosting é por OAuth/PKCE. Os tokens de acesso e renovação são guardados criptografados no PostgreSQL e renovados no servidor. O usuário não precisa colar chave de API manualmente.

A execução contínua depende dos limites, disponibilidade, quota e política de renovação do plano Bot-Hosting. O painel não promete 24/7 quando o plano do provedor não garante isso.

## Recursos do painel

- Criar e excluir projetos (com tentativa de parar e remover a implantação antes de excluir).
- Salvar, verificar e substituir Bot Tokens.
- Selecionar módulos CAOS por projeto.
- Iniciar, parar e reiniciar containers.
- Horários diários no fuso America/Bahia.
- Logs, diagnóstico e recursos quando o provedor os disponibiliza.
- Gerenciador de arquivos, upload de ZIP, extração, edição e exclusão segura de arquivos.
- Terminal do container.
- Exportação ZIP manual e consulta/restauração de pontos de backup oferecidos pelo provedor.
- Documentação e diagnóstico do ambiente.

Marketplace e alertas avançados ainda não estão habilitados; não devem ser apresentados como recursos prontos.

## Segurança

As senhas usam PBKDF2-SHA-256; tokens de sessão são armazenados como hash e os cookies são HttpOnly, Secure e SameSite=Lax. O primeiro cadastro válido reivindica o papel owner da instalação.

A frase de entrada e as chaves de sessão e criptografia ficam exclusivamente em variáveis de ambiente da Vercel. Nunca as coloque no HTML ou no repositório.

## Login por conta Discord

O login OAuth por conta Discord é opcional e separado do Bot Token. Ele depende de DISCORD_CLIENT_ID e DISCORD_CLIENT_SECRET; o token individual de cada bot não substitui essas credenciais.

## Arquivos legados Cloudflare

functions/api/[[path]].js, schema.sql e wrangler.toml são mantidos como material da implementação anterior Cloudflare Pages/D1. A produção atual usa api/[...path].js e PostgreSQL/Neon.
