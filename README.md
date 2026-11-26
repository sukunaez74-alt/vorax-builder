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

## Provedores gratuitos adicionais

### Criação automática pelo Estúdio
- **Cube Hosting Free**: a conta precisa reivindicar a vaga com `/free`; o Estúdio consulta quota e memória antes de criar o projeto por API.
- **Discloud Free**: alternativa automática quando a Cube não tem capacidade. A conta precisa estar no Free, sem aplicação existente e com 100 MB livres confirmados; o Estúdio não seleciona planos pagos.

### Servidores gratuitos conectados por API
- **Kerit Cloud Free**: cada membro reivindica o próprio servidor no painel Kerit (verificação de e-mail, vinculação do Discord e entrada na comunidade). Depois conecta uma Client API Key Pterodactyl; o Estúdio lista servidores, vincula o projeto, envia ZIP/arquivos, extrai, controla energia e lê métricas. A API de cliente não cria o primeiro servidor. O Free anuncia 256 MB RAM e 2 GB NVMe; bots de música ou com uso alto de memória podem não caber.
- **Waifly Free**: 1 servidor por conta, cerca de 300 MB RAM e 1 GB de armazenamento. O membro cria o servidor no painel e conecta a Client API Key; o Estúdio envia ZIP, gerencia arquivos e controla energia. O provedor pode suspender servidores que ficam desligados por vários dias.
- **X Systems Hosting**: a primeira vaga gratuita da conta anuncia 4 GB RAM, 10 GB de disco e 20 backups. Servidores adicionais usam créditos conquistados no próprio serviço. O membro cria o servidor e conecta a Client API Key ao Estúdio.
- **Torchlite Free Bot**: plano específico para bots Discord, com 512 MB RAM, 3 GB de disco, 0,5 CPU e 1 banco MySQL. Cada conta permite 1 servidor de jogo e 1 servidor de bot/TeamSpeak. O servidor de bot exige renovação manual gratuita a cada 24 horas (o botão abre 6 horas antes e pede 2 anúncios); também é preciso fazer uma ação no servidor a cada 5 dias. O Estúdio lista o servidor, envia ZIP, configura variável de token/startup quando o egg permite, gerencia arquivos e controla energia. A renovação diária continua manual.
- **Daki Hosting**: integração de Client API para vincular e gerenciar servidores existentes. O provedor informa que as novas vagas Free estão fechadas no momento; não conte com uma vaga nova até a disponibilidade reabrir.
- **Cogithost e ACLClouds**: integrações para servidores que o membro cria no painel do provedor antes de vincular ao Estúdio.

### Publicação pelo painel externo
- **FadeHost e Quaxly** continuam como opções de publicação pelo painel externo, sem fluxo automático de ZIP por API documentado nesta versão.

Cada membro deve usar sua própria conta e chave de API. Credenciais são armazenadas criptografadas e não devem ser incluídas em arquivos públicos. Vagas, disponibilidade, cotas, renovações e termos são definidos pelos provedores; não há criação de contas em massa, contorno de limites ou garantia de hospedagem infinita.

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
