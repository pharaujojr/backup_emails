# Mail Archive Stack (Roundcube + Dovecot + imapsync + Flask Admin)

## Arquitetura
- `Roundcube` (`mailarchive_roundcube`) autentica via IMAP no `Dovecot` (`mailarchive_dovecot` em `31143`).
- `Dovecot` usa `passdb passwd-file` em `/home/paulo/PROJETOS/MAIL_SERVER/dovecot-users/users`.
- `imapsync` (`mailarchive_imapsync`) executa importações IMAP origem -> Dovecot local.
- `Flask Admin` (`mailarchive_imap_admin`) gerencia contas locais, sources, execuções e agendamentos.

Fluxo principal:
- Painel cria/atualiza usuário local no `passwd-file` + prepara `Maildir`.
- Roundcube passa a autenticar imediatamente com esse usuário.
- Painel dispara `imapsync` via Docker SDK (`docker.sock`) no container `mailarchive_imapsync`.
- Logs de execução ficam no dataset de logs.

## Subir o stack
1. Edite o `.env` com os valores corretos.
2. Suba os serviços:
```bash
docker compose up -d --build
```
3. Acesse:
- Roundcube teste: `http://<NAS_IP>:8080`
- Painel: `http://<NAS_IP>:8081`

## Rebuild/restart após alterações no painel
Se alterar código do `imap-admin` (Python/HTML/CSS), rode:
```bash
docker compose up -d --build imap_admin
```

Se também alterou compose/ambiente e quer garantir tudo consistente:
```bash
docker compose down
docker compose up -d --build
```

Ver logs do painel:
```bash
docker logs -f mailarchive_imap_admin
```

## Variáveis de ambiente
No `.env`, configure no mínimo:
```env
# Roundcube / Cloudflare
ROUNDCUBE_DB_PASSWORD=...
ROUNDCUBE_DES_KEY=...
CLOUDFLARE_TUNNEL_TOKEN=...

# Painel Flask
MASTER_KEY=...             # chave Fernet (32-byte urlsafe base64)
FLASK_SECRET_KEY=...
ADMIN_USER=admin
ADMIN_PASSWORD=...

# URLs exibidas no painel
ROUNDCUBE_TEST_URL=http://<NAS_IP>:8080
ROUNDCUBE_PROD_URL=https://webmail.seudominio.com
```

Gerar `MASTER_KEY` (Fernet) rapidamente:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Volumes / datasets usados
- Mail storage: `/home/paulo/PROJETOS/MAIL_SERVER/mail` -> painel em `/data/mail`
- passwd-file dovecot: `/home/paulo/PROJETOS/MAIL_SERVER/dovecot-users` -> painel em `/data/dovecot-users`
- logs imapsync: `/home/paulo/PROJETOS/MAIL_SERVER/imapsync-logs` -> painel em `/data/imapsync-logs`
- docker socket: `/var/run/docker.sock` (para `exec` no container `mailarchive_imapsync`)
- Dovecot conf override (na stack): `./dovecot-conf/99-archive.conf` -> `/etc/dovecot/conf.d/99-archive.conf`
- Dovecot auth override (na stack): `./dovecot-conf/auth.conf` -> `/etc/dovecot/conf.d/auth.conf`

Permissões importantes:
- `users` do Dovecot deve ser legível pelo processo `vmail` no container.
- O painel grava com modo `0644` (configurável por `DOVECOT_USERS_FILE_MODE`).

## Primeiro uso
1. Abra `http://<NAS_IP>:8081` e faça login com `ADMIN_USER` / `ADMIN_PASSWORD`.
2. Em **Accounts**, crie uma conta local (`usuario@archive.local`).
3. Copie a senha exibida (aparece apenas uma vez).
4. Teste login no Roundcube com essa conta.
5. Em **Nova Source IMAP**, associe a conta local e informe host/usuário/senha de origem.
6. Clique **Import now** para iniciar a importação.
7. Acompanhe em **Execuções** e no arquivo de log salvo em:
   - `/home/paulo/PROJETOS/MAIL_SERVER/imapsync-logs/<conta-local>/<timestamp>.log`

## Troubleshooting (erros de autenticação)
Se aparecer no log:
- `Host1 failure ... AUTHENTICATIONFAILED`
- `Host2 failure ... AUTHENTICATIONFAILED`
- `Exiting with return value 161 (EXIT_AUTHENTICATION_FAILURE_USER1)`

significa que as credenciais de login IMAP falharam em um ou nos dois lados.

### O que deu erro no seu log
- `Host1` (origem `mail.solturi.com.br`) falhou autenticação do usuário de origem.
- `Host2` (destino `mailarchive_dovecot:31143`) também falhou autenticação do usuário local.
- O código final `161` prioriza o erro de `user1`, mas seu log mostra falha nos dois.

### Checklist para corrigir (ordem recomendada)
1. Teste login no Roundcube com a conta local (`user2`) e senha atual.
2. Se falhar, no painel use **Accounts -> Alterar senha** (ou **Reset senha**) da conta local.
3. Confira no arquivo `users` do Dovecot se a conta está ativa (não comentada):
   - `/home/paulo/PROJETOS/MAIL_SERVER/dovecot-users/users`
4. Verifique se a conta local não está `disabled` no painel.
5. Na Source, confirme:
   - `Usuário origem` (`user1`) correto
   - `Senha origem` correta (atualize em **Sources -> Nova senha origem**)
   - `Host origem` e `Porta origem` corretos (`993` + `SSL` normalmente)
6. Clique **Import now** novamente.

### Sobre \"No log file because of option --nolog\"
- Isso é comportamento do `imapsync` em contexto Docker.
- No painel, o output continua salvo no arquivo:
  - `/home/paulo/PROJETOS/MAIL_SERVER/imapsync-logs/<conta-local>/<timestamp>.log`
- Ou abra direto pela UI em **Execuções -> abrir log**.

### Comando rápido para recarregar o Dovecot (opcional)
Se você acabou de alterar conta/senha e quiser forçar refresh:
```bash
docker exec mailarchive_dovecot doveadm reload
```

### Erro 409 \"container is restarting\" ao validar credenciais
Se o painel mostrar erro 409 ao chamar `doveadm`, o Dovecot está em restart loop.

Checklist:
1. Ver logs:
```bash
docker logs --tail 200 mailarchive_dovecot
```
2. Confirme o override de conf:
```bash
docker exec mailarchive_dovecot doveconf -n | grep -E 'passdb|passwd_file_path|mail_location|auth_username_format'
```
3. Reaplique a conf da stack e suba novamente:
```bash
docker compose up -d --build dovecot
docker exec mailarchive_dovecot doveadm reload
```

Se houver `internal auth failure` com `passdb static` mesmo com hash correto, ajuste permissão do passwd-file:
```bash
chmod 644 /home/paulo/PROJETOS/MAIL_SERVER/dovecot-users/users
```

### Validar credenciais do usuário local (recomendado)
No painel, use **Validate credentials** na linha da conta local.  
Isso executa internamente:
```bash
docker exec mailarchive_dovecot doveadm auth test '<user>' '<password>'
```
Antes do teste, o painel regrava o `users` a partir do banco para evitar arquivo legado/truncado.
Se a senha não bater com o hash no banco, o painel informa isso antes de chamar o Dovecot.

Teste manual equivalente:
```bash
docker exec mailarchive_dovecot doveadm auth test 'suporte@archive.local' 'SENHA_DA_CONTA'
```

Se retornar `passdb: ... succeeded`, a senha/hash está correta no Dovecot.
Quando falhar, o painel também mostra diagnósticos adicionais:
- `hash-test-ok`/`hash-test-fail`: resultado do `doveadm pw -t` com o hash salvo
- `user-line-found`/`user-line-missing`: se a linha do usuário foi encontrada em `/etc/dovecot/users` dentro do container
- Se aparecer `extra fields: user=%u`, remova `auth_username_format = %u` da conf (no Dovecot 2.4 isso pode virar literal e quebrar auth).

### Ajuste de passdb (evitar conflito com passdb static)
Use os arquivos `dovecot-conf/auth.conf` + `dovecot-conf/99-archive.conf` deste projeto para garantir:
- login via `passdb passwd-file` (`/etc/dovecot/users`)
- sem `passdb static` para autenticação de usuários finais
- compatibilidade com Dovecot 2.4 (`auth_allow_cleartext = yes`)

Após aplicar alterações de conf:
```bash
docker compose up -d
docker exec mailarchive_dovecot doveadm reload
```

## Segurança e políticas anti-destrutivas
O painel bloqueia opções destrutivas no `imapsync`.

Proibidas (incluindo variações):
- `--delete`, `--delete1`, `--delete2`
- `--expunge`, `--expunge1`, `--expunge2`
- `--deletefolders`, `--delete2folders`
- `--fast`

Também fixa no destino:
- `--nossl2 --notls2`

E sempre aplica:
- `--syncinternaldates --subscribeall --nofoldersizes`

Credenciais:
- Senhas de origem e senha local da conta são salvas criptografadas com `Fernet` (`MASTER_KEY`).
- Logs mascaram senhas antes de persistir.

Aviso importante:
- Montar `docker.sock` no painel dá acesso elevado ao Docker host. Restrinja acesso ao painel, use senha forte e rede confiável.

## Produção (sem portas locais)
Para operar apenas via Cloudflare Tunnel:
1. Remova o publish local do Roundcube (`8080:80`) no `docker-compose.yml`.
2. Remova o publish local do painel (`8081:5000`) ou restrinja por firewall/VPN.
3. Mantenha apenas exposição interna entre containers + Tunnel.

## Como funciona
### A) Gestão de contas locais (Dovecot passwd-file)
- Criar conta:
  - Gera senha aleatória forte.
  - Gera hash `SHA512-CRYPT` preferencialmente via `doveadm pw` (fallback `passlib`).
  - Valida hash antes de gravar (`$6$` e tamanho mínimo).
  - Escreve no arquivo `users` com lock de arquivo para evitar corrupção.
  - Cria `Maildir` em `/home/paulo/PROJETOS/MAIL_SERVER/mail/<usuario>/Maildir`.
  - Aplica `chown -R 1000:1000` no diretório do usuário.
- Reset senha:
  - Repete geração de senha/hash e atualiza o `users`.
- Alterar senha manualmente:
  - Admin informa a nova senha no painel (mínimo 12 caracteres).
  - O painel recalcula hash `SHA512-CRYPT`, atualiza segredo criptografado e regrava o `users`.
- Desativar:
  - Remove entrada ativa do passwd-file e mantém comentário `# managed-disabled:`.
  - Não remove Maildir.
- O arquivo `users` é regravado com:
  - somente um cabeçalho `# managed-by-imap-admin`
  - sem linhas duplicadas de usuários
  - remove entradas curinga legadas (`*:`/`user=%u`) que podem causar auth incorreto
  - formato exato por linha: `<email>:{SHA512-CRYPT}<hash>`
  - newline ao final do arquivo

### B) Importação IMAP -> IMAP por conta/source
- Cada conta local pode ter múltiplas `Sources`.
- `Import now` dispara execução assíncrona do `imapsync` no container `mailarchive_imapsync` via Docker SDK (sem shell injection).
- Resultado da execução:
  - status (`running`, `success`, `fail`)
  - duração, exit code, último sync
  - caminho do log persistido em dataset

### C) Agendamento
- Cada source pode ter schedule habilitado/desabilitado.
- Modos suportados:
  - intervalo em minutos
  - cron (`crontab`, ex: `0 */6 * * *`)
- Scheduler usa APScheduler com jobstore persistente em SQLite.
