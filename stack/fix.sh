#!/usr/bin/env bash

cd /home/paulo/PROJETOS/MAIL_SERVER/stack

U=/home/paulo/PROJETOS/MAIL_SERVER/dovecot-users/users
TS=$(date +%Y%m%d-%H%M%S)

# 1) Backups
cp -a "$U" "$U.bak.$TS"
cp -a dovecot-conf/auth.conf "dovecot-conf/auth.conf.bak.$TS"
cp -a dovecot-conf/99-archive.conf "dovecot-conf/99-archive.conf.bak.$TS"

# 2) Limpa entradas legadas que sequestram auth (wildcard/user=%u)
awk '
/^[[:space:]]*$/ { print; next }
/^[[:space:]]*#/ { print; next }
{
  if ($0 ~ /^(\*|\*@\*):/) next
  if ($0 ~ /(^|[[:space:]:])user=%u([[:space:]:]|$)/) next
  print
}
' "$U" > "$U.tmp" && mv "$U.tmp" "$U"

chmod 0644 "$U"

# 3) Força configuração correta do Dovecot
cat > dovecot-conf/auth.conf <<'EOF'
auth_allow_cleartext = yes
auth_mechanisms = plain login

passdb passwd-file {
  passwd_file_path = /etc/dovecot/users
}

userdb static {
  fields {
    uid = 1000
    gid = 1000
    home = /srv/vmail/%{user}
  }
}
EOF

cat > dovecot-conf/99-archive.conf <<'EOF'
mail_driver = maildir
mail_path = /srv/vmail/%{user}/Maildir
mail_home = /srv/vmail/%{user}
auth_username_format = %{user}
EOF

# 4) Recria dovecot com a conf nova
docker compose up -d --force-recreate dovecot

# 5) Validação de conf ativa
docker exec mailarchive_dovecot doveconf -n | egrep 'auth_username_format|passdb|passwd_file_path|userdb'

# 6) Regrava hash da conta e testa auth fim-a-fim
./fix-dovecot-hash.sh paulo@archive.local 'PauloArchive2026!'
docker exec mailarchive_dovecot doveadm auth test 'paulo@archive.local' 'PauloArchive2026!'

