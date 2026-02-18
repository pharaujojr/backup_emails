#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Uso:
  bash ./fix-dovecot-auth-full.sh <email> <senha>

Exemplo:
  bash ./fix-dovecot-auth-full.sh paulo@archive.local 'PauloArchive2026!'

Variaveis opcionais:
  STACK_DIR=/home/paulo/PROJETOS/MAIL_SERVER/stack
  USERS_FILE=/home/paulo/PROJETOS/MAIL_SERVER/dovecot-users/users
  DOVECOT_CONTAINER=mailarchive_dovecot
USAGE
}

log() {
  printf '[INFO] %s\n' "$*"
}

warn() {
  printf '[WARN] %s\n' "$*"
}

fail() {
  printf '[ERRO] %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Comando nao encontrado: $1"
}

backup_file() {
  local file="$1"
  local ts="$2"
  [[ -f "$file" ]] || return 0
  cp -a "$file" "${file}.bak.${ts}"
}

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    docker compose -f "$COMPOSE_FILE" "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose -f "$COMPOSE_FILE" "$@"
  else
    fail "Nem 'docker compose' nem 'docker-compose' disponivel"
  fi
}

wait_container_running() {
  local name="$1"
  local timeout="${2:-45}"
  local elapsed=0
  while (( elapsed < timeout )); do
    local status
    status="$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || true)"
    if [[ "$status" == "running" ]]; then
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  docker logs --tail 80 "$name" || true
  fail "Container $name nao entrou em running (timeout=${timeout}s)"
}

EMAIL="${1:-}"
PASSWORD="${2:-}"
if [[ -z "$EMAIL" || -z "$PASSWORD" ]]; then
  usage
  exit 1
fi

need_cmd docker
need_cmd awk
need_cmd sed
need_cmd tr
need_cmd mktemp
need_cmd grep
need_cmd date
need_cmd chmod
need_cmd cp
need_cmd mv
need_cmd cmp

STACK_DIR="${STACK_DIR:-$PWD}"
USERS_FILE="${USERS_FILE:-/home/paulo/PROJETOS/MAIL_SERVER/dovecot-users/users}"
DOVECOT_CONTAINER="${DOVECOT_CONTAINER:-mailarchive_dovecot}"
AUTH_CONF="${STACK_DIR}/dovecot-conf/auth.conf"
ARCHIVE_CONF="${STACK_DIR}/dovecot-conf/99-archive.conf"

if [[ -f "${STACK_DIR}/docker-compose.yml" ]]; then
  COMPOSE_FILE="${STACK_DIR}/docker-compose.yml"
elif [[ -f "${STACK_DIR}/docker-compose.yaml" ]]; then
  COMPOSE_FILE="${STACK_DIR}/docker-compose.yaml"
else
  fail "Nao achei docker-compose.yml em STACK_DIR=${STACK_DIR}"
fi

[[ -f "$USERS_FILE" ]] || fail "Arquivo users nao encontrado: $USERS_FILE"
[[ -d "${STACK_DIR}/dovecot-conf" ]] || fail "Pasta nao encontrada: ${STACK_DIR}/dovecot-conf"

ts="$(date +%Y%m%d-%H%M%S)"
log "Conta alvo: $EMAIL"
log "Stack dir: $STACK_DIR"
log "Arquivo users: $USERS_FILE"
log "Container dovecot: $DOVECOT_CONTAINER"

backup_file "$USERS_FILE" "$ts"
backup_file "$AUTH_CONF" "$ts"
backup_file "$ARCHIVE_CONF" "$ts"
log "Backups criados com sufixo .bak.${ts}"

# 1) Normaliza users file para LF
crlf_tmp="$(mktemp "${USERS_FILE}.crlf.XXXXXX")"
tr -d '\r' < "$USERS_FILE" > "$crlf_tmp"
if ! cmp -s "$USERS_FILE" "$crlf_tmp"; then
  mv "$crlf_tmp" "$USERS_FILE"
  log "CRLF removido do arquivo users"
else
  rm -f "$crlf_tmp"
fi

# 2) Remove linhas legadas que sequestram auth (wildcard e user=%u)
sanitize_tmp="$(mktemp "${USERS_FILE}.sanitize.XXXXXX")"
awk '
/^[[:space:]]*$/ { print; next }
/^[[:space:]]*#/ { print; next }
{
  if ($0 ~ /^(\*|\*@\*):/) next
  if ($0 ~ /(^|[[:space:]:])user=%u([[:space:]:]|$)/) next
  print
}
' "$USERS_FILE" > "$sanitize_tmp"
mv "$sanitize_tmp" "$USERS_FILE"
chmod 0644 "$USERS_FILE"
log "Entradas wildcard/user=%u removidas do users"

# 3) Forca conf do Dovecot para passdb passwd-file
cat > "$AUTH_CONF" <<'EOF_AUTH'
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
EOF_AUTH

cat > "$ARCHIVE_CONF" <<'EOF_ARCH'
mail_driver = maildir
mail_path = /srv/vmail/%{user}/Maildir
mail_home = /srv/vmail/%{user}
auth_username_format = %{user}
EOF_ARCH
log "Arquivos dovecot-conf/auth.conf e dovecot-conf/99-archive.conf atualizados"

# 4) Recria container do Dovecot para garantir conf aplicada
compose_cmd up -d --force-recreate dovecot
wait_container_running "$DOVECOT_CONTAINER" 60
log "Container $DOVECOT_CONTAINER em running"

# 5) Gera novo hash e grava linha unica do usuario
new_hash_raw="$(docker exec "$DOVECOT_CONTAINER" doveadm pw -s SHA512-CRYPT -p "$PASSWORD" | tr -d '\r' | tail -n 1)"
new_hash="${new_hash_raw#\{SHA512-CRYPT\}}"

[[ "$new_hash" == '$6$'* ]] || fail "Hash invalido gerado: $new_hash_raw"
[[ ${#new_hash} -ge 90 ]] || fail "Hash gerado muito curto: ${#new_hash}"

rewrite_tmp="$(mktemp "${USERS_FILE}.rewrite.XXXXXX")"
awk -F: -v user="$EMAIL" -v hash="{SHA512-CRYPT}$new_hash" '
BEGIN { replaced = 0 }
{
  if ($0 ~ "^# managed-disabled:[[:space:]]*" user "$") next
  if ($1 == user) {
    if (replaced == 0) {
      print user ":" hash
      replaced = 1
    }
    next
  }
  print
}
END {
  if (replaced == 0) print user ":" hash
}
' "$USERS_FILE" > "$rewrite_tmp"
mv "$rewrite_tmp" "$USERS_FILE"
chmod 0644 "$USERS_FILE"

count_user="$(awk -F: -v u="$EMAIL" '$1==u{c++} END{print c+0}' "$USERS_FILE")"
[[ "$count_user" == "1" ]] || fail "Quantidade de linhas para $EMAIL apos rewrite: $count_user"
log "Linha da conta atualizada no users"

# 6) Validacoes finais (hash e auth)
H="$(awk -F: -v u="$EMAIL" '$1==u{v=$2; sub(/^\{SHA512-CRYPT\}/, "", v); gsub(/\r/, "", v); print v; exit}' "$USERS_FILE")"
[[ -n "$H" ]] || fail "Nao consegui extrair hash final da conta"

docker exec "$DOVECOT_CONTAINER" doveadm pw -t "{SHA512-CRYPT}$H" -p "$PASSWORD" >/dev/null

conf_snippet="$(docker exec "$DOVECOT_CONTAINER" doveconf -n | grep -E 'auth_username_format|passdb|passwd_file_path|userdb' || true)"
if grep -q 'passdb static {' <<<"$conf_snippet"; then
  printf '%s\n' "$conf_snippet"
  fail "passdb static ainda detectado no dovecot ativo"
fi

set +e
auth_out="$(docker exec "$DOVECOT_CONTAINER" doveadm auth test "$EMAIL" "$PASSWORD" 2>&1)"
auth_code=$?
set -e
if [[ $auth_code -ne 0 ]]; then
  printf '%s\n' "$auth_out"
  printf '%s\n' "$conf_snippet"
  fail "doveadm auth test falhou para $EMAIL"
fi

log "Auth OK: $auth_out"
log "Concluido: hash + passdb + users file corrigidos"
printf '\nComando de conferencia:\n'
printf "docker exec %s doveadm auth test '%s' '<SENHA>'\n" "$DOVECOT_CONTAINER" "$EMAIL"
