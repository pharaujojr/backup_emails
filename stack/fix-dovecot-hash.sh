#!/usr/bin/env bash
set -euo pipefail

EMAIL="${1:-}"
PASSWORD="${2:-}"

if [[ -z "$EMAIL" || -z "$PASSWORD" ]]; then
  echo "Uso: $0 <email> <senha>"
  echo "Exemplo: $0 paulo@archive.local 'PauloArchive2026!'"
  exit 1
fi

USERS_FILE="${USERS_FILE:-/home/paulo/PROJETOS/MAIL_SERVER/dovecot-users/users}"
DOVECOT_CONTAINER="${DOVECOT_CONTAINER:-mailarchive_dovecot}"
EXPECTED_USERS_PATH="/etc/dovecot/dovecot-users/users"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Erro: comando obrigatório não encontrado: $1"
    exit 1
  }
}

warn() {
  echo "[WARN] $*"
}

info() {
  echo "[INFO] $*"
}

fail() {
  echo "[ERRO] $*"
  exit 1
}

need_cmd docker
need_cmd awk
need_cmd sed
need_cmd tr
need_cmd mktemp
need_cmd date
need_cmd grep
need_cmd cmp

[[ -f "$USERS_FILE" ]] || fail "Arquivo users não encontrado: $USERS_FILE"

status="$(docker inspect -f '{{.State.Status}}' "$DOVECOT_CONTAINER" 2>/dev/null || true)"
[[ "$status" == "running" ]] || fail "Container $DOVECOT_CONTAINER não está running (status=${status:-desconhecido})"

info "Conta alvo: $EMAIL"
info "Arquivo users: $USERS_FILE"
info "Container dovecot: $DOVECOT_CONTAINER"

conf_out="$(docker exec "$DOVECOT_CONTAINER" doveconf -n 2>/dev/null || true)"
if [[ -z "$conf_out" ]]; then
  warn "Não foi possível ler doveconf -n. Seguindo com validações de hash/auth."
else
  if grep -q 'passdb static {' <<<"$conf_out"; then
    warn "Detectado 'passdb static {' no Dovecot. Isso pode quebrar autenticação de usuários finais."
  fi
  if ! grep -q "passwd_file_path = ${EXPECTED_USERS_PATH}" <<<"$conf_out"; then
    warn "passwd_file_path diferente de ${EXPECTED_USERS_PATH}. Revise auth.conf."
  fi
fi

backup="${USERS_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
cp -a "$USERS_FILE" "$backup"
info "Backup criado: $backup"

# Remove CRLF para evitar mismatch silencioso no hash.
crlf_tmp="$(mktemp "${USERS_FILE}.crlf.XXXXXX")"
tr -d '\r' < "$USERS_FILE" > "$crlf_tmp"
if ! cmp -s "$USERS_FILE" "$crlf_tmp"; then
  mv "$crlf_tmp" "$USERS_FILE"
  info "CRLF removido do arquivo users"
else
  rm -f "$crlf_tmp"
fi

current_count="$(awk -F: -v u="$EMAIL" '$1==u{c++} END{print c+0}' "$USERS_FILE")"
info "Linhas atuais da conta no users: $current_count"

new_hash_raw="$(docker exec "$DOVECOT_CONTAINER" doveadm pw -s SHA512-CRYPT -p "$PASSWORD" | tr -d '\r' | tail -n 1)"
new_hash="$new_hash_raw"
new_hash="${new_hash#\{SHA512-CRYPT\}}"

[[ "$new_hash" == '$6$'* ]] || fail "Hash gerado não começou com \$6\$: $new_hash_raw"
[[ ${#new_hash} -ge 90 ]] || fail "Hash gerado muito curto: ${#new_hash}"

if ! docker exec "$DOVECOT_CONTAINER" doveadm pw -t "{SHA512-CRYPT}$new_hash" -p "$PASSWORD" >/dev/null 2>&1; then
  fail "Falha no auto-teste do hash recém-gerado"
fi

rewrite_tmp="$(mktemp "${USERS_FILE}.rewrite.XXXXXX")"
awk -v user="$EMAIL" -v hash="{SHA512-CRYPT}$new_hash" -F: '
BEGIN { replaced = 0 }
{
  if ($0 ~ "^# managed-disabled:[[:space:]]*" user "$") {
    next
  }
  if ($1 == user) {
    if (replaced == 0) {
      print user ":" hash
      replaced = 1
    }
    next
  }
  print $0
}
END {
  if (replaced == 0) {
    print user ":" hash
  }
}
' "$USERS_FILE" > "$rewrite_tmp"

mv "$rewrite_tmp" "$USERS_FILE"
chmod 0644 "$USERS_FILE"

post_count="$(awk -F: -v u="$EMAIL" '$1==u{c++} END{print c+0}' "$USERS_FILE")"
[[ "$post_count" == "1" ]] || fail "Após rewrite, quantidade de linhas para $EMAIL ficou em $post_count (esperado 1)"

H="$(awk -F: -v u="$EMAIL" '$1==u{v=$2; sub(/^\{SHA512-CRYPT\}/, "", v); gsub(/\r/, "", v); print v; exit}' "$USERS_FILE")"
[[ -n "$H" ]] || fail "Não foi possível extrair hash final de $EMAIL"

if ! docker exec "$DOVECOT_CONTAINER" doveadm pw -t "{SHA512-CRYPT}$H" -p "$PASSWORD" >/dev/null 2>&1; then
  fail "Hash final no arquivo ainda não valida com a senha informada"
fi

if ! docker exec "$DOVECOT_CONTAINER" doveadm auth test "$EMAIL" "$PASSWORD" >/tmp/dovecot-auth-test.out 2>&1; then
  cat /tmp/dovecot-auth-test.out
  fail "doveadm auth test falhou"
fi
cat /tmp/dovecot-auth-test.out
rm -f /tmp/dovecot-auth-test.out

if ! docker exec "$DOVECOT_CONTAINER" doveadm reload >/dev/null 2>&1; then
  warn "doveadm reload retornou erro (pode não ser crítico para passwd-file, mas revise logs)."
fi

info "Correção concluída com sucesso para $EMAIL"
info "Teste final: docker exec $DOVECOT_CONTAINER doveadm auth test '$EMAIL' '<SENHA>'"
