#!/usr/bin/env bash
# =============================================================================
# setup.sh — Configuração inicial do Mail Archive Stack
# Uso: bash setup.sh
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { printf "${GREEN}[OK]${NC}  %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
step()    { printf "\n${CYAN}==>${NC} %s\n" "$*"; }
fail()    { printf "${RED}[ERRO]${NC} %s\n" "$*" >&2; exit 1; }

ask() {
  # ask <VAR_NAME> <prompt> [default]
  local var="$1" prompt="$2" default="${3:-}"
  local current="${!var:-}"
  if [[ -n "$current" ]]; then
    info "$var já definido — mantendo valor existente."
    return
  fi
  if [[ -n "$default" ]]; then
    printf "%s [%s]: " "$prompt" "$default"
  else
    printf "%s: " "$prompt"
  fi
  local value
  read -r value
  value="${value:-$default}"
  while [[ -z "$value" ]]; do
    printf "  ↳ Este campo é obrigatório. %s: " "$prompt"
    read -r value
  done
  printf -v "$var" '%s' "$value"
}

ask_secret() {
  # ask_secret <VAR_NAME> <prompt>
  local var="$1" prompt="$2"
  local current="${!var:-}"
  if [[ -n "$current" ]]; then
    info "$var já definido — mantendo valor existente."
    return
  fi
  local value confirm
  while true; do
    printf "%s (não é exibido): " "$prompt"
    read -rs value; echo
    [[ -z "$value" ]] && { warn "Campo obrigatório."; continue; }
    printf "  ↳ Confirme a senha: "
    read -rs confirm; echo
    [[ "$value" == "$confirm" ]] && break
    warn "As senhas não conferem. Tente novamente."
  done
  printf -v "$var" '%s' "$value"
}

gen_fernet_key() {
  # Gera chave Fernet (32 bytes URL-safe base64) via Python3
  if command -v python3 &>/dev/null; then
    python3 -c "
import base64, os
key = base64.urlsafe_b64encode(os.urandom(32))
print(key.decode())
"
  elif command -v openssl &>/dev/null; then
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | head -c 44
    echo
  else
    fail "python3 ou openssl são necessários para gerar chaves seguras."
  fi
}

gen_secret() {
  local length="${1:-32}"
  if command -v python3 &>/dev/null; then
    python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range($length)))"
  elif command -v openssl &>/dev/null; then
    openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c "$length"
    echo
  else
    fail "python3 ou openssl são necessários para gerar chaves seguras."
  fi
}

# ---------------------------------------------------------------------------
# Detectar diretório base (pasta pai de stack/)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIL_BASE="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

step "Mail Archive Stack — Setup"
echo "  Diretório base detectado: $MAIL_BASE"
echo "  Arquivo .env: $ENV_FILE"

# ---------------------------------------------------------------------------
# Verificar dependências
# ---------------------------------------------------------------------------
step "Verificando dependências"
for cmd in docker; do
  command -v "$cmd" &>/dev/null && info "$cmd encontrado" || fail "$cmd não encontrado. Instale o Docker antes de continuar."
done
docker compose version &>/dev/null && info "docker compose (plugin) encontrado" || {
  command -v docker-compose &>/dev/null && info "docker-compose (standalone) encontrado" || \
    fail "Nem 'docker compose' nem 'docker-compose' encontrado."
}

# ---------------------------------------------------------------------------
# Carregar .env existente (se houver)
# ---------------------------------------------------------------------------
if [[ -f "$ENV_FILE" ]]; then
  warn ".env já existe — carregando valores existentes. Campos em branco serão preenchidos."
  # Exporta as variáveis sem sobrescrever o ambiente atual
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
else
  info "Nenhum .env encontrado — será criado agora."
fi

# ---------------------------------------------------------------------------
# Coletar variáveis
# ---------------------------------------------------------------------------
step "Configurando variáveis do ambiente"

# ----- Auto-geradas -----
if [[ -z "${MASTER_KEY:-}" ]]; then
  MASTER_KEY="$(gen_fernet_key)"
  info "MASTER_KEY gerada automaticamente (Fernet 256-bit)"
fi

if [[ -z "${FLASK_SECRET_KEY:-}" ]]; then
  FLASK_SECRET_KEY="$(gen_secret 48)"
  info "FLASK_SECRET_KEY gerada automaticamente"
fi

if [[ -z "${ROUNDCUBE_DES_KEY:-}" ]]; then
  ROUNDCUBE_DES_KEY="$(gen_secret 24)"
  info "ROUNDCUBE_DES_KEY gerada automaticamente (24 chars)"
fi

# ----- MAIL_BASE -----
if [[ -z "${MAIL_BASE_ENV:-}" ]]; then
  MAIL_BASE_ENV="$MAIL_BASE"
  info "MAIL_BASE definido como: $MAIL_BASE_ENV"
fi

# ----- Banco de dados -----
echo ""
echo "--- Banco de dados (PostgreSQL / Roundcube) ---"
ask_secret ROUNDCUBE_DB_PASSWORD "Senha do banco Roundcube (ROUNDCUBE_DB_PASSWORD)"

# ----- Cloudflare -----
echo ""
echo "--- Cloudflare Tunnel ---"
echo "  (Deixe em branco para pular — o container cloudflared não vai funcionar)"
printf "Token do Cloudflare Tunnel (CLOUDFLARE_TUNNEL_TOKEN): "
read -rs CLOUDFLARE_TUNNEL_TOKEN_INPUT; echo
if [[ -z "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]]; then
  CLOUDFLARE_TUNNEL_TOKEN="${CLOUDFLARE_TUNNEL_TOKEN_INPUT:-CONFIGURE_ME}"
  [[ "$CLOUDFLARE_TUNNEL_TOKEN" == "CONFIGURE_ME" ]] && warn "Cloudflare Tunnel não configurado. Edite o .env antes de usar em produção."
fi

# ----- Admin do painel -----
echo ""
echo "--- Painel Flask Admin ---"
ask ADMIN_USER "Usuário admin do painel (ADMIN_USER)" "admin"
ask_secret ADMIN_PASSWORD "Senha do admin do painel (ADMIN_PASSWORD)"

# ----- URLs -----
echo ""
echo "--- URLs de acesso ---"
# Tenta detectar o IP do servidor automaticamente
DETECTED_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")"
ask ROUNDCUBE_TEST_URL "URL do Roundcube (ROUNDCUBE_TEST_URL)" "http://${DETECTED_IP}:8080"
ask ROUNDCUBE_PROD_URL "URL de produção Roundcube (ROUNDCUBE_PROD_URL)" "https://webmail.seudominio.com"

# ---------------------------------------------------------------------------
# Gravar .env
# ---------------------------------------------------------------------------
step "Gravando $ENV_FILE"
cat > "$ENV_FILE" <<EOF
# =============================================================================
# Mail Archive Stack — Configuração gerada por setup.sh em $(date '+%Y-%m-%d %H:%M:%S')
# NÃO versione este arquivo. Ele contém segredos.
# =============================================================================

# Diretório base dos dados no host (gerado automaticamente)
MAIL_BASE=${MAIL_BASE_ENV}

# --- Banco de dados ---
ROUNDCUBE_DB_PASSWORD=${ROUNDCUBE_DB_PASSWORD}

# --- Roundcube ---
ROUNDCUBE_DES_KEY=${ROUNDCUBE_DES_KEY}

# --- Cloudflare Tunnel ---
CLOUDFLARE_TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN}

# --- Painel Flask Admin ---
MASTER_KEY=${MASTER_KEY}
FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}

# --- URLs ---
ROUNDCUBE_TEST_URL=${ROUNDCUBE_TEST_URL}
ROUNDCUBE_PROD_URL=${ROUNDCUBE_PROD_URL}
EOF
chmod 600 "$ENV_FILE"
info ".env gravado com permissão 600"

# ---------------------------------------------------------------------------
# Criar diretórios de dados no host
# ---------------------------------------------------------------------------
step "Criando estrutura de diretórios em $MAIL_BASE_ENV"
DIRS=(
  "$MAIL_BASE_ENV/mail"
  "$MAIL_BASE_ENV/roundcube-db"
  "$MAIL_BASE_ENV/roundcube-config"
  "$MAIL_BASE_ENV/dovecot-users"
  "$MAIL_BASE_ENV/imapsync-logs"
  "$MAIL_BASE_ENV/imap-admin-data"
)
for d in "${DIRS[@]}"; do
  mkdir -p "$d"
  info "  $d"
done

# Criar arquivo users vazio se não existir (Dovecot exige que exista)
USERS_FILE="$MAIL_BASE_ENV/dovecot-users/users"
if [[ ! -f "$USERS_FILE" ]]; then
  touch "$USERS_FILE"
  chmod 644 "$USERS_FILE"
  info "Arquivo users criado: $USERS_FILE"
else
  info "Arquivo users já existe: $USERS_FILE"
fi

# ---------------------------------------------------------------------------
# Subir o stack
# ---------------------------------------------------------------------------
step "Subindo o stack com docker compose"
cd "$SCRIPT_DIR"

compose_up() {
  if docker compose version &>/dev/null 2>&1; then
    docker compose --env-file "$ENV_FILE" up -d --build "$@"
  else
    docker-compose --env-file "$ENV_FILE" up -d --build "$@"
  fi
}

compose_up

# ---------------------------------------------------------------------------
# Aguardar serviços ficarem saudáveis
# ---------------------------------------------------------------------------
step "Aguardando serviços iniciarem (até 60s)..."
TIMEOUT=60
ELAPSED=0
ALL_UP=false
while (( ELAPSED < TIMEOUT )); do
  sleep 5
  ELAPSED=$((ELAPSED + 5))
  NOT_RUNNING=0
  for container in roundcube_db mailarchive_dovecot mailarchive_roundcube mailarchive_imap_admin mailarchive_imapsync; do
    STATUS="$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "missing")"
    if [[ "$STATUS" != "running" ]]; then
      NOT_RUNNING=$((NOT_RUNNING + 1))
    fi
  done
  if (( NOT_RUNNING == 0 )); then
    ALL_UP=true
    break
  fi
  printf "  ... %ds aguardando (%d container(s) não running)\n" "$ELAPSED" "$NOT_RUNNING"
done

echo ""
if [[ "$ALL_UP" == "true" ]]; then
  info "Todos os containers estão running!"
else
  warn "Alguns containers podem ainda estar iniciando. Execute 'docker compose ps' para verificar."
fi

# ---------------------------------------------------------------------------
# Resumo final
# ---------------------------------------------------------------------------
step "Setup concluído!"
cat <<SUMMARY

  Acesse o sistema:
    Painel Admin : ${ROUNDCUBE_TEST_URL/8080/8081}
                   (usuário: ${ADMIN_USER} / senha: como definida)
    Roundcube    : ${ROUNDCUBE_TEST_URL}

  Próximos passos:
    1. Abra o Painel Admin e crie uma conta local (ex: usuario@archive.local)
    2. A senha é exibida apenas uma vez — salve-a
    3. Faça login no Roundcube com essa conta para validar
    4. Crie uma Source IMAP para importar emails de origem

  Comandos úteis:
    Ver logs do painel  : docker logs -f mailarchive_imap_admin
    Ver logs do Dovecot : docker logs -f mailarchive_dovecot
    Status dos serviços : docker compose ps
    Parar tudo          : docker compose down
    Recriar tudo        : docker compose up -d --build

  Arquivo .env: $ENV_FILE  (não commite este arquivo!)

SUMMARY
