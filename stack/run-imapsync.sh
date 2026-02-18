#!/bin/sh
set -eu

# Rode dentro do container imapsync
imapsync \
  --host1 imap.hostgator.com \
  --user1 'suportetisorriso@solturi.com.br' \
  --password1 'SENHA_REAL_AQUI' \
  --ssl1 \
  --host2 mailarchive_dovecot \
  --port2 31143 \
  --user2 'suporte.ti.sorriso@archive.local' \
  --password2 '@Solturi#2025@' \
  --syncinternaldates \
  --subscribeall \
  --nofoldersizes \
  --fast
