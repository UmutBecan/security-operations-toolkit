#!/usr/bin/env bash
# Example: daily posture check for a list of domains you own.
# Writes one JSON report per domain and prints the domains that need attention.
# Schedule with cron, e.g.:  0 7 * * *  /opt/secops/examples/scheduled-check.sh
set -uo pipefail

TOOLKIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DOMAINS_FILE="${DOMAINS_FILE:-${TOOLKIT_DIR}/domains.txt}"   # one domain per line
OUT_DIR="${OUT_DIR:-/var/tmp/secops/$(date +%F)}"
mkdir -p "${OUT_DIR}"

attention=0
while IFS= read -r domain; do
  [[ -z "${domain}" || "${domain}" == \#* ]] && continue
  node "${TOOLKIT_DIR}/bin/secops.mjs" all "${domain}" --json >"${OUT_DIR}/${domain}.json"
  case $? in
    0) ;;
    2) echo "ATTENTION ${domain} (see ${OUT_DIR}/${domain}.json)"; attention=1 ;;
    *) echo "ERROR     ${domain} (invalid domain or usage error)"; attention=1 ;;
  esac
done <"${DOMAINS_FILE}"

exit "${attention}"
