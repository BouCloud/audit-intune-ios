#!/usr/bin/env bash
# =============================================================================
# audit_intune_ios.sh - Audit TLS des serveurs d'enrôlement Intune pour iOS 27
#
# Depuis iOS / iPadOS / macOS 27, Apple refuse les connexions MDM et d'enrôlement
# vers un serveur dont le TLS n'est pas conforme (ATS / FCP v2.1). En BYOD Intune,
# l'iPhone affiche alors « Your Apple Account does not support the expected services ».
# Référence : https://support.apple.com/en-qa/126655
#
# Le script audite le serveur qui publie /.well-known/com.apple.remotemanagement
# (site public ou reverse proxy du domaine), vérifie le fichier de découverte Intune,
# puis récapitule chaque exigence Apple.
#
# Portable : tout Linux (RHEL/Rocky/Alma, Debian/Ubuntu, SUSE, Alpine) et macOS avec
# un OpenSSL Homebrew. Lecture seule : peut viser un serveur distant.
# Pré-requis : bash, openssl (1.1.1+ recommandé pour TLS 1.3 et l'EMS), curl (optionnel)
#
# Usage   : ./audit_intune_ios.sh <hôte> [port] [nom_SNI]
# Exemples: ./audit_intune_ios.sh example.com
#           ./audit_intune_ios.sh 10.0.0.12 443 example.com    (IP interne, nom public en SNI)
# Options : OPENSSL=/chemin/openssl   binaire OpenSSL client à utiliser
#           WELLKNOWN=0              ne pas tester le fichier de découverte
# Code retour : 0 conforme, 1 non conforme, 2 erreur de connexion / usage
# =============================================================================

VERSION="1.2.0"
HOST="${1:-}"; PORT="${2:-443}"; SNI="${3:-$HOST}"
OPENSSL="${OPENSSL:-openssl}"; WELLKNOWN="${WELLKNOWN:-1}"; TMO=6
[ -z "$HOST" ] && { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
command -v "$OPENSSL" >/dev/null 2>&1 || { echo "openssl introuvable"; exit 2; }

# Comptage des caractères en UTF-8 (alignement du récapitulatif)
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *[Uu][Tt][Ff]*) ;; *) export LC_ALL=C.UTF-8 2>/dev/null ;; esac

PASS=0; WARN=0; FAIL=0
if [ -t 1 ]; then R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[1;34m'; N='\033[0m'; else R=; G=; Y=; B=; N=; fi
ok()   { printf "  ${G}[PASS]${N} %s\n" "$*"; PASS=$((PASS+1)); }
warn() { printf "  ${Y}[WARN]${N} %s\n" "$*"; WARN=$((WARN+1)); }
ko()   { printf "  ${R}[FAIL]${N} %s\n" "$*"; FAIL=$((FAIL+1)); }
info() { printf "  [INFO] %s\n" "$*"; }
titre(){ printf "\n${B}=== %s ===${N}\n" "$*"; }
pad()  { local s="$1" n=$(( $2 - ${#1} )); [ "$n" -gt 0 ] && s="$s$(printf '%*s' "$n" '')"; printf '%s' "$s"; }

# timeout absent (macOS, certains BusyBox) : exécution sans limite
if command -v timeout >/dev/null 2>&1; then TO="timeout $TMO"; else TO=""; fi

# OpenSSL 3 refuse TLS 1.0/1.1 côté client sans @SECLEVEL=0 : sans ça, un serveur
# laxiste apparaîtrait faussement conforme.
LOWSEC=""
"$OPENSSL" ciphers 'DEFAULT:@SECLEVEL=0' >/dev/null 2>&1 && LOWSEC=':@SECLEVEL=0'

sclient()  { echo | $TO "$OPENSSL" s_client -connect "$HOST:$PORT" -servername "$SNI" "$@" 2>&1; }
negocie()  { sclient "$@" | sed -n 's/.*Cipher is \(.*\)$/\1/p' | head -1 | grep -v '(NONE)'; }
supporte() { "$OPENSSL" s_client -help 2>&1 | grep -q -- "-$1[ ,]"; }
conforme12() { case "$1" in ECDHE-*-AES128-GCM-SHA256|ECDHE-*-AES256-GCM-SHA384) return 0;; esac; return 1; }

OVER=$("$OPENSSL" version | awk '{print $2}')
moderne() { printf '%s\n%s\n' 1.1.1 "$(echo "$OVER" | tr -cd '0-9.')" | sort -V -C 2>/dev/null; }

APPLE_SUITES="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"

# Statut de chaque exigence pour le récapitulatif final (OK / KO / ALERTE / ?)
R_TLS12="?"; R_OLD="?"; R_TLS13="?"; R_SUITE="?"; R_EXTRA="?"; R_EMS="?"; R_SIM="?"
R_HSIG="?"; R_CSIG="?"; R_KEY="?"; R_VALID="?"; R_SAN="?"; R_CHAIN="?"; R_WK=""; R_JSON=""

printf "audit_intune_ios.sh %s - exigences TLS Apple iOS 27 pour l'enrôlement Intune\n" "$VERSION"

# -----------------------------------------------------------------------------
titre "1. Environnement"
info "Cible  : $HOST:$PORT  (SNI : $SNI)"
info "Client : $("$OPENSSL" version)"
moderne || warn "Client OpenSSL $OVER : TLS 1.3 et EMS non testables, utiliser OPENSSL=<openssl 1.1.1+>"
for s in "httpd -v" "apache2 -v" "nginx -v" "haproxy -v"; do
  b=${s%% *}; command -v "$b" >/dev/null 2>&1 && info "Local  : $($s 2>&1 | head -1)"
done
sclient | grep -q CONNECTED || { ko "Connexion impossible à $HOST:$PORT"; exit 2; }

# -----------------------------------------------------------------------------
titre "2. Versions de protocole"
R_OLD="OK"
for p in tls1 tls1_1 tls1_2 tls1_3; do
  supporte "$p" || { info "$p : non testable avec ce client"; continue; }
  case $p in
    tls1|tls1_1) c=$(negocie -"$p" -cipher "DEFAULT$LOWSEC")
                 if [ -n "$c" ]; then ko "$p ACCEPTÉ ($c) : à désactiver"; R_OLD="KO"; else ok "$p refusé"; fi ;;
    tls1_2)      c=$(negocie -tls1_2)
                 if [ -n "$c" ]; then ok "TLS 1.2 accepté"; R_TLS12="OK"; else ko "TLS 1.2 refusé : obligatoire"; R_TLS12="KO"; fi ;;
    tls1_3)      c=$(negocie -tls1_3)
                 if [ -n "$c" ]; then ok "TLS 1.3 accepté ($c)"; R_TLS13="OK"; else warn "TLS 1.3 non proposé (recommandé)"; R_TLS13="ALERTE"; fi ;;
  esac
done

# -----------------------------------------------------------------------------
titre "3. Suites TLS 1.2 acceptées"
nok=0; nko=0
for c in $("$OPENSSL" ciphers "ALL:COMPLEMENTOFALL$LOWSEC" 2>/dev/null | tr ':' ' '); do
  case $c in TLS_*) continue;; esac          # suites TLS 1.3, hors périmètre TLS 1.2
  r=$(negocie -tls1_2 -cipher "$c$LOWSEC"); [ -z "$r" ] && continue
  if conforme12 "$r"; then printf "    ${G}OK  ${N} %s\n" "$r"; nok=$((nok+1))
  else printf "    ${Y}HORS${N} %s\n" "$r"; nko=$((nko+1)); fi
done
if [ "$nok" -gt 0 ]; then ok "$nok suite(s) ECDHE + AES-GCM acceptée(s)"; R_SUITE="OK"
else ko "Aucune suite ECDHE + AES-GCM : un appareil Apple ne pourra pas se connecter"; R_SUITE="KO"; fi
# Une suite hors liste Apple n'est jamais choisie par iOS (il ne la propose pas) : durcissement, pas blocage
if [ "$nko" -eq 0 ]; then ok "Aucune suite hors liste Apple"; R_EXTRA="OK"
else warn "$nko suite(s) hors liste Apple (DHE, CHACHA20, CBC...) : non bloquant, à retirer pour durcir"; R_EXTRA="ALERTE"; fi

# -----------------------------------------------------------------------------
titre "4. Extended Master Secret et signature"
OUT=$(sclient -tls1_2)
if moderne; then
  case "$(echo "$OUT" | sed -n 's/.*Extended master secret: *//p' | head -1)" in
    yes) ok "Extended Master Secret négocié"; R_EMS="OK" ;;
    no)  ko "Extended Master Secret ABSENT : bloquant pour iOS 27 (OpenSSL serveur < 1.1.0)"; R_EMS="KO" ;;
    *)   warn "EMS : résultat indéterminé" ;;
  esac
else
  warn "EMS non vérifiable avec ce client"
fi
DIG=$(echo "$OUT" | sed -n 's/.*Peer signing digest: *//p' | head -1)
case "$DIG" in
  "") info "Algorithme de signature du handshake non affiché" ;;
  *[Ss][Hh][Aa]1) ko "Signature du handshake en SHA1"; R_HSIG="KO" ;;
  *) ok "Signature du handshake : $DIG"; R_HSIG="OK" ;;
esac

# Simulation d'un iPhone en mode FCP v2.1 : TLS 1.2 seul, uniquement les suites autorisées
SIM=$(sclient -tls1_2 -cipher "$APPLE_SUITES")
SIMC=$(echo "$SIM" | sed -n 's/.*Cipher is \(.*\)$/\1/p' | head -1 | grep -v '(NONE)')
SIME=$(echo "$SIM" | sed -n 's/.*Extended master secret: *//p' | head -1)
if [ -z "$SIMC" ]; then ko "Simulation client Apple (TLS 1.2 FCP) : connexion refusée"; R_SIM="KO"
elif moderne && [ "$SIME" != "yes" ]; then ko "Simulation client Apple : $SIMC, mais sans EMS"; R_SIM="KO"
else ok "Simulation client Apple (TLS 1.2 FCP) : $SIMC${SIME:+, EMS $SIME}"; R_SIM="OK"; fi

# -----------------------------------------------------------------------------
titre "5. Certificat"
CERT=$(echo "$OUT" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p')
if [ -z "$CERT" ]; then ko "Certificat non récupéré"; R_CSIG="KO"; else
  TXT=$(echo "$CERT" | "$OPENSSL" x509 -noout -text 2>/dev/null)
  info "Sujet    : $(echo "$CERT" | "$OPENSSL" x509 -noout -subject -nameopt utf8,sep_comma_plus_space 2>/dev/null | sed 's/^subject= *//')"
  info "Émis par : $(echo "$CERT" | "$OPENSSL" x509 -noout -issuer -nameopt utf8,sep_comma_plus_space 2>/dev/null | sed 's/^issuer= *//')"
  SIG=$(echo "$TXT" | awk -F': ' '/Signature Algorithm/{print $2; exit}')
  if echo "$SIG" | grep -qiE 'sha(256|384|512)|ecdsa-with-SHA(256|384)|ED25519'; then ok "Signature : $SIG"; R_CSIG="OK"
  else ko "Signature faible : $SIG"; R_CSIG="KO"; fi
  BITS=$(echo "$TXT" | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -1)
  if echo "$TXT" | grep -q 'rsaEncryption'; then
    if [ "${BITS:-0}" -ge 2048 ]; then ok "Clé RSA $BITS bits"; R_KEY="OK"; else ko "Clé RSA $BITS bits (< 2048)"; R_KEY="KO"; fi
  else
    if [ "${BITS:-0}" -ge 256 ]; then ok "Clé ECDSA $BITS bits"; R_KEY="OK"; else ko "Clé $BITS bits (< 256)"; R_KEY="KO"; fi
  fi
  if echo "$CERT" | "$OPENSSL" x509 -noout -checkend 0 >/dev/null 2>&1; then
    END=$(echo "$CERT" | "$OPENSSL" x509 -noout -enddate | cut -d= -f2)
    if echo "$CERT" | "$OPENSSL" x509 -noout -checkend 2592000 >/dev/null 2>&1; then ok "Valide jusqu'au $END"; R_VALID="OK"
    else warn "Expire dans moins de 30 jours ($END)"; R_VALID="ALERTE"; fi
  else ko "Certificat EXPIRÉ"; R_VALID="KO"; fi
  if echo "$TXT" | grep -q 'Subject Alternative Name'; then ok "Extension SAN présente"; R_SAN="OK"
  else ko "Pas d'extension SAN"; R_SAN="KO"; fi
  V=$(echo "$OUT" | sed -n 's/.*Verify return code: *//p' | tail -1)
  case "$V" in 0\ *) ok "Chaîne de confiance valide"; R_CHAIN="OK" ;;
               *) warn "Chaîne : $V (CA interne ? elle doit être de confiance sur les appareils)"; R_CHAIN="ALERTE" ;; esac
fi

# -----------------------------------------------------------------------------
if [ "$WELLKNOWN" = 1 ] && command -v curl >/dev/null 2>&1; then
  titre "6. Fichier de découverte Intune (BYOD account-driven)"
  # --resolve n'accepte qu'une IP : utilisé seulement si la cible est une adresse
  # (cible IP = serveur visé directement : pas de proxy HTTP)
  case "$HOST" in *[!0-9.:]*) RESOLVE="" ;; *) RESOLVE="--resolve $SNI:$PORT:$HOST --noproxy $SNI" ;; esac
  URL="https://$SNI:$PORT/.well-known/com.apple.remotemanagement"
  info "Rôle : en BYOD (account-driven User Enrollment), l'iPhone lit ce fichier sur le domaine"
  info "       de l'adresse saisie par l'utilisateur pour savoir quel MDM contacter (ici Intune)."
  info "URL testée : $URL"
  BODY=$(curl -sk --max-time "$TMO" $RESOLVE -w '\n__HTTP__%{http_code} %{content_type}' "$URL" 2>/dev/null)
  META=$(printf '%s' "$BODY" | sed -n 's/^__HTTP__//p'); BODY=$(printf '%s' "$BODY" | sed '/^__HTTP__/d')
  CODE=${META%% *}; CTYPE=${META#* }
  case "$CODE" in
    200) R_WK="présent"
         ok "Fichier présent (HTTP 200) : ce serveur est sur le chemin d'enrôlement iOS 27"
         case "$CTYPE" in *json*) ok "Content-Type : $CTYPE" ;; *) warn "Content-Type '$CTYPE' (attendu : application/json)" ;; esac
         VERS=$(printf '%s' "$BODY" | grep -o '"Version"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/' | tr '\n' ' ' | sed 's/ *$//')
         BASE=$(printf '%s' "$BODY" | grep -o '"BaseURL"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\(https\{0,1\}:[^"]*\)"$/\1/')
         if [ -n "$VERS" ] && [ -n "$BASE" ]; then
           R_JSON="OK"
           ok "Version(s) déclarée(s) : $VERS"
           echo "$VERS" | grep -q 'mdm-byod' || warn "Pas de version 'mdm-byod' : l'enrôlement BYOD account-driven ne sera pas proposé"
           info "BaseURL : $BASE"
           case "$BASE" in
             https://*manage.microsoft.com*) ok "BaseURL pointe vers Microsoft Intune" ;;
             https://*) info "BaseURL hors Intune (autre MDM ?)" ;;
             *) ko "BaseURL non HTTPS"; R_JSON="KO" ;;
           esac
           # Côté Microsoft : contrôle informatif, non actionnable par l'organisation
           BHOST=$(echo "$BASE" | sed 's#^https://\([^/:?]*\).*#\1#')
           if [ -n "$BHOST" ] && moderne; then
             MS=$(echo | $TO "$OPENSSL" s_client -connect "$BHOST:443" -servername "$BHOST" -tls1_2 -cipher "$APPLE_SUITES" 2>&1)
             if echo "$MS" | grep -q 'Extended master secret: yes'; then info "Service $BHOST : TLS 1.2 FCP + EMS OK (côté Microsoft)"
             else info "Service $BHOST : non vérifié depuis ce poste (proxy, filtrage ?)"; fi
           fi
         else
           R_JSON="KO"; ko "Contenu JSON non reconnu (attendu : Servers[].Version et BaseURL)"
         fi ;;
    30*) R_WK="redirigé"; warn "Fichier redirigé (HTTP $CODE) : la cible doit aussi être conforme, préférer une réponse directe" ;;
    000) R_WK="injoignable"; info "Endpoint injoignable" ;;
    *)   R_WK="absent"; info "Fichier absent (HTTP $CODE) : serveur non utilisé pour l'enrôlement BYOD" ;;
  esac
fi

# -----------------------------------------------------------------------------
titre "7. Exigences Apple iOS 27 (support.apple.com/126655)"
ligne() { # $1 statut, $2 exigence, $3 niveau
  case "$1" in
    OK)     col="$G"; txt="OK    " ;;
    KO)     col="$R"; txt="KO    " ;;
    ALERTE) col="$Y"; txt="ALERTE" ;;
    *)      col="";   txt="?     " ;;
  esac
  printf "  ${col}%s${N}  %s %s\n" "$txt" "$(pad "$2" 52)" "$3"
}
printf "  %-6s  %s %s\n" "Statut" "$(pad Exigence 52)" "Niveau"
printf "  %s\n" "------------------------------------------------------------------------------"
ligne "$R_TLS12" "TLS 1.2 accepté"                                  "obligatoire"
ligne "$R_OLD"   "SSLv3 / TLS 1.0 / TLS 1.1 refusés"                "obligatoire"
ligne "$R_SUITE" "Suites ECDHE + AES-GCM (SHA-256/384) en TLS 1.2"  "obligatoire"
ligne "$R_EMS"   "Extended Master Secret (RFC 7627) en TLS 1.2"     "obligatoire"
ligne "$R_HSIG"  "Signature du handshake SHA-256+ (pas SHA-1)"      "obligatoire"
ligne "$R_CSIG"  "Certificat signé en SHA-256+"                     "obligatoire"
ligne "$R_KEY"   "Clé RSA >= 2048 bits ou ECDSA >= 256 bits"        "obligatoire"
ligne "$R_VALID" "Certificat en cours de validité"                  "obligatoire"
ligne "$R_SAN"   "Extension SAN (nom du serveur)"                   "obligatoire"
ligne "$R_CHAIN" "Chaîne de confiance reconnue par l'appareil"      "obligatoire"
ligne "$R_SIM"   "Connexion d'un client Apple FCP v2.1 simulé"      "synthèse"
ligne "$R_TLS13" "TLS 1.3 proposé"                                  "recommandé"
ligne "$R_EXTRA" "Aucune suite hors liste Apple acceptée"           "durcissement"
[ -n "$R_JSON" ] && ligne "$R_JSON" "Fichier de découverte Intune valide"   "BYOD Intune"
[ -n "$R_WK" ]   && printf "  %-6s  %s %s\n" "INFO" "$(pad "/.well-known/com.apple.remotemanagement" 52)" "$R_WK"

# -----------------------------------------------------------------------------
titre "Synthèse"
printf "  PASS: %s   WARN: %s   FAIL: %s\n" "$PASS" "$WARN" "$FAIL"
if [ "$FAIL" -eq 0 ]; then
  printf "  ${G}Conforme aux exigences iOS 27.${N}\n"
  printf "  Validation finale (Mac) : nscurl --ats-diagnostics https://%s/.well-known/com.apple.remotemanagement\n" "$SNI"
  exit 0
fi
printf "  ${R}Non conforme aux exigences iOS 27.${N}\n"; exit 1
