#!/usr/bin/env bash
# Instalação reproduzível do DeepSeek Harness + dsh-unrestricted no Kali/Debian.
# A chave da API nunca é mostrada nem enviada aos scripts de build/teste.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_VERSION="1.0.3"
readonly NODE_VERSION="24.21.0"
readonly PNPM_VERSION="11.7.0"
readonly PNPM_TARBALL_SHA512="19cc852c120c7125760f2443ee6be0ca5b40f9f50598de1a09a1f177503e010e57c23c77646e01e761de59bf874fb22a3398c33ab9691fc13eb946b6f0f4d620"
readonly HARNESS_REPOSITORY="https://github.com/deepseek-ai/deepseek-harness.git"
readonly HARNESS_COMMIT="c291e7961a515f6d7af9304e7fd1d257929aef26"
readonly HARNESS_VERSION="0.1.5-rc.2"
readonly PLUGIN_REPOSITORY="https://github.com/yexi-by/dsh-unrestricted.git"
readonly PLUGIN_COMMIT="5c6492db717ebdc58805114ef0406967d1e4eb7b"
readonly PLUGIN_VERSION="0.1.7"
readonly PLUGIN_BUNDLE_SHA256="3c54a076de221846454114ddfcbd4a93e43fa3cb3a96e5c52e10bd0bbcbc1747"
readonly DEEPSEEK_API_BASE="https://api.deepseek.com"
readonly MIN_FREE_KIB=$((4 * 1024 * 1024))
readonly RECOMMENDED_FREE_KIB=$((6 * 1024 * 1024))

COMMAND="install"
INSTALL_DIR=""
SKIP_APT=0
QUICK=0
SKIP_API_CHECK=0
PAID_SMOKE=0
CREATE_USER_LINKS=1
NON_INTERACTIVE=0
ALLOW_ROOT=0
LOCK_FD=""
SMOKE_PID=""
SMOKE_LOG=""
SMOKE_CURL_CONFIG=""
SMOKE_COOKIE_JAR=""
BUILD_TMPDIR=""
API_TEMP_DIR=""
API_HTTP_CODE=""
API_RESPONSE_FILE=""
INSTALL_LOG=""
HARNESS_TEST_STATUS="not-run"
HARNESS_PWSH_STATUS="not-probed"
API_KEY=""
API_KEY_SOURCE=""
TEMP_FILES=()
TEMP_DIRS=()

if [[ -t 1 ]]; then
  readonly C_BLUE=$'\033[1;34m'
  readonly C_GREEN=$'\033[1;32m'
  readonly C_YELLOW=$'\033[1;33m'
  readonly C_RED=$'\033[1;31m'
  readonly C_RESET=$'\033[0m'
else
  readonly C_BLUE="" C_GREEN="" C_YELLOW="" C_RED="" C_RESET=""
fi

info() { printf '%s[INFO]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok() { printf '%s[OK]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[AVISO]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die() { printf '%s[ERRO]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Uso:
  ./install-deepseek-kali.sh [install] [opções]
  ./install-deepseek-kali.sh doctor [--install-dir CAMINHO]
  ./install-deepseek-kali.sh api-check [--install-dir CAMINHO] [--paid-smoke]

Opções de instalação:
  --install-dir CAMINHO  Raiz da instalação (padrão: ~/.local/share/deepseek-stack)
  --skip-apt             Não executar apt-get; apenas validar os pré-requisitos
  --quick                Pular somente a suíte completa do Harness
  --skip-api-check       Não consultar GET /models ao final
  --paid-smoke           Fazer também uma pequena chamada paga ao deepseek-flash
  --no-user-links        Não criar atalhos em ~/.local/bin
  --non-interactive      Não solicitar chave nem senha sudo interativamente
  --allow-root           Permitir instalação e execução como root (desaconselhado)
  -h, --help             Mostrar esta ajuda

Variáveis aceitas:
  DEEPSEEK_API_KEY        Nome correto e recomendado para a chave
  deep-key               Nome legado aceito e normalizado pelo instalador
  DEEPSEEK_STACK_HOME    Alternativa a --install-dir

O teste padrão GET /models valida autenticação sem gerar tokens. --paid-smoke
faz uma inferência real, pequena e cobrada. A opção nunca é habilitada sozinha.
USAGE
}

cleanup() {
  local exit_code=$?
  trap - EXIT
  if [[ -n "$SMOKE_PID" ]] && kill -0 "$SMOKE_PID" 2>/dev/null; then
    kill "$SMOKE_PID" 2>/dev/null || true
    wait "$SMOKE_PID" 2>/dev/null || true
  fi
  if [[ -n "$SMOKE_LOG" ]]; then
    rm -f -- "$SMOKE_LOG" "$SMOKE_CURL_CONFIG" "$SMOKE_COOKIE_JAR" 2>/dev/null || true
  fi
  if [[ -n "$BUILD_TMPDIR" ]]; then
    rm -rf -- "$BUILD_TMPDIR" 2>/dev/null || true
  fi
  if [[ -n "$API_TEMP_DIR" ]]; then
    rm -rf -- "$API_TEMP_DIR" 2>/dev/null || true
  fi
  local temporary_path
  for temporary_path in "${TEMP_FILES[@]}"; do
    [[ -n "$temporary_path" ]] && rm -f -- "$temporary_path" 2>/dev/null || true
  done
  for temporary_path in "${TEMP_DIRS[@]}"; do
    [[ -n "$temporary_path" ]] && rm -rf -- "$temporary_path" 2>/dev/null || true
  done
  if [[ -n "$LOCK_FD" ]]; then
    flock -u "$LOCK_FD" 2>/dev/null || true
    exec {LOCK_FD}>&- 2>/dev/null || true
  fi
  exit "$exit_code"
}
trap cleanup EXIT

resolve_user_home() {
  local candidate=""
  if command -v getent >/dev/null 2>&1; then
    candidate="$(getent passwd "$(id -un)" 2>/dev/null | awk -F: 'NR == 1 { print $6 }')"
  fi
  if [[ -z "$candidate" ]]; then
    candidate="${HOME:-}"
  fi
  [[ -n "$candidate" && "$candidate" == /* ]] || die "Não foi possível determinar o diretório pessoal do usuário."
  printf '%s\n' "$candidate"
}

readonly USER_HOME="$(resolve_user_home)"

parse_arguments() {
  if (($# > 0)); then
    case "$1" in
      install|doctor|api-check)
        COMMAND="$1"
        shift
        ;;
    esac
  fi

  while (($# > 0)); do
    case "$1" in
      --install-dir)
        (($# >= 2)) || die "--install-dir exige um caminho."
        INSTALL_DIR="$2"
        shift 2
        ;;
      --install-dir=*)
        INSTALL_DIR="${1#*=}"
        shift
        ;;
      --skip-apt) SKIP_APT=1; shift ;;
      --quick) QUICK=1; shift ;;
      --skip-api-check) SKIP_API_CHECK=1; shift ;;
      --paid-smoke) PAID_SMOKE=1; shift ;;
      --no-user-links) CREATE_USER_LINKS=0; shift ;;
      --non-interactive) NON_INTERACTIVE=1; shift ;;
      --allow-root) ALLOW_ROOT=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Opção ou comando desconhecido: $1" ;;
    esac
  done

  if [[ -z "$INSTALL_DIR" ]]; then
    INSTALL_DIR="${DEEPSEEK_STACK_HOME:-$USER_HOME/.local/share/deepseek-stack}"
  fi
  [[ "$INSTALL_DIR" != *$'\n'* && "$INSTALL_DIR" != *$'\r'* && "$INSTALL_DIR" != *$'\t'* ]] \
    || die "--install-dir não pode conter caracteres de controle."
  [[ "$INSTALL_DIR" == /* ]] || die "--install-dir precisa ser um caminho absoluto."
  INSTALL_DIR="$(readlink -m -- "$INSTALL_DIR")"
  [[ "$INSTALL_DIR" != "/" && "$INSTALL_DIR" != "$USER_HOME" ]] \
    || die "Escolha um subdiretório dedicado; o caminho informado é amplo demais."
  if ((SKIP_API_CHECK == 1 && PAID_SMOKE == 1)); then
    die "--skip-api-check e --paid-smoke são incompatíveis."
  fi
}

capture_environment_key() {
  local legacy_key=""
  if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
    API_KEY="$DEEPSEEK_API_KEY"
    API_KEY_SOURCE="DEEPSEEK_API_KEY"
  elif legacy_key="$(printenv 'deep-key' 2>/dev/null)" && [[ -n "$legacy_key" ]]; then
    API_KEY="$legacy_key"
    API_KEY_SOURCE="deep-key (normalizada)"
  fi

  # Não permitir que scripts de dependências e testes recebam a variável válida.
  unset DEEPSEEK_API_KEY 2>/dev/null || true
}

# Executa comandos externos removendo tanto o nome correto quanto o legado da chave.
sanitized() {
  env \
    -u DEEPSEEK_API_KEY \
    -u 'deep-key' \
    -u NODE_OPTIONS \
    -u NODE_PATH \
    -u DSH_BUILD_FACE \
    -u TS_NODE_PROJECT \
    -u TS_NODE_TRANSPILE_ONLY \
    "$@"
}

retry() {
  local max_attempts="$1"
  shift
  local attempt=1 status=0 delay=2
  while true; do
    if "$@"; then
      return 0
    else
      status=$?
    fi
    if ((attempt >= max_attempts)); then
      return "$status"
    fi
    warn "Tentativa $attempt/$max_attempts falhou (código $status); nova tentativa em ${delay}s."
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

run_logged() {
  local label="$1"
  shift
  info "$label"
  {
    printf '\n[%s] %s\n' "$(date -Is)" "$label"
    "$@"
  } 2>&1 | tee -a "$INSTALL_LOG"
}

check_platform() {
  [[ "$(uname -s)" == "Linux" ]] || die "Este instalador foi feito para Linux Kali/Debian."
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    local distro="${ID:-desconhecida} ${ID_LIKE:-}"
    if [[ "$distro" != *kali* && "$distro" != *debian* ]]; then
      if ((SKIP_APT == 0)); then
        die "Distribuição não suportada pelo modo apt: $distro. Use Kali/Debian ou --skip-apt."
      fi
      warn "Distribuição fora da matriz validada: $distro."
    fi
  fi

  case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ;;
    *) die "Arquitetura não suportada: $(uname -m). Suportadas: x86_64 e arm64." ;;
  esac

  if ((EUID == 0 && ALLOW_ROOT == 0)); then
    die "Não execute todo o ambiente como root. Rode como usuário comum; o script usará sudo apenas no apt. Use --allow-root somente se isso for deliberado."
  fi
}

install_system_dependencies() {
  local -a privilege=()
  local -a packages=(
    build-essential
    bubblewrap
    ca-certificates
    curl
    git
    jq
    pkg-config
    python3
    python3-venv
    util-linux
    xz-utils
  )

  if ((SKIP_APT == 1)); then
    info "Etapa apt ignorada por solicitação."
    return
  fi

  command -v apt-get >/dev/null 2>&1 || die "apt-get não encontrado."
  if ((EUID != 0)); then
    command -v sudo >/dev/null 2>&1 || die "sudo não encontrado; instale os pacotes como root ou use --skip-apt após prepará-los."
    if ((NON_INTERACTIVE == 1)); then
      privilege=(sudo -n)
    else
      privilege=(sudo)
    fi
  fi

  info "Atualizando o índice do apt (pode solicitar a senha sudo)..."
  retry 3 sanitized "${privilege[@]}" apt-get update
  info "Instalando compiladores, certificados e utilitários necessários..."
  retry 3 sanitized "${privilege[@]}" env DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends "${packages[@]}"
}

validate_prerequisites() {
  local required
  for required in awk bwrap c++ cc curl find flock git jq make pkg-config python3 \
    sha256sum sha512sum tar xz; do
    command -v "$required" >/dev/null 2>&1 || die "Pré-requisito ausente: $required"
  done
  local git_version
  git_version="$(git --version | awk '{ print $3 }')"
  if [[ "$(printf '%s\n' '2.26.0' "$git_version" | sort -V | head -n 1)" != "2.26.0" ]]; then
    die "Git 2.26 ou superior é necessário; encontrado $git_version."
  fi
}

prepare_directories() {
  [[ ! -L "$INSTALL_DIR" ]] \
    || die "A raiz de instalação não pode ser um link simbólico: $INSTALL_DIR"
  mkdir -p -- "$INSTALL_DIR"
  [[ -w "$INSTALL_DIR" ]] || die "Sem permissão de escrita em $INSTALL_DIR."

  local managed_subdir
  for managed_subdir in bin cache config logs plugins runtime state; do
    [[ ! -L "$INSTALL_DIR/$managed_subdir" ]] \
      || die "Subdiretório gerenciado é link simbólico e foi preservado: $INSTALL_DIR/$managed_subdir"
  done

  local lock_file="$INSTALL_DIR/.install.lock"
  [[ ! -L "$lock_file" && ! -d "$lock_file" ]] \
    || die "O caminho do lock é um link/diretório inesperado e foi preservado: $lock_file"
  exec {LOCK_FD}>"$lock_file"
  if ! flock -n "$LOCK_FD"; then
    die "Outra instalação está em execução e mantém o lock: $lock_file"
  fi

  mkdir -p -- \
    "$INSTALL_DIR/bin" \
    "$INSTALL_DIR/cache" \
    "$INSTALL_DIR/config" \
    "$INSTALL_DIR/logs" \
    "$INSTALL_DIR/plugins" \
    "$INSTALL_DIR/runtime" \
    "$INSTALL_DIR/state"
  chmod 700 "$INSTALL_DIR/config" "$INSTALL_DIR/state"
  INSTALL_LOG="$(mktemp "$INSTALL_DIR/logs/install-$(date '+%Y%m%d-%H%M%S').XXXXXX.log")"
  chmod 600 "$INSTALL_LOG"

  local available_kib
  available_kib="$(df -Pk "$INSTALL_DIR" | awk 'NR == 2 { print $4 }')"
  [[ "$available_kib" =~ ^[0-9]+$ ]] || die "Não foi possível medir o espaço livre."
  local required_kib="$MIN_FREE_KIB"
  local required_inodes=100000
  if [[ -f "$INSTALL_DIR/install-manifest.json" ]] \
    && jq -e --arg harness "$HARNESS_COMMIT" --arg plugin "$PLUGIN_COMMIT" \
      '.harness.commit == $harness and .plugin.commit == $plugin' \
      "$INSTALL_DIR/install-manifest.json" >/dev/null 2>&1; then
    required_kib=$((1 * 1024 * 1024))
    required_inodes=20000
  fi
  if ((available_kib < required_kib)); then
    die "Espaço insuficiente: são necessários ao menos $((required_kib / 1024 / 1024)) GiB livres nesta execução."
  elif ((available_kib < RECOMMENDED_FREE_KIB)); then
    warn "Há menos de 6 GiB livres. Esta execução exige ao menos $((required_kib / 1024 / 1024)) GiB, mas terá pouca margem."
  fi

  if [[ -r /proc/meminfo ]]; then
    local memory_kib swap_kib combined_kib
    memory_kib="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)"
    swap_kib="$(awk '/^SwapTotal:/ { print $2 }' /proc/meminfo)"
    combined_kib=$((memory_kib + swap_kib))
    if ((combined_kib < 4 * 1024 * 1024)); then
      warn "RAM + swap abaixo de 4 GiB; o build TypeScript pode ser encerrado por falta de memória."
    fi
  fi

  local free_inodes
  free_inodes="$(df -Pi "$INSTALL_DIR" | awk 'NR == 2 { print $4 }')"
  if [[ "$free_inodes" =~ ^[0-9]+$ ]] && ((free_inodes < required_inodes)); then
    die "Inodes insuficientes: esta execução precisa de pelo menos $required_inodes inodes livres."
  fi
}

quarantine_path() {
  local target="$1"
  local reason="$2"
  local quarantine="${target}.invalid.$(date '+%Y%m%d%H%M%S').$$"
  warn "$reason"
  warn "Movendo o conteúdo existente para $quarantine (recuperável)."
  mv -- "$target" "$quarantine"
}

node_archive_details() {
  local machine="$1"
  case "$machine" in
    x86_64|amd64)
      printf '%s\t%s\n' "node-v${NODE_VERSION}-linux-x64" \
        "fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6"
      ;;
    aarch64|arm64)
      printf '%s\t%s\n' "node-v${NODE_VERSION}-linux-arm64" \
        "6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2"
      ;;
    *) return 1 ;;
  esac
}

validate_node_runtime() {
  local node_bin="$1/bin/node"
  [[ -x "$node_bin" ]] || return 1
  [[ "$(sanitized "$node_bin" --version 2>/dev/null)" == "v$NODE_VERSION" ]] || return 1
  [[ -f "$1/include/node/node_api.h" ]] || return 1
  local features
  features="$(sanitized "$node_bin" -p \
    "JSON.stringify({typescript: process.features?.typescript ?? false, amaro: process.config?.variables?.node_use_amaro ?? false})" \
    2>/dev/null)" || return 1
  [[ "$features" == *'"typescript":"strip"'* || "$features" == *'"typescript":"transform"'* ]] \
    || return 1
  [[ "$features" == *'"amaro":true'* || "$features" == *'"amaro":"true"'* ]]
}

install_node_runtime() {
  local details node_dist expected_sha archive url node_dir
  details="$(node_archive_details "$(uname -m)")"
  node_dist="${details%%$'\t'*}"
  expected_sha="${details#*$'\t'}"
  archive="$INSTALL_DIR/cache/${node_dist}.tar.xz"
  url="https://nodejs.org/download/release/v${NODE_VERSION}/${node_dist}.tar.xz"
  node_dir="$INSTALL_DIR/runtime/$node_dist"

  if [[ -L "$node_dir" ]]; then
    quarantine_path "$node_dir" "O diretório versionado do Node era um link simbólico inesperado."
  fi
  if [[ -e "$node_dir" ]] && ! validate_node_runtime "$node_dir"; then
    quarantine_path "$node_dir" "O runtime Node existente está incompleto ou incompatível."
  fi

  if [[ ! -e "$node_dir" ]]; then
    if [[ -L "$archive" ]]; then
      quarantine_path "$archive" "O arquivo Node em cache era um link simbólico inesperado."
    fi
    if [[ -f "$archive" ]]; then
      local cached_sha
      cached_sha="$(sha256sum "$archive" | awk '{ print $1 }')"
      if [[ "$cached_sha" != "$expected_sha" ]]; then
        quarantine_path "$archive" "O arquivo Node em cache falhou na verificação SHA-256."
      fi
    fi

    if [[ ! -f "$archive" ]]; then
      local partial
      partial="$(mktemp "$INSTALL_DIR/cache/.node-download.XXXXXX")"
      TEMP_FILES+=("$partial")
      info "Baixando Node.js oficial v$NODE_VERSION..."
      retry 4 sanitized curl --fail --location --silent --show-error \
        --connect-timeout 20 --max-time 600 --output "$partial" "$url" \
        || die "Falha ao baixar $url"
      local downloaded_sha
      downloaded_sha="$(sha256sum "$partial" | awk '{ print $1 }')"
      if [[ "$downloaded_sha" != "$expected_sha" ]]; then
        mv -- "$partial" "${partial}.invalid"
        die "SHA-256 do Node não confere; o arquivo foi preservado como .invalid."
      fi
      mv -- "$partial" "$archive"
    fi

    info "Extraindo o runtime Node verificado..."
    local extraction_dir
    extraction_dir="$(mktemp -d "$INSTALL_DIR/runtime/.node-extract.XXXXXX")"
    TEMP_DIRS+=("$extraction_dir")
    if sanitized tar -xJf "$archive" -C "$extraction_dir" \
      && [[ -d "$extraction_dir/$node_dist" ]]; then
      mv -- "$extraction_dir/$node_dist" "$node_dir"
      rmdir "$extraction_dir"
    else
      rm -rf -- "$extraction_dir"
      die "Falha ao extrair o arquivo oficial do Node."
    fi
  fi

  validate_node_runtime "$node_dir" \
    || die "O Node oficial foi instalado, mas falhou na validação de versão/headers/TypeScript interno."

  if [[ -e "$INSTALL_DIR/runtime/node" && ! -L "$INSTALL_DIR/runtime/node" ]]; then
    die "$INSTALL_DIR/runtime/node existe e não é um link simbólico; não será sobrescrito."
  fi
  ln -sfn "$node_dist" "$INSTALL_DIR/runtime/node"
  ok "Node v$NODE_VERSION oficial, SHA-256 e suporte interno a TypeScript verificados."
}

validate_pnpm_runtime() {
  local pnpm_bin="$1/bin/pnpm"
  [[ -x "$pnpm_bin" ]] || return 1
  [[ "$(sanitized env PATH="$INSTALL_DIR/runtime/node/bin:/usr/bin:/bin" \
    "$pnpm_bin" --version 2>/dev/null)" == "$PNPM_VERSION" ]]
}

install_pnpm_runtime() {
  local pnpm_dist="pnpm-$PNPM_VERSION"
  local pnpm_dir="$INSTALL_DIR/runtime/$pnpm_dist"
  local node_bin="$INSTALL_DIR/runtime/node/bin/node"
  local npm_cli="$INSTALL_DIR/runtime/node/lib/node_modules/npm/bin/npm-cli.js"
  local tarball="$INSTALL_DIR/cache/pnpm-$PNPM_VERSION.tgz"
  local tarball_url="https://registry.npmjs.org/pnpm/-/pnpm-$PNPM_VERSION.tgz"

  if [[ -L "$pnpm_dir" ]]; then
    quarantine_path "$pnpm_dir" "O diretório versionado do pnpm era um link simbólico inesperado."
  fi
  if [[ -e "$pnpm_dir" ]] && ! validate_pnpm_runtime "$pnpm_dir"; then
    quarantine_path "$pnpm_dir" "O pnpm local existente está incompleto ou tem versão divergente."
  fi
  if [[ ! -e "$pnpm_dir" ]]; then
    if [[ -L "$tarball" ]]; then
      quarantine_path "$tarball" "O pacote pnpm em cache era um link simbólico inesperado."
    fi
    if [[ -f "$tarball" ]]; then
      local cached_sha
      cached_sha="$(sha512sum "$tarball" | awk '{ print $1 }')"
      if [[ "$cached_sha" != "$PNPM_TARBALL_SHA512" ]]; then
        quarantine_path "$tarball" "O pacote pnpm em cache falhou na verificação SHA-512."
      fi
    fi
    if [[ ! -f "$tarball" ]]; then
      local partial
      partial="$(mktemp "$INSTALL_DIR/cache/.pnpm-download.XXXXXX")"
      TEMP_FILES+=("$partial")
      info "Baixando o pacote pnpm $PNPM_VERSION..."
      retry 4 sanitized curl --fail --location --silent --show-error \
        --connect-timeout 20 --max-time 300 --output "$partial" "$tarball_url" \
        || die "Falha ao baixar $tarball_url"
      local downloaded_sha
      downloaded_sha="$(sha512sum "$partial" | awk '{ print $1 }')"
      if [[ "$downloaded_sha" != "$PNPM_TARBALL_SHA512" ]]; then
        mv -- "$partial" "${partial}.invalid"
        die "SHA-512 do pnpm não confere; o arquivo foi preservado como .invalid."
      fi
      mv -- "$partial" "$tarball"
    fi
    mkdir -p -- "$pnpm_dir"
    info "Instalando pnpm $PNPM_VERSION localmente (sem sudo e sem alterar o Node do Kali)..."
    mkdir -p -- "$INSTALL_DIR/cache/npm"
    if ! retry 3 sanitized env npm_config_cache="$INSTALL_DIR/cache/npm" \
      "$node_bin" "$npm_cli" install --global \
      --ignore-scripts --prefix "$pnpm_dir" --no-audit --no-fund "$tarball"; then
      quarantine_path "$pnpm_dir" "A instalação do pnpm não foi concluída."
      die "Não foi possível instalar pnpm $PNPM_VERSION."
    fi
  fi
  validate_pnpm_runtime "$pnpm_dir" || die "Falha ao validar pnpm $PNPM_VERSION."

  if [[ -e "$INSTALL_DIR/runtime/pnpm" && ! -L "$INSTALL_DIR/runtime/pnpm" ]]; then
    die "$INSTALL_DIR/runtime/pnpm existe e não é um link simbólico; não será sobrescrito."
  fi
  ln -sfn "$pnpm_dist" "$INSTALL_DIR/runtime/pnpm"
  sanitized "$node_bin" -e 'process.exit(process.features?.typescript && process.config?.variables?.node_use_amaro ? 0 : 1)' \
    || die "O runtime efetivo perdeu o suporte TypeScript necessário."
  ok "pnpm $PNPM_VERSION isolado e verificado."
}

checkout_exact_commit() {
  local repository="$1"
  local commit="$2"
  local destination="$3"
  local label="$4"

  if [[ -e "$destination" ]]; then
    [[ ! -L "$destination" ]] || die "$destination é um link simbólico inesperado e foi preservado."
    [[ -d "$destination/.git" ]] || die "$destination já existe e não é o checkout Git esperado."
    if [[ -n "$(sanitized git -C "$destination" status --porcelain)" ]]; then
      die "$label contém alterações locais. Preserve/commit essas mudanças antes de executar novamente: $destination"
    fi
    local origin
    origin="$(sanitized git -C "$destination" remote get-url origin 2>/dev/null || true)"
    [[ "$origin" == "$repository" ]] || die "O remote origin de $label não é o esperado: $origin"
    local existing_head
    existing_head="$(sanitized git -C "$destination" rev-parse HEAD 2>/dev/null || true)"
    if [[ "$existing_head" == "$commit" ]]; then
      ok "$label já está no commit ${commit:0:12}; nenhuma rede necessária."
      return 0
    fi
    if ! sanitized git -C "$destination" cat-file -e "${commit}^{commit}" 2>/dev/null; then
      retry 4 sanitized git -C "$destination" fetch --depth 1 origin "$commit"
    fi
    sanitized git -C "$destination" checkout --detach --quiet "$commit"
  else
    local parent base temporary
    parent="$(dirname -- "$destination")"
    base="$(basename -- "$destination")"
    mkdir -p -- "$parent"
    temporary="$(mktemp -d "$parent/.${base}.download.XXXXXX")"
    TEMP_DIRS+=("$temporary")
    if sanitized git -C "$temporary" init --quiet \
      && sanitized git -C "$temporary" remote add origin "$repository" \
      && retry 4 sanitized git -C "$temporary" fetch --depth 1 origin "$commit" \
      && sanitized git -C "$temporary" checkout --detach --quiet FETCH_HEAD; then
      mv -- "$temporary" "$destination"
    else
      rm -rf -- "$temporary"
      die "Falha ao clonar $label."
    fi
  fi

  local actual
  actual="$(sanitized git -C "$destination" rev-parse HEAD)"
  [[ "$actual" == "$commit" ]] || die "$label ficou no commit $actual; esperado $commit."
  ok "$label fixado em ${commit:0:12}."
}

path_has_test_markers() {
  local current="$1"
  while true; do
    [[ ! -e "$current/.git" && ! -e "$current/.agents" ]] || return 0
    [[ "$current" == "/" ]] && break
    current="$(dirname -- "$current")"
  done
  return 1
}

prepare_build_tmpdir() {
  local candidate="" candidate_free="" candidate_inodes=""
  for candidate in /var/tmp /tmp "$INSTALL_DIR/cache"; do
    [[ -d "$candidate" && -w "$candidate" ]] || continue
    path_has_test_markers "$candidate" && continue
    candidate_free="$(df -Pk "$candidate" | awk 'NR == 2 { print $4 }')"
    [[ "$candidate_free" =~ ^[0-9]+$ ]] || continue
    ((candidate_free >= 1 * 1024 * 1024)) || continue
    candidate_inodes="$(df -Pi "$candidate" | awk 'NR == 2 { print $4 }')"
    if [[ "$candidate_inodes" =~ ^[0-9]+$ ]] && ((candidate_inodes < 20000)); then
      continue
    fi
    BUILD_TMPDIR="$(mktemp -d "$candidate/deepseek-build.XXXXXX")"
    chmod 700 "$BUILD_TMPDIR"
    break
  done
  [[ -n "$BUILD_TMPDIR" ]] \
    || die "Não encontrei um TMPDIR gravável sem marcadores .git/.agents nos ancestrais."
  info "Diretório temporário isolado para build/testes: $BUILD_TMPDIR"
}

activate_toolchain() {
  export PATH="$INSTALL_DIR/runtime/node/bin:$INSTALL_DIR/runtime/pnpm/bin:${PATH:-/usr/local/bin:/usr/bin:/bin}"
  export PNPM_HOME="$INSTALL_DIR/runtime/pnpm"
  export pnpm_config_store_dir="$INSTALL_DIR/cache/pnpm-store"
  export DSH_HOME="$INSTALL_DIR/state"
  export DSH_TELEMETRY_MODE="DISABLED"
  export DSH_TELEMETRY_DISABLED="1"
}

pnpm_safe() {
  sanitized env \
    PATH="$INSTALL_DIR/runtime/node/bin:$INSTALL_DIR/runtime/pnpm/bin:/usr/local/bin:/usr/bin:/bin" \
    PNPM_HOME="$INSTALL_DIR/runtime/pnpm" \
    pnpm_config_store_dir="$INSTALL_DIR/cache/pnpm-store" \
    NODE_OPTIONS="--max-old-space-size=4096" \
    TMPDIR="$BUILD_TMPDIR" \
    CI="1" \
    NO_COLOR="1" \
    "$INSTALL_DIR/runtime/pnpm/bin/pnpm" "$@"
}

harness_pwsh_is_available() {
  sanitized env \
    PATH="$INSTALL_DIR/runtime/node/bin:$INSTALL_DIR/runtime/pnpm/bin:/usr/local/bin:/usr/bin:/bin" \
    pwsh -NoLogo -NoProfile -NonInteractive -Command '$true' \
    >/dev/null 2>&1
}

harness_report_is_clean() {
  local report="$1"
  local pwsh_status="$2"
  local expected_passed expected_pending
  case "$pwsh_status" in
    present)
      expected_passed=22570
      expected_pending=70
      ;;
    absent)
      # 51 testes de integração com o executável pwsh são opcionais no Linux.
      expected_passed=22519
      expected_pending=121
      ;;
    *) return 1 ;;
  esac
  [[ -s "$report" ]] || return 1
  jq -e \
    --argjson expected_passed "$expected_passed" \
    --argjson expected_pending "$expected_pending" '
    .success == true
    and (.testResults | length) == 1278
    and .numTotalTests == 22640
    and .numPassedTests == $expected_passed
    and .numFailedTests == 0
    and .numPendingTests == $expected_pending
    and .numTodoTests == 0
    and .snapshot.failure == false
    and all(.testResults[]; .status != "failed")
    and ([.testResults[].assertionResults[] | select(.status == "failed")] | length) == 0
    and ([.testResults[].assertionResults[] | select(.status == "passed")] | length) == $expected_passed
    and ([.testResults[].assertionResults[] | select(.status == "skipped")] | length) == $expected_pending
    and all(.testResults[].assertionResults[]; .status == "passed" or .status == "skipped")
    and ((.numPassedTests + .numPendingTests + .numFailedTests + .numTodoTests)
      == .numTotalTests)
  ' "$report" >/dev/null 2>&1
}

harness_report_has_only_pwsh_real_shell_failures() {
  local report="$1"
  local harness="$2"
  local spec="$harness/packages/terminal/terminal-bash/tests/local.spec.ts"
  local false_name='terminal-bash pwsh real shell bootstraps a persistent pwsh, persists state, and scrubs secrets (hold command: false)'
  local true_name='terminal-bash pwsh real shell bootstraps a persistent pwsh, persists state, and scrubs secrets (hold command: true)'
  local utf8_name='terminal-bash pwsh real shell pins UTF-8 output encoding so non-ASCII output survives the byte decode'

  [[ -s "$report" ]] || return 1
  jq -e \
    --arg spec "$spec" \
    --arg false_name "$false_name" \
    --arg true_name "$true_name" \
    --arg utf8_name "$utf8_name" '
    def failures: [.testResults[].assertionResults[] | select(.status == "failed")];
    def failed_files: [.testResults[] | select(.status == "failed")];
    def allowed_names: [$false_name, $true_name, $utf8_name];
    .success == false
    and (.testResults | length) == 1278
    and .numTotalTests == 22640
    and (.numFailedTests >= 1 and .numFailedTests <= 3)
    and .numPassedTests == (22570 - .numFailedTests)
    and .numPendingTests == 70
    and .numTodoTests == 0
    and .snapshot.failure == false
    and ([.testResults[].assertionResults[] | select(.status == "passed")] | length) == .numPassedTests
    and ([.testResults[].assertionResults[] | select(.status == "skipped")] | length) == .numPendingTests
    and all(.testResults[].assertionResults[];
      .status == "passed" or .status == "skipped" or .status == "failed")
    and ((.numPassedTests + .numPendingTests + .numFailedTests + .numTodoTests)
      == .numTotalTests)
    and (failed_files | length) == 1
    and failed_files[0].name == $spec
    and (failures | length) == .numFailedTests
    and ((failures | map(.fullName) | unique | length) == .numFailedTests)
    and all(failures[];
      .fullName as $failed_name
      | (allowed_names | index($failed_name)) != null)
    and all(failures[];
      (.failureMessages | length) == 1
      and (.failureMessages[0] | startswith("AssertionError: expected "))
      and (if (.fullName == $utf8_name) then
        ((.failureMessages[0] | contains("to contain '\''console=utf-8 out=utf-8'\''"))
          and (.failureMessages[0] | contains("local.spec.ts:385:35")))
        or ((.failureMessages[0] | contains("to contain '\''中文 encoding-ok'\''"))
          and (.failureMessages[0] | contains("local.spec.ts:393:29")))
      else
        (.failureMessages[0] | contains("to contain '\''dsh> '\''"))
        and (.failureMessages[0] | contains("local.spec.ts:333:28"))
      end))
  ' "$report" >/dev/null 2>&1
}

harness_pwsh_retry_report_is_clean() {
  local report="$1"
  local harness="$2"
  local spec="$harness/packages/terminal/terminal-bash/tests/local.spec.ts"
  local false_name='terminal-bash pwsh real shell bootstraps a persistent pwsh, persists state, and scrubs secrets (hold command: false)'
  local true_name='terminal-bash pwsh real shell bootstraps a persistent pwsh, persists state, and scrubs secrets (hold command: true)'
  local utf8_name='terminal-bash pwsh real shell pins UTF-8 output encoding so non-ASCII output survives the byte decode'

  [[ -s "$report" ]] || return 1
  jq -e \
    --arg spec "$spec" \
    --arg false_name "$false_name" \
    --arg true_name "$true_name" \
    --arg utf8_name "$utf8_name" '
    .success == true
    and (.testResults | length) == 1
    and .testResults[0].name == $spec
    and .testResults[0].status == "passed"
    and (.testResults[0].assertionResults | length) == 10
    and .numTotalTests == 10
    and .numPassedTests == 3
    and .numFailedTests == 0
    and .numPendingTests == 7
    and .numTodoTests == 0
    and .snapshot.failure == false
    and ([.testResults[0].assertionResults[] | select(.status == "skipped")] | length) == 7
    and all(.testResults[0].assertionResults[]; .status == "passed" or .status == "skipped")
    and (([.testResults[0].assertionResults[]
      | select(.status == "passed") | .fullName] | sort)
      == ([$false_name, $true_name, $utf8_name] | sort))
  ' "$report" >/dev/null 2>&1
}

retry_pwsh_tests_isolated() {
  local harness="$1"
  local report
  report="$(mktemp "$BUILD_TMPDIR/harness-pwsh-retry.XXXXXX.json")"
  if ! run_logged "Revalidando isoladamente os três testes pwsh em processo limpo..." \
    pnpm_safe exec vitest run packages/terminal/terminal-bash/tests/local.spec.ts \
      --testNamePattern='^terminal-bash pwsh real shell' \
      --maxWorkers=1 --no-file-parallelism \
      --reporter=default --reporter=json --outputFile.json="$report"; then
    return 1
  fi
  harness_pwsh_retry_report_is_clean "$report" "$harness"
}

build_harness() {
  local harness="$INSTALL_DIR/deepseek-harness"
  local harness_test_status_file="$BUILD_TMPDIR/harness-test-status"
  local package_version
  package_version="$(sanitized "$INSTALL_DIR/runtime/node/bin/node" -e \
    'const fs = require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).version)' \
    "$harness/package.json")"
  [[ "$package_version" == "$HARNESS_VERSION" ]] \
    || die "Versão inesperada do Harness: $package_version (esperada $HARNESS_VERSION)."

  if harness_pwsh_is_available; then
    HARNESS_PWSH_STATUS="present"
    info "PowerShell detectado; os 51 testes opcionais pwsh também serão exigidos."
  else
    HARNESS_PWSH_STATUS="absent"
    info "PowerShell não detectado; a baseline permite exatamente 51 testes pwsh opcionais pendentes."
  fi

  (
    umask 022
    cd "$harness"
    retry 3 run_logged "Instalando dependências congeladas do DeepSeek Harness..." \
      pnpm_safe install --frozen-lockfile
    run_logged "Compilando o DeepSeek Harness..." pnpm_safe run build
    run_logged "Validando os tipos do DeepSeek Harness..." pnpm_safe run typecheck
    local suite_status="not-run"
    if ((QUICK == 0)); then
      local full_report serial_report
      full_report="$(mktemp "$BUILD_TMPDIR/harness-full.XXXXXX.json")"
      if run_logged "Executando a suíte completa do DeepSeek Harness..." \
        pnpm_safe run test --reporter=default --reporter=json \
          --outputFile.json="$full_report"; then
        harness_report_is_clean "$full_report" "$HARNESS_PWSH_STATUS" \
          || die "A suíte terminou com código zero, mas seu relatório estruturado não corresponde à baseline fixada."
        suite_status="passed"
      elif [[ "$HARNESS_PWSH_STATUS" == "present" ]] \
        && harness_report_has_only_pwsh_real_shell_failures "$full_report" "$harness"; then
        warn "A suíte completa só falhou em casos pwsh real shell reconhecidos; repetindo os três casos pwsh isoladamente."
        retry_pwsh_tests_isolated "$harness" \
          || die "Os testes pwsh não passaram isoladamente; instalação interrompida."
        suite_status="passed-after-isolated-pwsh-retry"
        ok "Os demais testes passaram juntos e os três testes pwsh passaram na repetição isolada."
      else
        warn "A execução paralela teve uma falha não classificada; repetindo uma vez em modo serial."
        run_logged "Recompilando o addon nativo antes do fallback serial..." \
          pnpm_safe run build:native-system
        serial_report="$(mktemp "$BUILD_TMPDIR/harness-serial.XXXXXX.json")"
        if run_logged "Executando fallback serial da suíte do DeepSeek Harness..." \
          pnpm_safe exec vitest run --maxWorkers=1 --no-file-parallelism \
            --reporter=default --reporter=json --outputFile.json="$serial_report"; then
          harness_report_is_clean "$serial_report" "$HARNESS_PWSH_STATUS" \
            || die "O fallback serial terminou com código zero, mas seu relatório estruturado é inesperado."
          suite_status="passed-after-serial"
        elif [[ "$HARNESS_PWSH_STATUS" == "present" ]] \
          && harness_report_has_only_pwsh_real_shell_failures "$serial_report" "$harness"; then
          warn "O fallback serial só falhou em casos pwsh real shell reconhecidos; repetindo os três casos isoladamente."
          retry_pwsh_tests_isolated "$harness" \
            || die "Os testes pwsh não passaram isoladamente; instalação interrompida."
          suite_status="passed-after-serial-pwsh-retry"
          ok "Os demais testes passaram no fallback serial e os três testes pwsh passaram isoladamente."
        else
          die "A suíte do Harness apresentou falhas fora da assinatura pwsh conhecida."
        fi
      fi
    else
      warn "--quick: suíte completa do Harness ignorada; build e typecheck continuam validados."
      suite_status="skipped-quick"
    fi
    printf '%s\n' "$suite_status" > "$harness_test_status_file"
    chmod 600 "$harness_test_status_file"
  )

  [[ -s "$harness_test_status_file" ]] || die "Status da suíte do Harness não foi registrado."
  IFS= read -r HARNESS_TEST_STATUS < "$harness_test_status_file"
  case "$HARNESS_TEST_STATUS" in
    passed|passed-after-isolated-pwsh-retry|passed-after-serial|passed-after-serial-pwsh-retry|skipped-quick) ;;
    *) die "Status inesperado da suíte do Harness: $HARNESS_TEST_STATUS" ;;
  esac

  [[ -f "$harness/apps/cli/lib/bin.js" ]] || die "Artefato da CLI do Harness ausente."
  [[ -f "$harness/apps/web/dist/index.html" ]] || die "Artefato Web do Harness ausente."
  find "$harness/native/system/packages" -type f -name system.node -print -quit | grep -q . \
    || die "Addon nativo system.node não foi gerado."
  ok "DeepSeek Harness compilado e validado."
}

build_plugin() {
  local plugin="$INSTALL_DIR/plugins/dsh-unrestricted"
  local package_version
  package_version="$(sanitized "$INSTALL_DIR/runtime/node/bin/node" -e \
    'const fs = require("node:fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).version)' \
    "$plugin/package.json")"
  [[ "$package_version" == "$PLUGIN_VERSION" ]] \
    || die "Versão inesperada do dsh-unrestricted: $package_version (esperada $PLUGIN_VERSION)."

  (
    umask 022
    cd "$plugin"
    retry 3 run_logged "Instalando dependências congeladas do dsh-unrestricted..." \
      pnpm_safe install --frozen-lockfile
    run_logged "Validando os tipos do dsh-unrestricted..." pnpm_safe run typecheck
    run_logged "Compilando o dsh-unrestricted..." pnpm_safe run build
    run_logged "Executando os testes do dsh-unrestricted..." pnpm_safe run test
  )

  local actual_bundle_sha
  actual_bundle_sha="$(sha256sum "$plugin/lib/client.js" | awk '{ print $1 }')"
  [[ "$actual_bundle_sha" == "$PLUGIN_BUNDLE_SHA256" ]] \
    || die "O bundle reproduzido do plugin não corresponde ao SHA-256 esperado."
  ok "dsh-unrestricted compilado, testado e reproduzido byte a byte."
}

invoke_dsh_without_key() {
  sanitized env \
    PATH="$INSTALL_DIR/runtime/node/bin:$INSTALL_DIR/runtime/pnpm/bin:${PATH:-/usr/local/bin:/usr/bin:/bin}" \
    PNPM_HOME="$INSTALL_DIR/runtime/pnpm" \
    pnpm_config_store_dir="$INSTALL_DIR/cache/pnpm-store" \
    DSH_HOME="$INSTALL_DIR/state" \
    DSH_TELEMETRY_MODE="DISABLED" \
    DSH_TELEMETRY_DISABLED="1" \
    NODE_OPTIONS="--max-old-space-size=4096" \
    "$INSTALL_DIR/runtime/node/bin/node" \
    "$INSTALL_DIR/deepseek-harness/apps/cli/lib/bin.js" "$@"
}

install_plugin_profile() {
  local profile="$INSTALL_DIR/state/profiles/web/package.json"
  local plugin_spec="file:$INSTALL_DIR/plugins/dsh-unrestricted"
  [[ ! -L "$profile" ]] || die "O package.json do profile Web é um link simbólico inesperado."
  if [[ -f "$profile" ]] \
    && jq -e --arg spec "$plugin_spec" \
      '.dependencies["dsh-unrestricted"] == $spec and (.dsh.profile.bundles | index("dsh-unrestricted"))' \
      "$profile" >/dev/null; then
    info "O plugin já está instalado no profile Web com o caminho exato; mantendo o profile."
  else
    run_logged "Instalando o plugin local no profile Web..." \
      invoke_dsh_without_key plugin --profile web add "$plugin_spec"
  fi

  [[ -f "$profile" ]] || die "O profile Web não foi criado."
  jq -e '.dependencies["dsh-unrestricted"] and (.dsh.profile.bundles | index("dsh-unrestricted"))' \
    "$profile" >/dev/null || die "O plugin não aparece na composição do profile Web."
  (
    umask 022
    cd "$(dirname -- "$profile")"
    run_logged "Validando/reparando as dependências congeladas do profile Web..." \
      pnpm_safe install --frozen-lockfile
  )
  [[ -e "$(dirname -- "$profile")/node_modules/dsh-unrestricted" ]] \
    || die "O módulo dsh-unrestricted não foi materializado no profile Web."
  chmod 700 "$INSTALL_DIR/state"
  ok "Plugin instalado no profile Web (o padrão novo é desativado; uma reinstalação preserva o estado existente)."
}

write_wrapper_files() {
  local bin_dir="$INSTALL_DIR/bin"
  local installed_manager="$bin_dir/deepseek-stack"
  local source_path manager_tmp dsh_tmp web_tmp doctor_tmp api_tmp
  source_path="$(readlink -f -- "${BASH_SOURCE[0]}")"
  if [[ "$source_path" != "$(readlink -m -- "$installed_manager")" ]]; then
    manager_tmp="$(mktemp "$bin_dir/.deepseek-stack.XXXXXX")"
    TEMP_FILES+=("$manager_tmp")
    install -m 0755 "$source_path" "$manager_tmp"
    mv -T -- "$manager_tmp" "$installed_manager"
  fi

  dsh_tmp="$(mktemp "$bin_dir/.dsh.XXXXXX")"
  web_tmp="$(mktemp "$bin_dir/.deepseek-web.XXXXXX")"
  doctor_tmp="$(mktemp "$bin_dir/.deepseek-doctor.XXXXXX")"
  api_tmp="$(mktemp "$bin_dir/.deepseek-api-check.XXXXXX")"
  TEMP_FILES+=("$dsh_tmp" "$web_tmp" "$doctor_tmp" "$api_tmp")

  cat > "$dsh_tmp" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
SELF_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
STACK_ROOT="$(CDPATH= cd -- "$(dirname -- "$SELF_PATH")/.." && pwd -P)"
API_KEY="${DEEPSEEK_API_KEY:-}"
if [[ -z "$API_KEY" ]]; then
  API_KEY="$(printenv 'deep-key' 2>/dev/null || true)"
fi
KEY_FILE="$STACK_ROOT/config/deepseek.env"
if [[ -z "$API_KEY" && ( -e "$KEY_FILE" || -L "$KEY_FILE" ) ]]; then
  CONFIG_DIR="$STACK_ROOT/config"
  if [[ ! -f "$KEY_FILE" || -L "$KEY_FILE" ]]; then
    printf '[ERRO] O arquivo da chave não é um arquivo regular ou é link simbólico.\n' >&2
    exit 1
  fi
  CURRENT_UID="$(id -u)"
  FILE_UID="$(env -u 'deep-key' stat -c '%u' "$KEY_FILE")"
  FILE_MODE="$(env -u 'deep-key' stat -c '%a' "$KEY_FILE")"
  DIR_UID="$(env -u 'deep-key' stat -c '%u' "$CONFIG_DIR")"
  DIR_MODE="$(env -u 'deep-key' stat -c '%a' "$CONFIG_DIR")"
  if [[ "$FILE_UID" != "$CURRENT_UID" || "$DIR_UID" != "$CURRENT_UID" ]] \
    || (( (8#$FILE_MODE & 077) != 0 || (8#$DIR_MODE & 077) != 0 )); then
    printf '[ERRO] Dono/permissões inseguros em config/deepseek.env (esperado: diretório 0700 e arquivo 0600).\n' >&2
    exit 1
  fi
  KEY_LINE=""
  EXTRA_LINE=""
  exec 3< "$KEY_FILE"
  IFS= read -r KEY_LINE <&3 || [[ -n "$KEY_LINE" ]]
  if IFS= read -r EXTRA_LINE <&3; then
    exec 3<&-
    printf '[ERRO] O arquivo da chave contém mais de uma linha.\n' >&2
    exit 1
  fi
  exec 3<&-
  case "$KEY_LINE" in
    DEEPSEEK_API_KEY=*) API_KEY="${KEY_LINE#DEEPSEEK_API_KEY=}" ;;
    *)
      printf '[ERRO] Formato inválido em config/deepseek.env.\n' >&2
      exit 1
      ;;
  esac
fi
if [[ "$API_KEY" == *$'\n'* || "$API_KEY" == *$'\r'* ]]; then
  printf '[ERRO] A chave contém quebra de linha e foi recusada.\n' >&2
  exit 1
fi
if [[ "$API_KEY" == "chave-aqui" || "$API_KEY" == "sk-..." ]]; then
  printf '[ERRO] A chave configurada ainda é um valor de exemplo.\n' >&2
  exit 1
fi
if [[ -n "$API_KEY" ]]; then
  export DEEPSEEK_API_KEY="$API_KEY"
else
  unset DEEPSEEK_API_KEY 2>/dev/null || true
fi
export PATH="$STACK_ROOT/runtime/node/bin:$STACK_ROOT/runtime/pnpm/bin:${PATH:-/usr/local/bin:/usr/bin:/bin}"
export PNPM_HOME="$STACK_ROOT/runtime/pnpm"
export pnpm_config_store_dir="$STACK_ROOT/cache/pnpm-store"
export DSH_HOME="$STACK_ROOT/state"
export DSH_TELEMETRY_MODE="DISABLED"
export DSH_TELEMETRY_DISABLED="1"
export NODE_OPTIONS="--max-old-space-size=4096"
exec env -u 'deep-key' "$STACK_ROOT/runtime/node/bin/node" \
  "$STACK_ROOT/deepseek-harness/apps/cli/lib/bin.js" "$@"
WRAPPER

  cat > "$web_tmp" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
SELF_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
BIN_DIR="$(CDPATH= cd -- "$(dirname -- "$SELF_PATH")" && pwd -P)"
for argument in "$@"; do
  case "$argument" in
    --host|--host=*)
      printf '[ERRO] deepseek-web fixa o bind em 127.0.0.1; use um túnel SSH para acesso remoto.\n' >&2
      exit 2
      ;;
  esac
done
exec "$BIN_DIR/dsh" web --host 127.0.0.1 "$@"
WRAPPER

  cat > "$doctor_tmp" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
SELF_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
BIN_DIR="$(CDPATH= cd -- "$(dirname -- "$SELF_PATH")" && pwd -P)"
exec "$BIN_DIR/deepseek-stack" doctor --install-dir "$(dirname -- "$BIN_DIR")" "$@"
WRAPPER

  cat > "$api_tmp" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
SELF_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
BIN_DIR="$(CDPATH= cd -- "$(dirname -- "$SELF_PATH")" && pwd -P)"
exec "$BIN_DIR/deepseek-stack" api-check --install-dir "$(dirname -- "$BIN_DIR")" "$@"
WRAPPER

  chmod 755 "$dsh_tmp" "$web_tmp" "$doctor_tmp" "$api_tmp"
  mv -T -- "$dsh_tmp" "$bin_dir/dsh"
  mv -T -- "$web_tmp" "$bin_dir/deepseek-web"
  mv -T -- "$doctor_tmp" "$bin_dir/deepseek-doctor"
  mv -T -- "$api_tmp" "$bin_dir/deepseek-api-check"
  chmod 755 "$installed_manager"
}

create_user_links() {
  ((CREATE_USER_LINKS == 1)) || return 0
  local user_bin="$USER_HOME/.local/bin"
  mkdir -p -- "$user_bin"
  local name source destination existing
  for name in dsh deepseek-web deepseek-doctor deepseek-api-check; do
    source="$INSTALL_DIR/bin/$name"
    destination="$user_bin/$name"
    if [[ -L "$destination" ]]; then
      existing="$(readlink -f -- "$destination" 2>/dev/null || true)"
      if [[ "$existing" == "$source" || "$existing" == "$INSTALL_DIR/bin/"* ]]; then
        ln -sfn "$source" "$destination"
      else
        warn "Atalho existente preservado: $destination -> $existing"
      fi
    elif [[ -e "$destination" ]]; then
      warn "Arquivo existente preservado; atalho não criado: $destination"
    else
      ln -s "$source" "$destination"
    fi
  done
  ok "Atalhos criados em $user_bin."
  if [[ ":${PATH:-}:" != *":$user_bin:"* ]]; then
    warn "$user_bin ainda não está no PATH desta sessão; use os caminhos completos ou abra um novo terminal."
  fi
}

key_path_is_secure() {
  local config_dir="$INSTALL_DIR/config"
  local key_file="$config_dir/deepseek.env"
  [[ -d "$config_dir" && ! -L "$config_dir" ]] || return 1
  [[ -f "$key_file" && ! -L "$key_file" ]] || return 1
  local expected_uid config_uid key_uid config_mode key_mode
  expected_uid="$(id -u)"
  config_uid="$(stat -c '%u' "$config_dir")"
  key_uid="$(stat -c '%u' "$key_file")"
  [[ "$config_uid" == "$expected_uid" && "$key_uid" == "$expected_uid" ]] || return 1
  config_mode="$(stat -c '%a' "$config_dir")"
  key_mode="$(stat -c '%a' "$key_file")"
  (( (8#$config_mode & 077) == 0 && (8#$key_mode & 077) == 0 ))
}

read_key_file() {
  local key_file="$INSTALL_DIR/config/deepseek.env"
  key_path_is_secure || return 1
  local -a lines=()
  mapfile -t lines < "$key_file"
  ((${#lines[@]} == 1)) || return 1
  local line="${lines[0]}"
  case "$line" in
    DEEPSEEK_API_KEY=*)
      API_KEY="${line#DEEPSEEK_API_KEY=}"
      API_KEY_SOURCE="arquivo protegido"
      [[ -n "$API_KEY" && "$API_KEY" != *$'\r'* \
        && "$API_KEY" != "chave-aqui" && "$API_KEY" != "sk-..." ]]
      ;;
    *) return 1 ;;
  esac
}

validate_key_value() {
  [[ -n "$API_KEY" ]] || return 1
  [[ "$API_KEY" != *$'\n'* && "$API_KEY" != *$'\r'* ]] \
    || die "A chave contém uma quebra de linha e foi recusada."
  [[ "$API_KEY" != "chave-aqui" && "$API_KEY" != "sk-..." ]] \
    || die "Foi detectado um valor de exemplo, não uma chave real da API."
}

resolve_api_key() {
  local allow_prompt="$1"
  if [[ -z "$API_KEY" ]]; then
    read_key_file || true
  fi
  if [[ -z "$API_KEY" && "$allow_prompt" == "1" && "$NON_INTERACTIVE" == "0" && -t 0 ]]; then
    local entered=""
    printf 'Digite a DEEPSEEK_API_KEY (entrada oculta; Enter para configurar depois): ' >&2
    IFS= read -r -s entered || true
    printf '\n' >&2
    if [[ -n "$entered" ]]; then
      API_KEY="$entered"
      API_KEY_SOURCE="entrada interativa"
    fi
  fi
  validate_key_value
}

store_api_key() {
  validate_key_value || return 1
  local key_file="$INSTALL_DIR/config/deepseek.env"
  local temporary
  temporary="$(mktemp "$INSTALL_DIR/config/.deepseek-key.XXXXXX")"
  TEMP_FILES+=("$temporary")
  printf '%s\n' "DEEPSEEK_API_KEY=$API_KEY" > "$temporary"
  chmod 600 "$temporary"
  mv -T -- "$temporary" "$key_file"
  chmod 600 "$key_file"
  ok "Chave normalizada de $API_KEY_SOURCE para $key_file (modo 0600)."
}

curl_escape_config() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

api_http_request() {
  local endpoint="$1"
  local method="$2"
  local body_json="${3:-}"
  local config_file request_file escaped_key
  API_TEMP_DIR="$(mktemp -d "$INSTALL_DIR/cache/api-check.XXXXXX")"
  config_file="$API_TEMP_DIR/curl.conf"
  request_file="$API_TEMP_DIR/request.json"
  API_RESPONSE_FILE="$API_TEMP_DIR/response.json"
  escaped_key="$(curl_escape_config "$API_KEY")"

  {
    printf 'url = "%s%s"\n' "$DEEPSEEK_API_BASE" "$endpoint"
    printf 'request = "%s"\n' "$method"
    printf 'header = "Authorization: Bearer %s"\n' "$escaped_key"
    printf 'header = "Accept: application/json"\n'
    printf 'silent\nshow-error\n'
    printf 'proto = "=https"\n'
    printf 'connect-timeout = 20\nmax-time = 120\n'
    if [[ "$method" == "GET" ]]; then
      printf 'retry = 3\nretry-all-errors\nretry-delay = 1\nretry-max-time = 30\n'
    fi
    if [[ -n "$body_json" ]]; then
      printf 'header = "Content-Type: application/json"\n'
      printf 'data-binary = "@%s"\n' "$(curl_escape_config "$request_file")"
    fi
  } > "$config_file"
  chmod 600 "$config_file"
  if [[ -n "$body_json" ]]; then
    printf '%s\n' "$body_json" > "$request_file"
    chmod 600 "$request_file"
  fi

  if ! API_HTTP_CODE="$(sanitized curl --config "$config_file" --output "$API_RESPONSE_FILE" \
    --write-out '%{http_code}')"; then
    die "Falha de rede/TLS ao acessar a API DeepSeek."
  fi
}

clear_api_temp() {
  if [[ -n "$API_TEMP_DIR" ]]; then
    rm -rf -- "$API_TEMP_DIR"
  fi
  API_TEMP_DIR=""
  API_HTTP_CODE=""
  API_RESPONSE_FILE=""
}

explain_api_error() {
  local code="$1"
  local response="$2"
  local message=""
  message="$(jq -r '.error.message // .message // empty' "$response" 2>/dev/null || true)"
  case "$code" in
    400) die "API retornou 400 (requisição inválida): ${message:-sem detalhe}." ;;
    401) die "API retornou 401: chave inválida ou revogada." ;;
    402) die "API retornou 402: saldo/crédito insuficiente." ;;
    422) die "API retornou 422 (parâmetros rejeitados): ${message:-sem detalhe}." ;;
    429) die "API retornou 429: limite de concorrência/taxa atingido; tente mais tarde." ;;
    500|503) die "API DeepSeek está temporariamente indisponível (HTTP $code); tente novamente." ;;
    *) die "API DeepSeek retornou HTTP $code: ${message:-sem detalhe}." ;;
  esac
}

run_api_check() {
  if ! resolve_api_key 1; then
    die "Nenhuma chave configurada. Defina DEEPSEEK_API_KEY ou execute sem --non-interactive para digitá-la."
  fi

  info "Validando autenticação com GET /models (sem inferência e sem tokens gerados)..."
  local models
  api_http_request '/models' 'GET'
  if [[ "$API_HTTP_CODE" != "200" ]]; then
    explain_api_error "$API_HTTP_CODE" "$API_RESPONSE_FILE"
  fi
  models="$(jq -r '[.data[]?.id] | join(", ")' "$API_RESPONSE_FILE" 2>/dev/null || true)"
  [[ -n "$models" ]] || die "A autenticação funcionou, mas /models retornou um formato inesperado."
  clear_api_temp
  ok "API autenticada. Modelos visíveis: $models"

  if ((PAID_SMOKE == 1)); then
    info "Executando smoke test pago e mínimo no deepseek-flash..."
    local request_json answer input_tokens output_tokens
    request_json='{"model":"deepseek-flash","messages":[{"role":"user","content":"Responda apenas OK"}],"thinking":{"type":"disabled"},"max_tokens":16}'
    # POST não tem retry automático: uma resposta perdida poderia duplicar cobrança.
    api_http_request '/chat/completions' 'POST' "$request_json"
    if [[ "$API_HTTP_CODE" != "200" ]]; then
      explain_api_error "$API_HTTP_CODE" "$API_RESPONSE_FILE"
    fi
    answer="$(jq -r '.choices[0].message.content // empty' "$API_RESPONSE_FILE")"
    input_tokens="$(jq -r '.usage.prompt_tokens // .usage.input_tokens // "?"' "$API_RESPONSE_FILE")"
    output_tokens="$(jq -r '.usage.completion_tokens // .usage.output_tokens // "?"' "$API_RESPONSE_FILE")"
    clear_api_temp
    [[ -n "$answer" ]] || die "A chamada paga retornou 200, mas sem conteúdo reconhecível."
    ok "Inferência paga concluída (entrada: $input_tokens tokens; saída: $output_tokens tokens; resposta: ${answer:0:80})."
  fi
}

web_boot_smoke() {
  SMOKE_LOG="$(mktemp "$INSTALL_DIR/logs/web-smoke.XXXXXX.log")"
  SMOKE_CURL_CONFIG="$(mktemp "$INSTALL_DIR/logs/web-smoke.XXXXXX.curl.conf")"
  SMOKE_COOKIE_JAR="$(mktemp "$INSTALL_DIR/logs/web-smoke.XXXXXX.cookies")"
  chmod 600 "$SMOKE_LOG"

  info "Inicializando temporariamente o profile Web para validar a composição completa..."
  invoke_dsh_without_key web --host 127.0.0.1 --no-open --port 0 \
    > "$SMOKE_LOG" 2>&1 &
  SMOKE_PID=$!

  local launch_url="" attempt
  for attempt in $(seq 1 180); do
    launch_url="$(sed -n 's/^.*dsh web: \(http:\/\/[^[:space:]]*\).*$/\1/p' "$SMOKE_LOG" | tail -n 1)"
    if [[ -n "$launch_url" ]]; then
      break
    fi
    if ! kill -0 "$SMOKE_PID" 2>/dev/null; then
      local redacted
      redacted="$(sed -E 's/(token=)[^[:space:]]+/\1[REDACTED]/g' "$SMOKE_LOG" | tail -n 40)"
      printf '%s\n' "$redacted" >&2
      die "O profile Web encerrou antes de ficar pronto."
    fi
    sleep 0.5
  done
  [[ -n "$launch_url" ]] || die "O profile Web não ficou pronto em 90 segundos."

  local escaped_url http_code
  escaped_url="$(curl_escape_config "$launch_url")"
  {
    printf 'url = "%s"\n' "$escaped_url"
    printf 'silent\nshow-error\nlocation\n'
    printf 'noproxy = "*"\n'
    printf 'connect-timeout = 5\nmax-time = 20\n'
    printf 'cookie = "%s"\n' "$(curl_escape_config "$SMOKE_COOKIE_JAR")"
    printf 'cookie-jar = "%s"\n' "$(curl_escape_config "$SMOKE_COOKIE_JAR")"
    printf 'output = "/dev/null"\n'
  } > "$SMOKE_CURL_CONFIG"
  : > "$SMOKE_COOKIE_JAR"
  chmod 600 "$SMOKE_COOKIE_JAR"
  chmod 600 "$SMOKE_CURL_CONFIG"
  http_code="$(sanitized curl --config "$SMOKE_CURL_CONFIG" --write-out '%{http_code}')" \
    || die "O profile Web iniciou, mas a verificação HTTP local falhou."

  kill "$SMOKE_PID" 2>/dev/null || true
  wait "$SMOKE_PID" 2>/dev/null || true
  SMOKE_PID=""
  rm -f -- "$SMOKE_LOG" "$SMOKE_CURL_CONFIG" "$SMOKE_COOKIE_JAR"
  SMOKE_LOG=""
  SMOKE_CURL_CONFIG=""
  SMOKE_COOKIE_JAR=""
  [[ "$http_code" == "200" ]] || die "O profile Web respondeu HTTP $http_code em vez de 200."
  ok "Profile Web, autenticação local e dsh-unrestricted validados sem chamada ao modelo."
}

doctor_check() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    ok "$description"
    return 0
  fi
  printf '%s[FALHA]%s %s\n' "$C_RED" "$C_RESET" "$description" >&2
  return 1
}

doctor_git_commit() {
  local directory="$1" expected="$2"
  [[ -d "$directory/.git" && ! -L "$directory" ]] \
    && [[ "$(sanitized git -C "$directory" rev-parse HEAD 2>/dev/null)" == "$expected" ]] \
    && [[ -z "$(sanitized git -C "$directory" status --porcelain 2>/dev/null)" ]]
}

doctor_node() {
  local details expected_dist
  details="$(node_archive_details "$(uname -m)")"
  expected_dist="${details%%$'\t'*}"
  [[ -L "$INSTALL_DIR/runtime/node" ]] \
    && [[ "$(readlink -- "$INSTALL_DIR/runtime/node")" == "$expected_dist" ]] \
    && [[ ! -L "$INSTALL_DIR/runtime/$expected_dist" ]] \
    && validate_node_runtime "$INSTALL_DIR/runtime/node"
}

doctor_pnpm() {
  [[ -L "$INSTALL_DIR/runtime/pnpm" ]] \
    && [[ "$(readlink -- "$INSTALL_DIR/runtime/pnpm")" == "pnpm-$PNPM_VERSION" ]] \
    && [[ ! -L "$INSTALL_DIR/runtime/pnpm-$PNPM_VERSION" ]] \
    && validate_pnpm_runtime "$INSTALL_DIR/runtime/pnpm"
}

doctor_profile() {
  local profile="$INSTALL_DIR/state/profiles/web/package.json"
  [[ -f "$profile" && ! -L "$profile" ]] \
    && jq -e '.dependencies["dsh-unrestricted"] and (.dsh.profile.bundles | index("dsh-unrestricted"))' "$profile" >/dev/null
}

doctor_bundle() {
  local bundle="$INSTALL_DIR/plugins/dsh-unrestricted/lib/client.js"
  [[ -f "$bundle" && ! -L "$bundle" ]] \
    && [[ "$(sha256sum "$bundle" | awk '{ print $1 }')" == "$PLUGIN_BUNDLE_SHA256" ]]
}

doctor_regular_file() {
  [[ -f "$1" && ! -L "$1" ]]
}

doctor_web_launcher() {
  local launcher="$INSTALL_DIR/bin/deepseek-web"
  doctor_regular_file "$launcher" \
    && grep -Fq -- '--host|--host=*)' "$launcher" \
    && grep -Fq -- 'web --host 127.0.0.1 "$@"' "$launcher"
}

doctor_native_addon() {
  find "$INSTALL_DIR/deepseek-harness/native/system/packages" \
    -type f -name system.node -print -quit 2>/dev/null | grep -q .
}

doctor_cli_version() {
  [[ "$(invoke_dsh_without_key --version 2>/dev/null)" == "$HARNESS_VERSION" ]]
}

doctor_composition() {
  invoke_dsh_without_key --profile web --dump-config 2>/dev/null | grep -q 'dsh-unrestricted'
}

doctor_key() {
  local config_dir="$INSTALL_DIR/config"
  local key_file="$INSTALL_DIR/config/deepseek.env"
  [[ -d "$config_dir" && ! -L "$config_dir" ]] || return 1
  [[ -f "$key_file" && ! -L "$key_file" ]] || return 1
  local config_mode key_mode expected_uid config_uid key_uid
  expected_uid="$(id -u)"
  config_uid="$(stat -c '%u' "$config_dir")"
  key_uid="$(stat -c '%u' "$key_file")"
  [[ "$config_uid" == "$expected_uid" && "$key_uid" == "$expected_uid" ]] || return 1
  config_mode="$(stat -c '%a' "$config_dir")"
  key_mode="$(stat -c '%a' "$key_file")"
  (( (8#$config_mode & 077) == 0 && (8#$key_mode & 077) == 0 )) || return 1
  local -a lines=()
  mapfile -t lines < "$key_file"
  ((${#lines[@]} == 1)) || return 1
  [[ "${lines[0]}" == DEEPSEEK_API_KEY=* && "${lines[0]}" != "DEEPSEEK_API_KEY=" ]] || return 1
  local value="${lines[0]#DEEPSEEK_API_KEY=}"
  [[ "$value" != *$'\r'* && "$value" != "chave-aqui" && "$value" != "sk-..." ]]
}

doctor_bwrap() {
  command -v bwrap >/dev/null 2>&1 \
    && bwrap --ro-bind / / --dev /dev --proc /proc /bin/true
}

run_doctor() {
  local failures=0
  info "Auditando $INSTALL_DIR"
  doctor_check "Node oficial v$NODE_VERSION com TypeScript interno" doctor_node || failures=$((failures + 1))
  doctor_check "pnpm $PNPM_VERSION isolado" doctor_pnpm || failures=$((failures + 1))
  doctor_check "Harness no commit testado ${HARNESS_COMMIT:0:12} e árvore limpa" \
    doctor_git_commit "$INSTALL_DIR/deepseek-harness" "$HARNESS_COMMIT" || failures=$((failures + 1))
  doctor_check "dsh-unrestricted no commit testado ${PLUGIN_COMMIT:0:12} e árvore limpa" \
    doctor_git_commit "$INSTALL_DIR/plugins/dsh-unrestricted" "$PLUGIN_COMMIT" || failures=$((failures + 1))
  doctor_check "CLI compilada" doctor_regular_file "$INSTALL_DIR/deepseek-harness/apps/cli/lib/bin.js" || failures=$((failures + 1))
  doctor_check "Frontend Web compilado" doctor_regular_file "$INSTALL_DIR/deepseek-harness/apps/web/dist/index.html" || failures=$((failures + 1))
  doctor_check "Addon nativo compilado" doctor_native_addon || failures=$((failures + 1))
  doctor_check "Bundle reproduzível do plugin" doctor_bundle || failures=$((failures + 1))
  doctor_check "Plugin presente no profile Web" doctor_profile || failures=$((failures + 1))
  doctor_check "CLI responde com a versão $HARNESS_VERSION" doctor_cli_version || failures=$((failures + 1))
  doctor_check "Composição efetiva contém dsh-unrestricted" doctor_composition || failures=$((failures + 1))
  doctor_check "Chave presente e protegida contra grupo/outros" doctor_key || failures=$((failures + 1))
  doctor_check "bubblewrap e user namespaces funcionais" doctor_bwrap || failures=$((failures + 1))
  doctor_check "Launcher local é arquivo regular" doctor_regular_file "$INSTALL_DIR/bin/dsh" || failures=$((failures + 1))
  doctor_check "Launcher Web fixa o serviço em 127.0.0.1" doctor_web_launcher || failures=$((failures + 1))
  doctor_check "Telemetria desabilitada no launcher" grep -q 'DSH_TELEMETRY_MODE="DISABLED"' "$INSTALL_DIR/bin/dsh" || failures=$((failures + 1))

  if ((failures > 0)); then
    die "Doctor encontrou $failures falha(s). Consulte o guia e o log de instalação."
  fi
  ok "Doctor não encontrou falhas estruturais. Para testar a conta/API: $INSTALL_DIR/bin/deepseek-api-check"
}

write_install_manifest() {
  local manifest="$INSTALL_DIR/install-manifest.json"
  local temporary
  temporary="$(mktemp "$INSTALL_DIR/.install-manifest.XXXXXX")"
  TEMP_FILES+=("$temporary")
  local test_mode="full"
  ((QUICK == 0)) || test_mode="quick"
  jq -n \
    --arg installedAt "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg installerVersion "$SCRIPT_VERSION" \
    --arg architecture "$(uname -m)" \
    --arg nodeVersion "$NODE_VERSION" \
    --arg pnpmVersion "$PNPM_VERSION" \
    --arg harnessVersion "$HARNESS_VERSION" \
    --arg harnessCommit "$HARNESS_COMMIT" \
    --arg pluginVersion "$PLUGIN_VERSION" \
    --arg pluginCommit "$PLUGIN_COMMIT" \
    --arg pluginBundleSha256 "$PLUGIN_BUNDLE_SHA256" \
    --arg testMode "$test_mode" \
    --arg harnessTestStatus "$HARNESS_TEST_STATUS" \
    --arg harnessPwshStatus "$HARNESS_PWSH_STATUS" \
    '{
      installedAt: $installedAt,
      installerVersion: $installerVersion,
      architecture: $architecture,
      node: {version: $nodeVersion},
      pnpm: {version: $pnpmVersion},
      harness: {version: $harnessVersion, commit: $harnessCommit},
      plugin: {version: $pluginVersion, commit: $pluginCommit, bundleSha256: $pluginBundleSha256},
      validation: {
        mode: $testMode,
        build: true,
        typecheck: true,
        harnessTests: ($harnessTestStatus | startswith("passed")),
        harnessTestStatus: $harnessTestStatus,
        harnessPwshStatus: $harnessPwshStatus,
        pluginTests: true,
        webBoot: true
      }
    }' > "$temporary"
  chmod 600 "$temporary"
  mv -T -- "$temporary" "$manifest"
}

run_install() {
  check_platform
  install_system_dependencies
  validate_prerequisites
  prepare_directories

  install_node_runtime
  install_pnpm_runtime
  activate_toolchain
  prepare_build_tmpdir

  checkout_exact_commit "$HARNESS_REPOSITORY" "$HARNESS_COMMIT" \
    "$INSTALL_DIR/deepseek-harness" "DeepSeek Harness $HARNESS_VERSION"
  checkout_exact_commit "$PLUGIN_REPOSITORY" "$PLUGIN_COMMIT" \
    "$INSTALL_DIR/plugins/dsh-unrestricted" "dsh-unrestricted $PLUGIN_VERSION"

  build_harness
  build_plugin
  install_plugin_profile
  write_wrapper_files
  create_user_links
  web_boot_smoke

  if resolve_api_key 1; then
    if ((SKIP_API_CHECK == 0)); then
      run_api_check
    fi
    # Uma chave nova só substitui o arquivo persistido após autenticar com sucesso.
    # Com --skip-api-check, a persistência direta é a escolha explícita do operador.
    store_api_key
  else
    ((PAID_SMOKE == 0)) || die "--paid-smoke exige uma chave da API."
    warn "Instalação concluída sem chave. Configure DEEPSEEK_API_KEY e rode deepseek-api-check antes de usar."
  fi

  write_install_manifest

  printf '\n'
  ok "Ambiente instalado com sucesso em $INSTALL_DIR"
  printf '  Doctor: %s/bin/deepseek-doctor\n' "$INSTALL_DIR"
  printf '  Interface Web: %s/bin/deepseek-web\n' "$INSTALL_DIR"
  printf '  CLI: %s/bin/dsh --profile headless "sua tarefa"\n' "$INSTALL_DIR"
  printf '  Log: %s\n' "$INSTALL_LOG"
  printf '\nO modo unrestricted foi instalado. O padrão novo é DESLIGADO; reinstalações preservam o estado anterior.\n'
  printf 'Na Web: Configurações → Plugins → Configuração do plugin → Unrestricted mode.\n'
}

prepare_api_check_directories() {
  [[ ! -L "$INSTALL_DIR" ]] \
    || die "A raiz de instalação não pode ser um link simbólico: $INSTALL_DIR"
  mkdir -p -- "$INSTALL_DIR"
  [[ -w "$INSTALL_DIR" ]] || die "Sem permissão de escrita em $INSTALL_DIR."
  [[ ! -L "$INSTALL_DIR/cache" && ! -L "$INSTALL_DIR/config" ]] \
    || die "cache/config contém link simbólico inesperado; nenhum arquivo será alterado."
  mkdir -p -- "$INSTALL_DIR/cache" "$INSTALL_DIR/config"
  chmod 700 "$INSTALL_DIR/config"

  local lock_file="$INSTALL_DIR/.install.lock"
  [[ ! -L "$lock_file" && ! -d "$lock_file" ]] \
    || die "O caminho do lock é um link/diretório inesperado: $lock_file"
  exec {LOCK_FD}>"$lock_file"
  flock -n "$LOCK_FD" \
    || die "Uma instalação/verificação concorrente mantém o lock: $lock_file"
}

main() {
  parse_arguments "$@"
  capture_environment_key
  if [[ -n "$API_KEY" ]]; then
    validate_key_value
  fi
  case "$COMMAND" in
    install) run_install ;;
    doctor)
      check_platform
      validate_prerequisites
      run_doctor
      ;;
    api-check)
      check_platform
      validate_prerequisites
      prepare_api_check_directories
      run_api_check
      if [[ "$API_KEY_SOURCE" != "arquivo protegido" ]]; then
        store_api_key
      fi
      ;;
    *) die "Comando interno desconhecido: $COMMAND" ;;
  esac
}

main "$@"
