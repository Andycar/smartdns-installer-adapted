#!/usr/bin/env bash
# ==============================================================================
# Unified SmartDNS + Transparent SNI Proxy Production Installer (Stealth Edition)
# File: unified-smartdns-installer.sh
# Version: 2.9.1-stealth
# Supported OS: Debian 12, Debian 13 (Trixie), Ubuntu 22.04 LTS, Ubuntu 24.04 LTS
# ==============================================================================

set -Eeuo pipefail
umask 027

# ------------------------------ Global Constants ------------------------------
readonly SCRIPT_NAME="unified-smartdns-installer.sh"
INSTALLER_VERSION="2.10.0-stealth"
readonly LOCK_FILE="/run/lock/unified-smartdns-installer.lock"
readonly STATE_DIR="/var/lib/oxidns-installer"
readonly BACKUP_ROOT="${STATE_DIR}/backups"
readonly SETTINGS_FILE="${STATE_DIR}/settings"
readonly VERSIONS_FILE="${STATE_DIR}/versions.env"
readonly SECRETS_FILE="${STATE_DIR}/secrets.env"
readonly IPSET_SAVE_FILE="${STATE_DIR}/ipset-whitelist.save"
readonly DNS_ASSETS_DIR="/var/lib/dns-assets"
readonly ROUTING_VARS_FILE="${DNS_ASSETS_DIR}/xray-routing-vars.env"
readonly GEOHIDE_LIST_FILE="${DNS_ASSETS_DIR}/geohide-domains.txt"
readonly GEOHIDE_HOSTS_FILE="${DNS_ASSETS_DIR}/geohide-hosts.txt"
readonly AGH_RULES_FILE="${DNS_ASSETS_DIR}/ag-smartdns-rules.txt"
readonly CUSTOM_ALLOW_FILE="${DNS_ASSETS_DIR}/custom-allow.txt"
readonly CUSTOM_DENY_FILE="${DNS_ASSETS_DIR}/custom-deny.txt"
readonly XRAY_CONF_DIR="/etc/xray/conf.d"
readonly XRAY_RULES_DIR="/etc/xray/rules.d"
readonly XRAY_ROUTING_JSON="${XRAY_RULES_DIR}/10-smartdns-routing.json"
readonly LOG_DIR="/var/log/oxidns-installer"
readonly CERT_DIR="/etc/ssl/smartdns"
readonly WEB_ROOT="/var/www/studio-nord"
LAUNCH_DIR="$(pwd)"
readonly LAUNCH_DIR
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
readonly TIMESTAMP

readonly OXIDNS_REPO="https://github.com/svenshi/oxidns"
readonly OXIDNS_DEFAULT_VER="v1.7.1"
readonly OXIDNS_DEFAULT_URL="https://github.com/svenshi/oxidns/releases/download/v1.7.1/oxidns-x86_64-unknown-linux-musl.tar.gz"
readonly XRAY_DEFAULT_VER="v26.11.9"
GEOHIDE_REPO="https://github.com/Internet-Helper/GeoHideDNS"
readonly GEOHIDE_RAW_URL="https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts"
readonly GEOSITE_RAW_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

# Runtime flags
ACTION_MODE=""
TRANSACTION_ACTIVE=0
CURRENT_BACKUP_DIR=""
DOT_WHITELIST_ENABLED="false"
DOT_WHITELIST_MODE="shared"

# ------------------------------ Logging Helpers -------------------------------
init_logging() {
    if [[ "${ACTION_MODE}" == "preflight" || "${ACTION_MODE}" == "help" ]]; then
        return 0
    fi
    mkdir -p "${LOG_DIR}"
    chmod 0750 "${LOG_DIR}"
    for lf in installation.log preflight.log firewall.log dns.log xray.log certificate.log update.log rollback.log; do
        touch "${LOG_DIR}/${lf}"
        chmod 0640 "${LOG_DIR}/${lf}"
    done
}

redact_secrets() {
    local msg="$1"
    if [[ -n "${CF_API_TOKEN:-}" ]]; then
        msg="${msg//${CF_API_TOKEN}/[REDACTED_CF_TOKEN]}"
    fi
    if [[ -n "${DOH_PATH:-}" ]]; then
        msg="${msg//${DOH_PATH}/[REDACTED_DOH_PATH]}"
    fi
    if [[ -n "${AGH_ADMIN_PASS:-}" ]]; then
        msg="${msg//${AGH_ADMIN_PASS}/[REDACTED_PASS]}"
    fi
    printf '%s' "${msg}"
}

log_msg() {
    local level="$1"
    local log_file="$2"
    shift 2
    local raw_msg="$*"
    local safe_msg
    safe_msg="$(redact_secrets "${raw_msg}")"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S %z')"
    printf '[%s] [%s] %s\n' "${ts}" "${level}" "${safe_msg}" >&2
    if [[ "${ACTION_MODE}" != "preflight" && "${ACTION_MODE}" != "help" && -d "${LOG_DIR}" ]]; then
        printf '[%s] [%s] %s\n' "${ts}" "${level}" "${safe_msg}" >> "${LOG_DIR}/${log_file}"
        if [[ "${log_file}" != "installation.log" ]]; then
            printf '[%s] [%s] [%s] %s\n' "${ts}" "${level}" "${log_file}" "${safe_msg}" >> "${LOG_DIR}/installation.log"
        fi
    fi
}

log_info()  { log_msg "INFO"  "${1}" "${@:2}"; }
log_warn()  { log_msg "WARN"  "${1}" "${@:2}"; }
log_error() { log_msg "ERROR" "${1}" "${@:2}"; }

# ------------------------------ Error & Lock Trap -----------------------------
on_error_trap() {
    local exit_code=$?
    local line_no="${1:-unknown}"
    trap - ERR
    if [[ "${BASH_SUBSHELL:-0}" -gt 0 ]]; then
        exit "${exit_code}"
    fi
    log_error "installation.log" "Критическая ошибка выполнения на строке ${line_no} (код возврата: ${exit_code})."
    if [[ "${TRANSACTION_ACTIVE}" -eq 1 && -n "${CURRENT_BACKUP_DIR}" && -d "${CURRENT_BACKUP_DIR}" ]]; then
        log_warn "rollback.log" "Обнаружена незавершённая транзакция. Запуск автоматического аварийного отката..."
        perform_rollback "${CURRENT_BACKUP_DIR}" || true
    fi
    exit "${exit_code}"
}

trap 'on_error_trap ${LINENO}' ERR

acquire_lock() {
    if [[ "${ACTION_MODE}" == "help" ]]; then
        return 0
    fi
    mkdir -p "$(dirname "${LOCK_FILE}")"
    exec 9>"${LOCK_FILE}"
    if ! flock -n 9; then
        printf 'ОШИБКА: Другой экземпляр %s уже запущен (блокировка %s).\n' "${SCRIPT_NAME}" "${LOCK_FILE}" >&2
        exit 1
    fi
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        printf 'ОШИБКА: Скрипт должен запускаться с привилегиями root (sudo).\n' >&2
        exit 1
    fi
}

# ------------------------------ System Discovery ------------------------------
detect_environment() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "preflight.log" "Не найден /etc/os-release. Невозможно определить ОС."
        exit 1
    fi
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION_ID="${VERSION_ID:-unknown}"
    OS_CODENAME="${VERSION_CODENAME:-unknown}"
    OS_PRETTY="${PRETTY_NAME:-unknown}"

    CPU_ARCH="$(uname -m)"
    KERNEL_VER="$(uname -r)"
    CPU_CORES="$(nproc 2>/dev/null || echo 1)"
    MEM_TOTAL_MB="$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)"
    DISK_FREE_MB="$(df -Pm / /var /usr 2>/dev/null | awk 'NR==2 {print $4}')"

    PRIMARY_IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
    if [[ -z "${PRIMARY_IFACE}" ]]; then
        PRIMARY_IFACE="$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')"
    fi

    SERVER_IPV4="$(ip -4 -o addr show dev "${PRIMARY_IFACE}" scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}' || true)"
    SERVER_IPV6="$(ip -6 -o addr show dev "${PRIMARY_IFACE}" scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}' || true)"
    ALL_LOCAL_IPS="$(ip -o addr show 2>/dev/null | awk '{split($4,a,"/"); print a[1]}' | paste -sd ',' -)"

    HAS_IPV6=0
    if [[ -f /proc/net/if_inet6 && -n "${SERVER_IPV6}" ]]; then
        HAS_IPV6=1
    fi

    IPTABLES_BACKEND="unknown"
    if command -v iptables >/dev/null 2>&1; then
        if iptables --version 2>/dev/null | grep -qi "nf_tables"; then
            IPTABLES_BACKEND="iptables-nft"
        else
            IPTABLES_BACKEND="iptables-legacy"
        fi
    fi

    DOCKER_PRESENT=0
    if command -v docker >/dev/null 2>&1 || systemctl is-active --quiet docker 2>/dev/null; then
        DOCKER_PRESENT=1
    fi
}

validate_os_and_resources() {
    local supported=0
    case "${OS_ID}" in
        debian)
            if [[ "${OS_VERSION_ID}" == "12" || "${OS_VERSION_ID}" == "13" || "${OS_CODENAME}" == "trixie" || "${OS_CODENAME}" == "bookworm" ]]; then
                supported=1
            fi
            ;;
        ubuntu)
            if [[ "${OS_VERSION_ID}" == "22.04" || "${OS_VERSION_ID}" == "24.04" ]]; then
                supported=1
            fi
            ;;
    esac

    if [[ "${supported}" -ne 1 ]]; then
        log_error "preflight.log" "Несовместимая ОС: ${OS_PRETTY}. Поддерживаются только Debian 12/13 и Ubuntu 22.04/24.04 LTS."
        exit 1
    fi

    if [[ "${MEM_TOTAL_MB}" -lt 512 ]]; then
        log_error "preflight.log" "Недостаточно оперативной памяти: ${MEM_TOTAL_MB} МБ (требуется минимум 512 МБ)."
        exit 1
    fi

    if [[ "${DISK_FREE_MB}" -lt 1500 ]]; then
        log_error "preflight.log" "Недостаточно свободного места на диске: ${DISK_FREE_MB} МБ (требуется минимум 1500 МБ)."
        exit 1
    fi

    if [[ -z "${SERVER_IPV4}" ]]; then
        log_error "preflight.log" "Не обнаружен глобальный IPv4-адрес на основном интерфейсе ${PRIMARY_IFACE}."
        exit 1
    fi
}

# ------------------------------ Preflight Mode --------------------------------
run_preflight() {
    detect_environment
    printf '==============================================================================\n'
    printf '               ОТЧЁТ PREFLIGHT (РЕЖИМ ТОЛЬКО ЧТЕНИЕ)                          \n'
    printf '==============================================================================\n'
    printf 'ОС и версия          : %s (%s / %s)\n' "${OS_PRETTY}" "${OS_ID}" "${OS_CODENAME}"
    printf 'Ядро Linux           : %s\n' "${KERNEL_VER}"
    printf 'Архитектура CPU      : %s (%s ядер)\n' "${CPU_ARCH}" "${CPU_CORES}"
    printf 'Оперативная память   : %s МБ\n' "${MEM_TOTAL_MB}"
    printf 'Свободно на диске    : %s МБ\n' "${DISK_FREE_MB}"
    printf 'Основной интерфейс   : %s\n' "${PRIMARY_IFACE}"
    printf 'Публичный IPv4       : %s\n' "${SERVER_IPV4:-нет}"
    printf 'Публичный IPv6       : %s (активен: %s)\n' "${SERVER_IPV6:-нет}" "${HAS_IPV6}"
    printf 'Все адреса хоста     : %s\n' "${ALL_LOCAL_IPS}"
    printf 'Firewall backend     : %s\n' "${IPTABLES_BACKEND}"
    printf 'Наличие Docker       : %s\n' "$( [[ "${DOCKER_PRESENT}" -eq 1 ]] && echo "Обнаружен (ВНИМАНИЕ: возможен конфликт NAT)" || echo "Не обнаружен" )"
    printf -- '------------------------------------------------------------------------------\n'
    printf 'Состояние существующих служб:\n'
    for svc in nginx xray oxidns adguardhome ufw; do
        if systemctl is-active --quiet "${svc}" 2>/dev/null; then
            printf '  - %-15s : АКТИВНА\n' "${svc}"
        else
            printf '  - %-15s : не активна / не установлена\n' "${svc}"
        fi
    done
    printf -- '------------------------------------------------------------------------------\n'
    printf 'Проверка совместимости с OxiDNS и AdGuardHome:\n'
    if [[ "${CPU_ARCH}" == "x86_64" ]]; then
        printf '  - OxiDNS      : СОВМЕСТИМ (x86_64)\n'
    else
        printf '  - OxiDNS      : НЕ СОВМЕСТИМ (официальный бинарный релиз требует x86_64)\n'
    fi
    printf '  - AdGuardHome : СОВМЕСТИМ (%s)\n' "${CPU_ARCH}"
    printf -- '------------------------------------------------------------------------------\n'
    printf 'Занятые сокеты (TCP/UDP):\n'
    ss -tulnp 2>/dev/null | sed 's/^/  /' || true
    printf '==============================================================================\n'
    validate_os_and_resources
    printf 'ИТОГ PREFLIGHT: Сервер соответствует требованиям для развёртывания.\n'
}

# ------------------------------ Crypto & Validators ---------------------------
generate_random_alnum() {
    local length="$1"
    local result=""
    while [[ "${#result}" -lt "${length}" ]]; do
        local chunk
        chunk="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "${length}" || true)"
        result+="${chunk}"
    done
    printf '%s' "${result:0:${length}}"
}

generate_random_lower() {
    local length="$1"
    local result=""
    while [[ "${#result}" -lt "${length}" ]]; do
        local chunk
        chunk="$(LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c "${length}" || true)"
        result+="${chunk}"
    done
    printf '%s' "${result:0:${length}}"
}

validate_domain_syntax() {
    local fqdn="$1"
    [[ "${#fqdn}" -le 253 ]] || return 1
    [[ "${fqdn}" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]] || return 1
    return 0
}

validate_single_ipv4() {
    local ip="$1"
    [[ "${ip}" != *"/"* ]] || return 1
    [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    read -r o1 o2 o3 o4 <<<"${ip}"
    [[ "${o1}" -le 255 && "${o2}" -le 255 && "${o3}" -le 255 && "${o4}" -le 255 ]] || return 1
    return 0
}

validate_single_ipv6() {
    local ip="$1"
    [[ "${ip}" != *"/"* ]] || return 1
    [[ "${ip}" == *:* ]] || return 1
    [[ "${ip}" =~ ^[0-9a-fA-F:]+$ ]] || return 1
    return 0
}

# ------------------------------ Interactive Wizard ----------------------------
run_interactive_wizard() {
    local existing_dot_wl=""
    local existing_dot_mode="shared"
    if [[ -f "${SETTINGS_FILE}" ]]; then
        existing_dot_wl="$(awk -F'"' '/^DOT_WHITELIST_ENABLED=/ {print $2}' "${SETTINGS_FILE}" 2>/dev/null || true)"
        existing_dot_mode="$(awk -F'"' '/^DOT_WHITELIST_MODE=/ {print $2}' "${SETTINGS_FILE}" 2>/dev/null || echo "shared")"
    fi

    printf '\n==============================================================================\n'
    printf '   МАСТЕР НАСТРОЙКИ UNIFIED SMARTDNS + TRANSPARENT SNI PROXY (STEALTH MODE)   \n'
    printf '==============================================================================\n\n'

    printf 'Сравнение поддерживаемых DNS-движков:\n'
    printf '+------------------------+-------------------------------+-------------------------------+\n'
    printf '| Характеристика         | 1) OxiDNS (Rust)              | 2) AdGuardHome (Go)           |\n'
    printf '+------------------------+-------------------------------+-------------------------------+\n'
    printf '| Архитектура конвейера  | YAML sequence (hosts/nodata)  | DNS-правила ($dnsrewrite)     |\n'
    printf '| Блокировка рекламы     | Нативно через geosite.dat     | Списки фильтров AdGuard       |\n'
    printf '| Поддержка NODATA       | Нативно через hosts/reject    | Правила $dnsrewrite=NOERROR   |\n'
    printf '| Веб-панель управления  | Отсутствует (конфиг YAML)     | Есть (локально 127.0.0.1:8053)|\n'
    printf '| Поддержка архитектур   | Только x86_64                 | x86_64, aarch64, armv7        |\n'
    printf '+------------------------+-------------------------------+-------------------------------+\n\n'

    while true; do
        read -r -p "Выберите DNS-движок [1 - OxiDNS, 2 - AdGuardHome] (по умолчанию 1): " engine_choice
        engine_choice="${engine_choice:-1}"
        if [[ "${engine_choice}" == "1" ]]; then
            if [[ "${CPU_ARCH}" != "x86_64" ]]; then
                printf 'ОШИБКА: OxiDNS предоставляет официальную сборку только для x86_64. Ваша архитектура: %s.\n' "${CPU_ARCH}"
                continue
            fi
            DNS_ENGINE="oxidns"
            DNS_USER="oxidns"
            break
        elif [[ "${engine_choice}" == "2" ]]; then
            DNS_ENGINE="adguardhome"
            DNS_USER="adguard"
            break
        else
            printf 'Пожалуйста, введите 1 или 2.\n'
        fi
    done

    while true; do
        read -r -p "Введите основной домен (ROOT_DOMAIN, например example.com): " ROOT_DOMAIN
        ROOT_DOMAIN="${ROOT_DOMAIN,,}"
        if validate_domain_syntax "${ROOT_DOMAIN}"; then
            break
        fi
        printf 'ОШИБКА: Некорректный синтаксис доменного имени.\n'
    done

    DOH_HOST="${ROOT_DOMAIN}"
    printf 'Режим маскировки DoH       : используется корневой домен https://%s/resolve/[SECRET]\n' "${DOH_HOST}"

    local default_dot_prefix
    default_dot_prefix="$(generate_random_lower 10)"
    while true; do
        read -r -p "Введите поддомен для DoT (DOT_HOST, по умолчанию ${default_dot_prefix}.${ROOT_DOMAIN}): " DOT_HOST
        DOT_HOST="${DOT_HOST:-${default_dot_prefix}.${ROOT_DOMAIN}}"
        DOT_HOST="${DOT_HOST,,}"
        if validate_domain_syntax "${DOT_HOST}" && [[ "${DOT_HOST}" == *".${ROOT_DOMAIN}" ]] && [[ "${DOT_HOST}" != "${ROOT_DOMAIN}" ]]; then
            break
        fi
        printf 'ОШИБКА: DOT_HOST должен быть валидным поддоменом *.%s.\n' "${ROOT_DOMAIN}"
    done

    printf '\nНастройка секретного пути DoH и веб-авторизации (минимум 48 символов):\n'
    read -r -p "Сгенерировать криптографически случайный путь автоматически? [Y/n]: " auto_doh
    auto_doh="${auto_doh:-Y}"
    if [[ "${auto_doh}" =~ ^[Yy]$ ]]; then
        DOH_PATH="$(generate_random_alnum 52)"
    else
        while true; do
            read -r -s -p "Введите собственный секретный путь DoH (не менее 48 букв/цифр): " DOH_PATH
            printf '\n'
            if [[ "${#DOH_PATH}" -ge 48 && "${DOH_PATH}" =~ ^[A-Za-z0-9]+$ ]]; then
                break
            fi
            printf 'ОШИБКА: Путь должен содержать минимум 48 символов (только латинские буквы и цифры).\n'
        done
    fi

    printf '\nНастройка IP-whitelist для DNS-over-TLS (DoT, TCP 853):\n'
    if [[ -n "${existing_dot_wl}" ]]; then
        printf 'Текущее сохранённое значение DOT_WHITELIST_ENABLED: %s (режим: %s)\n' "${existing_dot_wl}" "${existing_dot_mode}"
    fi
    local dot_wl_prompt="Требуется ли включить предварительный whitelist IP-адресов для DoT (TCP 853)? [y/N]: "
    read -r -p "${dot_wl_prompt}" dot_wl_choice
    if [[ -z "${dot_wl_choice}" && -n "${existing_dot_wl}" ]]; then
        read -r -p "Оставить текущее значение (${existing_dot_wl}) без изменений? [Y/n]: " keep_existing_wl
        if [[ "${keep_existing_wl:-Y}" =~ ^[Yy]$ ]]; then
            DOT_WHITELIST_ENABLED="${existing_dot_wl}"
            DOT_WHITELIST_MODE="${existing_dot_mode:-shared}"
        else
            DOT_WHITELIST_ENABLED="false"
            DOT_WHITELIST_MODE="shared"
        fi
    elif [[ "${dot_wl_choice:-N}" =~ ^[Yy]$ ]]; then
        DOT_WHITELIST_ENABLED="true"
    else
        DOT_WHITELIST_ENABLED="false"
    fi

    if [[ "${DOT_WHITELIST_ENABLED}" == "true" ]]; then
        printf 'Выберите режим работы whitelist для DoT:\n'
        printf '  1 — общий whitelist smartdns_clients для DoH и DoT (по умолчанию)\n'
        printf '  2 — отдельный независимый whitelist dot_clients для DoT (с автодоступом к SNI-прокси)\n'
        read -r -p "Режим whitelist [1/2] (по умолчанию 1): " wl_mode_choice
        if [[ "${wl_mode_choice:-1}" == "2" ]]; then
            DOT_WHITELIST_MODE="separate"
        else
            DOT_WHITELIST_MODE="shared"
        fi
    else
        DOT_WHITELIST_MODE="${existing_dot_mode:-shared}"
    fi

    printf '\nНастройка фильтра фоновых системных доменов Google/Android (EXCLUDE_GOOGLE_SYS):\n'
    printf '  y — исключить фоновые домены (apis.google.com, *.clients.google.com и др.), сохранив generativelanguage.googleapis.com\n'
    printf '  N — оставить все домены Google в проксируемом списке (по умолчанию N)\n'
    read -r -p "Исключить фоновые домены Google? [y/N]: " excl_google
    if [[ "${excl_google:-N}" =~ ^[Yy]$ ]]; then
        EXCLUDE_GOOGLE_SYS="y"
    else
        EXCLUDE_GOOGLE_SYS="N"
    fi

    printf '\nНастройка дополнительных фильтров (INCLUDE_XBOX_IPIFY):\n'
    printf '  y — включить домены Xbox Live в проксируемый список\n'
    printf '  N — исключить их (по умолчанию N)\n'
    read -r -p "Включить домены Xbox Live? [y/N]: " incl_xbox
    if [[ "${incl_xbox:-N}" =~ ^[Yy]$ ]]; then
        INCLUDE_XBOX_IPIFY="y"
    else
        INCLUDE_XBOX_IPIFY="N"
    fi

    local saved_cf_token=""
    if [[ -f "${SECRETS_FILE}" ]]; then
        saved_cf_token="$(awk -F'"' '/^CF_API_TOKEN=/ {print $2}' "${SECRETS_FILE}" 2>/dev/null || true)"
    fi

    while true; do
        if [[ -n "${saved_cf_token}" && "${saved_cf_token}" != "REUSE_EXISTING_CERT_TOKEN" ]]; then
            read -r -s -p "Введите Cloudflare API Token (или нажмите Enter для использования сохранённого токена): " CF_API_TOKEN
            printf '\n'
            CF_API_TOKEN="${CF_API_TOKEN:-${saved_cf_token}}"
            break
        else
            read -r -s -p "Введите Cloudflare API Token (с правами Zone:DNS:Edit для синхронизации DNS и выпуска сертификата ${ROOT_DOMAIN}): " CF_API_TOKEN
            printf '\n'
            if [[ -n "${CF_API_TOKEN}" && "${#CF_API_TOKEN}" -ge 20 ]]; then
                break
            fi
            printf 'ОШИБКА: API-токен Cloudflare необходим для автоматической привязки IP сервера к домену и выпуска сертификата.\n'
        fi
    done

    read -r -p "Введите контактный email для выпуска сертификатов Let's Encrypt (по умолчанию admin@${ROOT_DOMAIN}): " ACME_EMAIL
    ACME_EMAIL="${ACME_EMAIL:-admin@${ROOT_DOMAIN}}"

    printf '\n==============================================================================\n'
    printf '                    ПОДТВЕРЖДЕНИЕ ПАРАМЕТРОВ УСТАНОВКИ                        \n'
    printf '==============================================================================\n'
    printf 'Выбранный DNS-движок       : %s (системный пользователь: %s)\n' "${DNS_ENGINE}" "${DNS_USER}"
    printf 'Основной домен (Сайт + DoH): %s (единый TLS SNI профиль)\n' "${ROOT_DOMAIN}"
    printf 'Домен DoT                  : %s\n' "${DOT_HOST}"
    printf 'Секретный путь DoH / Auth  : [СКРЫТО, длина %d симв.]\n' "${#DOH_PATH}"
    printf 'DoT IP-whitelist (TCP 853) : %s (режим: %s)\n' "${DOT_WHITELIST_ENABLED}" "${DOT_WHITELIST_MODE}"
    printf 'EXCLUDE_GOOGLE_SYS         : %s\n' "${EXCLUDE_GOOGLE_SYS}"
    printf 'INCLUDE_XBOX_IPIFY         : %s\n' "${INCLUDE_XBOX_IPIFY}"
    printf 'Публичные порты            : 80/TCP, 443/TCP, 853/TCP\n'
    printf 'Внутренние порты           : 8444/TCP (Xray), 9443/9444 (Nginx), 8853/TCP (DoT), 5353 (DNS), 8053 (DoH)\n'
    printf 'План Firewall              : UFW + %s + ipset (smartdns_clients / dot_clients, TTL 86400s)\n' "${IPTABLES_BACKEND}"
    if [[ "${DOCKER_PRESENT}" -eq 1 ]]; then
        printf 'ПРЕДУПРЕЖДЕНИЕ             : Обнаружен Docker. Правила PREROUTING будут вставлены перед цепочками DOCKER.\n'
    fi
    printf '==============================================================================\n'

    read -r -p "Подтверждаете внесение изменений в конфигурацию сервера? [y/N]: " confirm_install
    if [[ ! "${confirm_install:-N}" =~ ^[Yy]$ ]]; then
        printf 'Установка отменена пользователем.\n'
        exit 0
    fi
}

# ------------------------------ Backup & Rollback -----------------------------
create_system_backup() {
    CURRENT_BACKUP_DIR="${BACKUP_ROOT}/backup-${TIMESTAMP}"
    mkdir -p "${CURRENT_BACKUP_DIR}"
    chmod 0700 "${CURRENT_BACKUP_DIR}"
    install -d -m 0755 "${CURRENT_BACKUP_DIR}/fs"
    log_info "rollback.log" "Создание полной резервной копии в ${CURRENT_BACKUP_DIR}..."

    for path in /etc/nginx /etc/xray /etc/oxidns /etc/adguardhome /etc/ufw "${CERT_DIR}" "${STATE_DIR}/settings" "${DNS_ASSETS_DIR}" "${IPSET_SAVE_FILE}"; do
        if [[ -e "${path}" ]]; then
            local rel_path="${path#/}"
            local parent_dir
            parent_dir="${CURRENT_BACKUP_DIR}/fs/$(dirname "${rel_path}")"
            mkdir -p "${parent_dir}"
            chmod 0755 "${CURRENT_BACKUP_DIR}/fs" "${CURRENT_BACKUP_DIR}/fs/etc" "${CURRENT_BACKUP_DIR}/fs/var" "${CURRENT_BACKUP_DIR}/fs/var/lib" 2>/dev/null || true
            cp -a "${path}" "${CURRENT_BACKUP_DIR}/fs/${rel_path}"
        fi
    done

    mkdir -p "${CURRENT_BACKUP_DIR}/systemd"
    for unit in xray.service xray-reload.path xray-reload.service oxidns.service adguardhome.service \
                doh-ipset-watcher.service dot-ipset-watcher.service geohide-update.service geohide-update.timer \
                geosite-update.service geosite-update.timer smartdns-firewall.service; do
        if [[ -f "/etc/systemd/system/${unit}" ]]; then
            cp -a "/etc/systemd/system/${unit}" "${CURRENT_BACKUP_DIR}/systemd/"
        fi
    done

    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "${CURRENT_BACKUP_DIR}/iptables.v4" 2>/dev/null || true
    fi
    if command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save > "${CURRENT_BACKUP_DIR}/iptables.v6" 2>/dev/null || true
    fi
    if command -v ipset >/dev/null 2>&1; then
        ipset save > "${CURRENT_BACKUP_DIR}/ipset.rules" 2>/dev/null || true
    fi

    printf '%s\n' "${CURRENT_BACKUP_DIR}" > "${STATE_DIR}/latest_backup"
    log_info "rollback.log" "Резервная копия успешно создана: ${CURRENT_BACKUP_DIR}"
}

perform_rollback() {
    local target_backup="${1:-}"
    if [[ -z "${target_backup}" && -f "${STATE_DIR}/latest_backup" ]]; then
        target_backup="$(cat "${STATE_DIR}/latest_backup")"
    fi
    if [[ -z "${target_backup}" || ! -d "${target_backup}" ]]; then
        log_error "rollback.log" "Не найдена директория резервной копии для отката."
        exit 1
    fi

    TRANSACTION_ACTIVE=0
    log_warn "rollback.log" "Восстановление состояния системы из ${target_backup}..."

    if command -v ufw >/dev/null 2>&1; then
        ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null 2>&1 || true
    fi

    if [[ -d "${target_backup}/fs" ]]; then
        chmod 0755 "${target_backup}/fs" "${target_backup}/fs/etc" "${target_backup}/fs/var" "${target_backup}/fs/var/lib" 2>/dev/null || true
        cp -a "${target_backup}/fs/." /
        chmod 0755 / /etc /var /var/lib /var/log /usr /usr/local /usr/local/bin /run /etc/ssl /etc/ssl/certs
        chmod 0644 /etc/ssl/certs/ca-certificates.crt /etc/resolv.conf 2>/dev/null || true
    fi
    if [[ -d "${target_backup}/systemd" ]]; then
        cp -a "${target_backup}/systemd/." /etc/systemd/system/
        systemctl daemon-reload || true
    fi
    if [[ -f "${target_backup}/ipset.rules" ]] && command -v ipset >/dev/null 2>&1; then
        ipset restore -! < "${target_backup}/ipset.rules" || true
    fi
    if [[ -f "${target_backup}/iptables.v4" ]] && command -v iptables-restore >/dev/null 2>&1; then
        iptables-restore < "${target_backup}/iptables.v4" || true
    fi
    if [[ -f "${target_backup}/iptables.v6" ]] && command -v ip6tables-restore >/dev/null 2>&1; then
        ip6tables-restore < "${target_backup}/iptables.v6" || true
    fi

    local restored_engine="oxidns"
    if [[ -f "${SETTINGS_FILE}" ]]; then
        restored_engine="$(awk -F'"' '/^DNS_ENGINE=/ {print $2}' "${SETTINGS_FILE}" 2>/dev/null || echo "oxidns")"
    fi

    if [[ "${restored_engine}" == "adguardhome" ]]; then
        chown -R adguard:xray "${DNS_ASSETS_DIR}" "${XRAY_RULES_DIR}" 2>/dev/null || true
        systemctl disable --now oxidns.service 2>/dev/null || true
        systemctl enable --now adguardhome.service 2>/dev/null || true
    else
        chown -R oxidns:xray "${DNS_ASSETS_DIR}" "${XRAY_RULES_DIR}" 2>/dev/null || true
        systemctl disable --now adguardhome.service 2>/dev/null || true
        systemctl enable --now oxidns.service 2>/dev/null || true
    fi

    for svc in nginx xray doh-ipset-watcher dot-ipset-watcher; do
        if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1; then
            systemctl restart "${svc}" 2>/dev/null || true
        fi
    done

    log_info "rollback.log" "Откат из резервной копии ${target_backup} завершён (активный DNS backend: ${restored_engine})."
}

# ------------------------------ Base Dependencies -----------------------------
install_system_packages() {
    log_info "installation.log" "Установка системных пакетов и официального репозитория Nginx..."
    umask 022
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y -q
    apt-get install -y -q curl ca-certificates gnupg2 lsb-release jq ufw ipset conntrack \
        dnsutils openssl tar unzip socat cron logrotate python3-bcrypt

    chmod 0755 /etc/ssl /etc/ssl/certs /usr/share/ca-certificates 2>/dev/null || true
    find /usr/share/ca-certificates -type d -exec chmod 0755 {} + 2>/dev/null || true
    find /usr/share/ca-certificates -type f -exec chmod 0644 {} + 2>/dev/null || true
    update-ca-certificates --fresh >/dev/null 2>&1 || true
    chmod 0644 /etc/ssl/certs/ca-certificates.crt /etc/resolv.conf 2>/dev/null || true

    install -d -m 0755 /etc/apt/keyrings
    if [[ ! -f /etc/apt/keyrings/nginx-archive-keyring.gpg ]]; then
        curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /etc/apt/keyrings/nginx-archive-keyring.gpg
        chmod 0644 /etc/apt/keyrings/nginx-archive-keyring.gpg
    fi

    if [[ "${OS_ID}" == "debian" ]]; then
        printf 'deb [signed-by=/etc/apt/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian %s nginx\n' "${OS_CODENAME}" \
            > /etc/apt/sources.list.d/nginx-official.list
    else
        printf 'deb [signed-by=/etc/apt/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu %s nginx\n' "${OS_CODENAME}" \
            > /etc/apt/sources.list.d/nginx-official.list
    fi

    cat > /etc/apt/preferences.d/99nginx-official <<'EOF'
Package: *
Pin: origin nginx.org
Pin: release o=nginx
Pin-Priority: 900
EOF

    apt-get update -y -q
    apt-get install -y -q nginx
    umask 027
    NGINX_INSTALLED_VER="$(nginx -v 2>&1 | awk -F'/' '{print $2}')"
    log_info "installation.log" "Установлен стабильный Nginx версии: ${NGINX_INSTALLED_VER}"
}

# ------------------------------ Users & Permissions ---------------------------
setup_users_and_dirs() {
    log_info "installation.log" "Настройка непривилегированных пользователей, перекрёстных групп и прав доступа..."

    chmod 0755 / /etc /var /var/lib /var/log /usr /usr/local /usr/local/bin /run /etc/ssl /etc/ssl/certs 2>/dev/null || true
    chmod 0644 /etc/ssl/certs/ca-certificates.crt /etc/resolv.conf 2>/dev/null || true

    for usr in xray "${DNS_USER}"; do
        if ! getent group "${usr}" >/dev/null 2>&1; then
            groupadd --system "${usr}"
        fi
        if ! id -u "${usr}" >/dev/null 2>&1; then
            useradd --system --gid "${usr}" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "${usr}"
        else
            usermod --shell /usr/sbin/nologin --home /nonexistent "${usr}"
        fi
    done

    if ! getent group ssl-smartdns >/dev/null 2>&1; then
        groupadd --system ssl-smartdns
    fi

    usermod -aG xray "${DNS_USER}"
    usermod -aG "${DNS_USER}" xray

    if ! id -u www-data >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin www-data
    fi
    usermod -aG ssl-smartdns www-data
    gpasswd -d xray ssl-smartdns >/dev/null 2>&1 || true

    install -d -m 0700 -o root -g root "${STATE_DIR}" "${BACKUP_ROOT}"
    install -d -m 0750 -o root -g xray /etc/xray "${XRAY_CONF_DIR}"
    install -d -m 2750 -o "${DNS_USER}" -g xray "${XRAY_RULES_DIR}" "${DNS_ASSETS_DIR}"
    install -d -m 0750 -o root -g ssl-smartdns "${CERT_DIR}"
    install -d -m 0755 -o root -g root "${WEB_ROOT}" "${WEB_ROOT}/assets"
    install -d -m 0750 -o "${DNS_USER}" -g "${DNS_USER}" "/etc/${DNS_ENGINE}" "/var/lib/${DNS_ENGINE}"

    chown -R "${DNS_USER}:xray" "${DNS_ASSETS_DIR}" "${XRAY_RULES_DIR}" 2>/dev/null || true
    touch "${CUSTOM_ALLOW_FILE}" "${CUSTOM_DENY_FILE}" "${GEOHIDE_LIST_FILE}" "${GEOHIDE_HOSTS_FILE}"
    chown "${DNS_USER}:xray" "${CUSTOM_ALLOW_FILE}" "${CUSTOM_DENY_FILE}" "${GEOHIDE_LIST_FILE}" "${GEOHIDE_HOSTS_FILE}"
    chmod 0640 "${CUSTOM_ALLOW_FILE}" "${CUSTOM_DENY_FILE}" "${GEOHIDE_LIST_FILE}" "${GEOHIDE_HOSTS_FILE}"
}

save_persistent_settings() {
    DOH_HOST="${ROOT_DOMAIN}"
    local tmp_settings="${SETTINGS_FILE}.tmp"
    cat > "${tmp_settings}" <<EOF
DNS_ENGINE="${DNS_ENGINE}"
DNS_USER="${DNS_USER}"
ROOT_DOMAIN="${ROOT_DOMAIN}"
DOH_HOST="${ROOT_DOMAIN}"
DOT_HOST="${DOT_HOST}"
DOT_WHITELIST_ENABLED="${DOT_WHITELIST_ENABLED}"
DOT_WHITELIST_MODE="${DOT_WHITELIST_MODE}"
EXCLUDE_GOOGLE_SYS="${EXCLUDE_GOOGLE_SYS}"
INCLUDE_XBOX_IPIFY="${INCLUDE_XBOX_IPIFY}"
SERVER_IPV4="${SERVER_IPV4}"
SERVER_IPV6="${SERVER_IPV6}"
HAS_IPV6="${HAS_IPV6}"
PRIMARY_IFACE="${PRIMARY_IFACE}"
ACME_EMAIL="${ACME_EMAIL}"
EOF
    chmod 0600 "${tmp_settings}"
    mv -f "${tmp_settings}" "${SETTINGS_FILE}"

    local tmp_vars="${ROUTING_VARS_FILE}.tmp"
    cat > "${tmp_vars}" <<EOF
DNS_ENGINE="${DNS_ENGINE}"
DOT_WHITELIST_ENABLED="${DOT_WHITELIST_ENABLED}"
DOT_WHITELIST_MODE="${DOT_WHITELIST_MODE}"
EXCLUDE_GOOGLE_SYS="${EXCLUDE_GOOGLE_SYS}"
INCLUDE_XBOX_IPIFY="${INCLUDE_XBOX_IPIFY}"
SERVER_IPV4="${SERVER_IPV4}"
EOF
    chown "${DNS_USER}:xray" "${tmp_vars}"
    chmod 0640 "${tmp_vars}"
    mv -f "${tmp_vars}" "${ROUTING_VARS_FILE}"

    local tmp_secrets="${SECRETS_FILE}.tmp"
    cat > "${tmp_secrets}" <<EOF
DOH_PATH="${DOH_PATH}"
CF_API_TOKEN="${CF_API_TOKEN}"
EOF
    if [[ -n "${AGH_ADMIN_USER:-}" ]]; then
        printf 'AGH_ADMIN_USER="%s"\n' "${AGH_ADMIN_USER}" >> "${tmp_secrets}"
    fi
    if [[ -n "${AGH_ADMIN_PASS:-}" ]]; then
        printf 'AGH_ADMIN_PASS="%s"\n' "${AGH_ADMIN_PASS}" >> "${tmp_secrets}"
    fi
    chmod 0600 "${tmp_secrets}"
    mv -f "${tmp_secrets}" "${SECRETS_FILE}"
}

# ------------------------------ Binary Installers -----------------------------
install_xray_binary() {
    local tag_name="${XRAY_DEFAULT_VER}"
    local zip_url=""

    case "${CPU_ARCH}" in
        x86_64)
            zip_url="https://github.com/XTLS/Xray-core/releases/download/${tag_name}/Xray-linux-64.zip"
            ;;
        aarch64)
            zip_url="https://github.com/XTLS/Xray-core/releases/download/${tag_name}/Xray-linux-arm64-v8a.zip"
            ;;
        *)
            log_error "xray.log" "Неподдерживаемая архитектура CPU для Xray: ${CPU_ARCH}"
            exit 1
            ;;
    esac

    log_info "xray.log" "Проверка релизов Xray-core (базовый релиз: ${tag_name})..."
    local api_json=""
    if api_json="$(curl -fsSL --retry 2 --connect-timeout 10 https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null)"; then
        local latest_tag
        latest_tag="$(printf '%s' "${api_json}" | jq -r '.tag_name // empty')"
        local pre_flag
        pre_flag="$(printf '%s' "${api_json}" | jq -r '.prerelease // true')"
        if [[ -n "${latest_tag}" && "${latest_tag}" != "null" && "${pre_flag}" == "false" ]]; then
            tag_name="${latest_tag}"
            if [[ "${CPU_ARCH}" == "x86_64" ]]; then
                zip_url="https://github.com/XTLS/Xray-core/releases/download/${tag_name}/Xray-linux-64.zip"
            else
                zip_url="https://github.com/XTLS/Xray-core/releases/download/${tag_name}/Xray-linux-arm64-v8a.zip"
            fi
        fi
    else
        log_warn "xray.log" "api.github.com недоступен, используется прямая ссылка: ${zip_url}"
    fi

    local dgst_url="${zip_url}.dgst"
    local tmp_dir
    tmp_dir="$(mktemp -d /tmp/xray-install.XXXXXX)"

    log_info "xray.log" "Загрузка Xray-core (${tag_name}) из ${zip_url}..."
    curl -fsSL --retry 3 --connect-timeout 15 -o "${tmp_dir}/Xray.zip" "${zip_url}"
    curl -fsSL --retry 3 --connect-timeout 15 -o "${tmp_dir}/Xray.zip.dgst" "${dgst_url}"

    local expected_sha256
    expected_sha256="$(awk -F'= ' '/SHA2-256=/ {print $2; exit}' "${tmp_dir}/Xray.zip.dgst" | tr -d ' \r\n')"
    local actual_sha256
    actual_sha256="$(sha256sum "${tmp_dir}/Xray.zip" | awk '{print $1}')"

    if [[ -z "${expected_sha256}" || "${expected_sha256}" != "${actual_sha256}" ]]; then
        rm -rf "${tmp_dir}"
        log_error "xray.log" "Ошибка проверки SHA-256 архива Xray! Ожидался: ${expected_sha256}, получен: ${actual_sha256}"
        exit 1
    fi

    unzip -q "${tmp_dir}/Xray.zip" -d "${tmp_dir}/unpacked"
    if [[ ! -x "${tmp_dir}/unpacked/xray" ]]; then
        chmod +x "${tmp_dir}/unpacked/xray"
    fi

    local ver_out
    ver_out="$("${tmp_dir}/unpacked/xray" version | sed -n '1p')"
    install -m 0755 -o root -g root "${tmp_dir}/unpacked/xray" /usr/local/bin/xray.new
    mv -f /usr/local/bin/xray.new /usr/local/bin/xray
    rm -rf "${tmp_dir}"

    XRAY_INSTALLED_VER="${tag_name}"
    XRAY_SOURCE_URL="${zip_url}"
    log_info "xray.log" "Установлен и проверен Xray-core: ${ver_out} (${tag_name})"
}

install_oxidns_binary() {
    if [[ "${CPU_ARCH}" != "x86_64" ]]; then
        log_error "dns.log" "OxiDNS поддерживает только архитектуру x86_64. Текущая архитектура: ${CPU_ARCH}."
        exit 1
    fi

    local target_ver="${OXIDNS_DEFAULT_VER}"
    local target_url="${OXIDNS_DEFAULT_URL}"

    log_info "dns.log" "Проверка релизов OxiDNS в официальном репозитории ${OXIDNS_REPO}..."
    local latest_json=""
    if latest_json="$(curl -fsSL --retry 2 --connect-timeout 10 https://api.github.com/repos/svenshi/oxidns/releases/latest 2>/dev/null)"; then
        local latest_tag
        latest_tag="$(printf '%s' "${latest_json}" | jq -r '.tag_name // empty')"
        local latest_pre
        latest_pre="$(printf '%s' "${latest_json}" | jq -r '.prerelease // true')"
        local latest_asset
        latest_asset="$(printf '%s' "${latest_json}" | jq -r '.assets[]? | select(.name | test("x86_64.*linux.*tar\\.gz$")) | .browser_download_url' | sed -n '1p')"
        if [[ -n "${latest_tag}" && "${latest_pre}" == "false" && -n "${latest_asset}" ]]; then
            target_ver="${latest_tag}"
            target_url="${latest_asset}"
        fi
    fi

    local tmp_dir
    tmp_dir="$(mktemp -d /tmp/oxidns-install.XXXXXX)"
    log_info "dns.log" "Загрузка OxiDNS (${target_ver}) из ${target_url}..."
    curl -fsSL --retry 3 --connect-timeout 15 -o "${tmp_dir}/oxidns.tar.gz" "${target_url}"

    if ! gzip -t "${tmp_dir}/oxidns.tar.gz" 2>/dev/null; then
        rm -rf "${tmp_dir}"
        log_error "dns.log" "Загруженный архив OxiDNS повреждён."
        exit 1
    fi

    tar -xzf "${tmp_dir}/oxidns.tar.gz" -C "${tmp_dir}"
    local bin_path
    bin_path="$(find "${tmp_dir}" -type f -name "oxidns" | sed -n '1p')"
    if [[ -z "${bin_path}" ]]; then
        rm -rf "${tmp_dir}"
        log_error "dns.log" "В архиве OxiDNS не найден исполняемый файл oxidns."
        exit 1
    fi
    chmod 0755 "${bin_path}"

    local actual_ver
    actual_ver="$("${bin_path}" --version 2>&1 || "${bin_path}" -V 2>&1 || echo "${target_ver}")"
    install -m 0755 -o root -g root "${bin_path}" /usr/local/bin/oxidns.new
    mv -f /usr/local/bin/oxidns.new /usr/local/bin/oxidns
    rm -rf "${tmp_dir}"

    DNS_INSTALLED_VER="${target_ver} (${actual_ver})"
    DNS_SOURCE_URL="${target_url}"
    log_info "dns.log" "OxiDNS успешно установлен в /usr/local/bin/oxidns: ${DNS_INSTALLED_VER}"
}

install_adguardhome_binary() {
    log_info "dns.log" "Получение информации о последнем стабильном релизе AdGuardHome..."
    local api_json
    api_json="$(curl -fsSL --retry 3 --connect-timeout 10 https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest)"
    local tag_name
    tag_name="$(printf '%s' "${api_json}" | jq -r '.tag_name')"
    local pre_flag
    pre_flag="$(printf '%s' "${api_json}" | jq -r '.prerelease')"
    if [[ -z "${tag_name}" || "${tag_name}" == "null" || "${pre_flag}" != "false" ]]; then
        log_error "dns.log" "Не удалось получить стабильный релиз AdGuardHome."
        exit 1
    fi

    local agh_arch=""
    case "${CPU_ARCH}" in
        x86_64)  agh_arch="amd64" ;;
        aarch64) agh_arch="arm64" ;;
        *)
            log_error "dns.log" "Неподдерживаемая архитектура для AdGuardHome: ${CPU_ARCH}"
            exit 1
            ;;
    esac

    local tar_url="https://github.com/AdguardTeam/AdGuardHome/releases/download/${tag_name}/AdGuardHome_linux_${agh_arch}.tar.gz"
    local tmp_dir
    tmp_dir="$(mktemp -d /tmp/agh-install.XXXXXX)"
    curl -fsSL --retry 3 --connect-timeout 15 -o "${tmp_dir}/agh.tar.gz" "${tar_url}"

    tar -xzf "${tmp_dir}/agh.tar.gz" -C "${tmp_dir}"
    if [[ ! -f "${tmp_dir}/AdGuardHome/AdGuardHome" ]]; then
        rm -rf "${tmp_dir}"
        log_error "dns.log" "Не найден бинарный файл AdGuardHome после распаковки."
        exit 1
    fi

    chmod 0755 "${tmp_dir}/AdGuardHome/AdGuardHome"
    local ver_out
    ver_out="$("${tmp_dir}/AdGuardHome/AdGuardHome" --version 2>&1 | sed -n '1p')"
    install -m 0755 -o root -g root "${tmp_dir}/AdGuardHome/AdGuardHome" /usr/local/bin/AdGuardHome.new
    mv -f /usr/local/bin/AdGuardHome.new /usr/local/bin/AdGuardHome
    rm -rf "${tmp_dir}"

    DNS_INSTALLED_VER="${tag_name} (${ver_out})"
    DNS_SOURCE_URL="${tar_url}"
    log_info "dns.log" "AdGuardHome успешно установлен: ${DNS_INSTALLED_VER}"
}

record_installed_versions() {
    local tmp_ver="${VERSIONS_FILE}.tmp"
    cat > "${tmp_ver}" <<EOF
INSTALL_DATE="$(date -Is)"
INSTALLER_VERSION="${INSTALLER_VERSION}"
DNS_ENGINE="${DNS_ENGINE}"
DNS_VERSION="${DNS_INSTALLED_VER}"
DNS_SOURCE_URL="${DNS_SOURCE_URL}"
XRAY_VERSION="${XRAY_INSTALLED_VER}"
XRAY_SOURCE_URL="${XRAY_SOURCE_URL}"
NGINX_VERSION="${NGINX_INSTALLED_VER}"
NGINX_SOURCE="http://nginx.org/packages/${OS_ID}"
GEOHIDE_REPO="${GEOHIDE_REPO}"
GEOHIDE_SOURCE_URL="${GEOHIDE_RAW_URL}"
EOF
    chmod 0640 "${tmp_ver}"
    mv -f "${tmp_ver}" "${VERSIONS_FILE}"
}

# ------------------------------ Cloudflare DNS Synchronization ----------------
sync_cloudflare_dns_records() {
    local new_ipv4="$1"
    local new_ipv6="${2:-}"

    # shellcheck disable=SC1091
    [[ -f "${SECRETS_FILE}" ]] && source "${SECRETS_FILE}"

    if [[ -z "${CF_API_TOKEN:-}" || "${CF_API_TOKEN}" == "REUSE_EXISTING_CERT_TOKEN" ]]; then
        if [[ -t 0 ]]; then
            read -r -s -p "Введите Cloudflare API Token (с правами Zone:DNS:Edit для ${ROOT_DOMAIN}): " CF_API_TOKEN
            printf '\n'
            if [[ -n "${CF_API_TOKEN}" && "${#CF_API_TOKEN}" -ge 20 ]]; then
                sed -i "s|^CF_API_TOKEN=.*|CF_API_TOKEN=\"${CF_API_TOKEN}\"|" "${SECRETS_FILE}" 2>/dev/null || true
            else
                log_error "update.log" "Некорректный Cloudflare API Token. Пропуск обновления DNS в Cloudflare."
                return 1
            fi
        else
            log_warn "update.log" "CF_API_TOKEN не задан в ${SECRETS_FILE}. Пропуск обновления Cloudflare API."
            return 1
        fi
    fi

    log_info "update.log" "Получение Zone ID в Cloudflare для домена ${ROOT_DOMAIN}..."
    local zone_resp
    zone_resp="$(curl -fsSL --retry 3 --connect-timeout 10 -G \
        "https://api.cloudflare.com/client/v4/zones" \
        --data-urlencode "name=${ROOT_DOMAIN}" \
        --data-urlencode "status=active" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" 2>/dev/null || true)"

    local zone_id
    zone_id="$(printf '%s' "${zone_resp}" | jq -r '.result[0].id // empty' 2>/dev/null || true)"
    if [[ -z "${zone_id}" ]]; then
        log_error "update.log" "Не удалось получить Zone ID для ${ROOT_DOMAIN} через Cloudflare API. Проверьте права токена."
        return 1
    fi

    upsert_cf_record() {
        local rec_type="$1"
        local rec_name="$2"
        local rec_content="$3"
        local create_if_missing="$4"

        local search_resp
        search_resp="$(curl -fsSL --retry 3 --connect-timeout 10 -G \
            "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" \
            --data-urlencode "type=${rec_type}" \
            --data-urlencode "name=${rec_name}" \
            -H "Authorization: Bearer ${CF_API_TOKEN}" \
            -H "Content-Type: application/json" 2>/dev/null || true)"

        local rec_id
        rec_id="$(printf '%s' "${search_resp}" | jq -r '.result[0].id // empty' 2>/dev/null || true)"

        local payload
        payload="$(jq -n \
            --arg t "${rec_type}" \
            --arg n "${rec_name}" \
            --arg c "${rec_content}" \
            '{type: $t, name: $n, content: $c, ttl: 120, proxied: false}')"

        if [[ -n "${rec_id}" ]]; then
            local put_resp
            put_resp="$(curl -fsSL --retry 3 --connect-timeout 10 -X PUT \
                "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${rec_id}" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" \
                -H "Content-Type: application/json" \
                --data "${payload}" 2>/dev/null || true)"
            if [[ "$(printf '%s' "${put_resp}" | jq -r '.success // false')" == "true" ]]; then
                log_info "update.log" "Cloudflare DNS: обновлена запись ${rec_type} ${rec_name} -> ${rec_content} (DNS Only / proxied=false)."
            else
                log_error "update.log" "Cloudflare DNS: ошибка обновления ${rec_type} ${rec_name}."
                return 1
            fi
        elif [[ "${create_if_missing}" == "true" ]]; then
            local post_resp
            post_resp="$(curl -fsSL --retry 3 --connect-timeout 10 -X POST \
                "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" \
                -H "Content-Type: application/json" \
                --data "${payload}" 2>/dev/null || true)"
            if [[ "$(printf '%s' "${post_resp}" | jq -r '.success // false')" == "true" ]]; then
                log_info "update.log" "Cloudflare DNS: создана запись ${rec_type} ${rec_name} -> ${rec_content} (DNS Only / proxied=false)."
            else
                log_error "update.log" "Cloudflare DNS: ошибка создания ${rec_type} ${rec_name}."
                return 1
            fi
        fi
    }

    delete_cf_record_if_exists() {
        local rec_type="$1"
        local rec_name="$2"
        local search_resp
        search_resp="$(curl -fsSL --retry 3 --connect-timeout 10 -G \
            "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" \
            --data-urlencode "type=${rec_type}" \
            --data-urlencode "name=${rec_name}" \
            -H "Authorization: Bearer ${CF_API_TOKEN}" \
            -H "Content-Type: application/json" 2>/dev/null || true)"

        local rec_ids
        rec_ids="$(printf '%s' "${search_resp}" | jq -r '.result[]?.id // empty' 2>/dev/null || true)"
        for rid in ${rec_ids}; do
            curl -fsSL --retry 2 --connect-timeout 10 -X DELETE \
                "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${rid}" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" \
                -H "Content-Type: application/json" >/dev/null 2>&1 || true
            log_info "update.log" "Cloudflare DNS: удалена неактуальная запись ${rec_type} для ${rec_name} (ID: ${rid})."
        done
    }

    upsert_cf_record "A" "${ROOT_DOMAIN}" "${new_ipv4}" "true"
    upsert_cf_record "A" "*.${ROOT_DOMAIN}" "${new_ipv4}" "true"
    upsert_cf_record "A" "${DOT_HOST}" "${new_ipv4}" "false"

    if [[ -n "${new_ipv6}" ]]; then
        upsert_cf_record "AAAA" "${ROOT_DOMAIN}" "${new_ipv6}" "false"
        upsert_cf_record "AAAA" "*.${ROOT_DOMAIN}" "${new_ipv6}" "false"
        upsert_cf_record "AAAA" "${DOT_HOST}" "${new_ipv6}" "false"
    else
        delete_cf_record_if_exists "AAAA" "${ROOT_DOMAIN}"
        delete_cf_record_if_exists "AAAA" "*.${ROOT_DOMAIN}"
        delete_cf_record_if_exists "AAAA" "${DOT_HOST}"
    fi
}

# ------------------------------ TLS & Cloudflare DNS-01 -----------------------
install_tls_verification_helper() {
    cat > /usr/local/bin/verify-tls-keys.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

CERT_FILE="${1:?Укажите путь к fullchain.pem}"
KEY_FILE="${2:?Укажите путь к privkey.pem}"
ROOT_DOM="${3:?Укажите ROOT_DOMAIN}"

if [[ ! -s "${CERT_FILE}" || ! -s "${KEY_FILE}" ]]; then
    echo "ОШИБКА: Файлы сертификата или ключа отсутствуют или пусты." >&2
    exit 1
fi

CERT_PUB_HASH="$(openssl x509 -in "${CERT_FILE}" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')"
KEY_PUB_HASH="$(openssl pkey -in "${KEY_FILE}" -pubout -outform DER | sha256sum | awk '{print $1}')"

if [[ -z "${CERT_PUB_HASH}" || "${CERT_PUB_HASH}" != "${KEY_PUB_HASH}" ]]; then
    echo "КРИТИЧЕСКАЯ ОШИБКА: Несовпадение SHA-256 публичных ключей fullchain.pem (${CERT_PUB_HASH}) и privkey.pem (${KEY_PUB_HASH})!" >&2
    exit 1
fi

if ! openssl x509 -in "${CERT_FILE}" -noout -checkend 86400 >/dev/null 2>&1; then
    echo "ОШИБКА: Срок действия сертификата истёк или истекает менее чем через 24 часа." >&2
    exit 1
fi

SAN_TEXT="$(openssl x509 -in "${CERT_FILE}" -noout -ext subjectAltName)"
if ! grep -Fq "DNS:${ROOT_DOM}" <<<"${SAN_TEXT}" || ! grep -Fq "DNS:*.${ROOT_DOM}" <<<"${SAN_TEXT}"; then
    echo "ОШИБКА: Сертификат не содержит обязательные SAN: ${ROOT_DOM} и *.${ROOT_DOM}." >&2
    exit 1
fi

DNS_COUNT="$(grep -o 'DNS:' <<<"${SAN_TEXT}" | wc -l)"
if [[ "${DNS_COUNT}" -ne 2 ]]; then
    echo "ОШИБКА: Сертификат содержит лишние SAN записи (ожидалось строго 2: ${ROOT_DOM} и *.${ROOT_DOM}, найдено: ${DNS_COUNT})." >&2
    exit 1
fi

echo "OK: Сертификат и ключ прошли криптографическую проверку (SHA-256 PubKey DER: ${CERT_PUB_HASH})."
EOF
    chmod 0755 /usr/local/bin/verify-tls-keys.sh
}

issue_wildcard_certificate() {
    install_tls_verification_helper
    log_info "certificate.log" "Проверка наличия ранее выпущенного wildcard TLS-сертификата для ${ROOT_DOMAIN}..."

    cat > /usr/local/bin/smartdns-cert-deploy.sh <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
if /usr/local/bin/verify-tls-keys.sh "${CERT_DIR}/fullchain.pem" "${CERT_DIR}/privkey.pem" "${ROOT_DOMAIN}"; then
    chown root:ssl-smartdns "${CERT_DIR}/fullchain.pem" "${CERT_DIR}/privkey.pem"
    chmod 0644 "${CERT_DIR}/fullchain.pem"
    chmod 0640 "${CERT_DIR}/privkey.pem"
    nginx -t && systemctl reload nginx
fi
EOF
    chmod 0750 /usr/local/bin/smartdns-cert-deploy.sh

    if [[ -s "${CERT_DIR}/fullchain.pem" && -s "${CERT_DIR}/privkey.pem" ]]; then
        if /usr/local/bin/verify-tls-keys.sh "${CERT_DIR}/fullchain.pem" "${CERT_DIR}/privkey.pem" "${ROOT_DOMAIN}" >> "${LOG_DIR}/certificate.log" 2>&1; then
            chown root:ssl-smartdns "${CERT_DIR}/fullchain.pem" "${CERT_DIR}/privkey.pem"
            chmod 0644 "${CERT_DIR}/fullchain.pem"
            chmod 0640 "${CERT_DIR}/privkey.pem"
            log_info "certificate.log" "Найден действующий проверенный сертификат в ${CERT_DIR}. Повторный выпуск не требуется."
            return 0
        fi
    fi

    local acme_ecc_dir="/root/.acme.sh/${ROOT_DOMAIN}_ecc"
    if [[ -s "${acme_ecc_dir}/fullchain.cer" && -s "${acme_ecc_dir}/${ROOT_DOMAIN}.key" ]]; then
        if /usr/local/bin/verify-tls-keys.sh "${acme_ecc_dir}/fullchain.cer" "${acme_ecc_dir}/${ROOT_DOMAIN}.key" "${ROOT_DOMAIN}" >> "${LOG_DIR}/certificate.log" 2>&1; then
            install -m 0644 -o root -g ssl-smartdns "${acme_ecc_dir}/fullchain.cer" "${CERT_DIR}/fullchain.pem.new"
            install -m 0640 -o root -g ssl-smartdns "${acme_ecc_dir}/${ROOT_DOMAIN}.key" "${CERT_DIR}/privkey.pem.new"
            mv -f "${CERT_DIR}/fullchain.pem.new" "${CERT_DIR}/fullchain.pem"
            mv -f "${CERT_DIR}/privkey.pem.new" "${CERT_DIR}/privkey.pem"
            log_info "certificate.log" "Восстановлен ранее выпущенный валидный сертификат из ${acme_ecc_dir} без обращения к Let's Encrypt."
            return 0
        fi
    fi

    log_info "certificate.log" "Действующий сертификат не найден. Подготовка выпуска через Cloudflare DNS-01..."

    if [[ ! -x /root/.acme.sh/acme.sh ]]; then
        local tmp_acme
        tmp_acme="$(mktemp -d /tmp/acme-install.XXXXXX)"
        local git_tar_url="https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz"
        curl -fsSL --retry 3 -o "${tmp_acme}/acme.tar.gz" "${git_tar_url}"
        tar -xzf "${tmp_acme}/acme.tar.gz" -C "${tmp_acme}"
        pushd "${tmp_acme}"/acme.sh-* >/dev/null
        ./acme.sh --install --home /root/.acme.sh --accountemail "${ACME_EMAIL}" --nocron >/dev/null
        popd >/dev/null
        rm -rf "${tmp_acme}"
    fi

    local stage_dir
    stage_dir="$(mktemp -d /tmp/cert-stage.XXXXXX)"
    chmod 0700 "${stage_dir}"

    export CF_Token="${CF_API_TOKEN}"
    /root/.acme.sh/acme.sh --home /root/.acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

    log_info "certificate.log" "Запрос сертификата для SAN: ${ROOT_DOMAIN} и *.${ROOT_DOMAIN}..."
    if ! /root/.acme.sh/acme.sh --home /root/.acme.sh --issue --dns dns_cf \
        -d "${ROOT_DOMAIN}" -d "*.${ROOT_DOMAIN}" --keylength ec-256 >> "${LOG_DIR}/certificate.log" 2>&1; then
        unset CF_Token
        rm -rf "${stage_dir}"
        log_error "certificate.log" "Не удалось выпустить сертификат через Cloudflare DNS-01. Старые сертификаты сохранены."
        exit 1
    fi
    unset CF_Token

    /root/.acme.sh/acme.sh --home /root/.acme.sh --install-cert -d "${ROOT_DOMAIN}" --ecc \
        --fullchain-file "${stage_dir}/fullchain.pem" \
        --key-file "${stage_dir}/privkey.pem" >/dev/null 2>&1

    if ! /usr/local/bin/verify-tls-keys.sh "${stage_dir}/fullchain.pem" "${stage_dir}/privkey.pem" "${ROOT_DOMAIN}" >> "${LOG_DIR}/certificate.log" 2>&1; then
        rm -rf "${stage_dir}"
        log_error "certificate.log" "Проверка ключей нового сертификата не пройдена! Отмена установки сертификата."
        exit 1
    fi

    install -m 0644 -o root -g ssl-smartdns "${stage_dir}/fullchain.pem" "${CERT_DIR}/fullchain.pem.new"
    install -m 0640 -o root -g ssl-smartdns "${stage_dir}/privkey.pem" "${CERT_DIR}/privkey.pem.new"
    mv -f "${CERT_DIR}/fullchain.pem.new" "${CERT_DIR}/fullchain.pem"
    mv -f "${CERT_DIR}/privkey.pem.new" "${CERT_DIR}/privkey.pem"
    rm -rf "${stage_dir}"

    log_info "certificate.log" "Сертификат для ${ROOT_DOMAIN} и *.${ROOT_DOMAIN} успешно проверен и установлен."
}

# ------------------------------ GeoHideDNS & Geosite --------------------------
install_domain_update_scripts() {
    log_info "dns.log" "Создание скриптов обновления geosite.dat и GeoHideDNS..."

    cat > /usr/local/bin/update-geosite.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

exec 9>/run/lock/update-geosite.lock
if ! flock -n 9; then
    exit 0
fi

# shellcheck disable=SC1091
source /var/lib/oxidns-installer/settings
LOG_FILE="/var/log/oxidns-installer/update.log"
TMP_DAT="/var/lib/dns-assets/geosite.dat.download"
FINAL_DAT="/var/lib/dns-assets/geosite.dat"

log() {
    printf '[%s] [GEOSITE] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$*" >> "${LOG_FILE}"
}

log "Начало загрузки свежего geosite.dat..."
if ! curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
    -o "${TMP_DAT}" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"; then
    rm -f "${TMP_DAT}"
    log "ОШИБКА: Не удалось скачать geosite.dat. Сохранена предыдущая версия."
    exit 1
fi

FILE_SIZE="$(stat -c%s "${TMP_DAT}" 2>/dev/null || echo 0)"
if [[ "${FILE_SIZE}" -lt 100000 ]]; then
    rm -f "${TMP_DAT}"
    log "ОШИБКА: Размер geosite.dat подозрительно мал (${FILE_SIZE} байт). Отмена обновления."
    exit 1
fi

chown "${DNS_USER}:xray" "${TMP_DAT}"
chmod 0640 "${TMP_DAT}"
mv -f "${TMP_DAT}" "${FINAL_DAT}"
log "Файл geosite.dat успешно обновлён (${FILE_SIZE} байт)."

if [[ "${DNS_ENGINE}" == "oxidns" ]] && systemctl is-active --quiet oxidns; then
    systemctl reload-or-restart oxidns
    log "Выполнена перезагрузка провайдера OxiDNS."
fi
EOF
    chmod 0755 /usr/local/bin/update-geosite.sh

    cat > /usr/local/bin/update-geohide-domains.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

exec 9>/run/lock/update-geohide-domains.lock
if ! flock -n 9; then
    echo "Обновление GeoHideDNS уже выполняется." >&2
    exit 0
fi

# shellcheck disable=SC1091
source /var/lib/oxidns-installer/settings
# shellcheck disable=SC1091
source /var/lib/dns-assets/xray-routing-vars.env

LOG_FILE="/var/log/oxidns-installer/update.log"
ASSETS_DIR="/var/lib/dns-assets"
RAW_URL="https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts"

TMP_DOWNLOAD="${ASSETS_DIR}/hosts.download"
TMP_DOMAINS="${ASSETS_DIR}/geohide-domains.new"
FINAL_DOMAINS="${ASSETS_DIR}/geohide-domains.txt"
AGH_RULES_NEW="${ASSETS_DIR}/ag-smartdns-rules.new"
AGH_RULES_FINAL="${ASSETS_DIR}/ag-smartdns-rules.txt"
XRAY_JSON_NEW="/etc/xray/rules.d/10-smartdns-routing.json.new"
XRAY_JSON_FINAL="/etc/xray/rules.d/10-smartdns-routing.json"
STATS_FILE="/var/lib/oxidns-installer/geohide-stats.env"

log() {
    printf '[%s] [GEOHIDE] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$*" >> "${LOG_FILE}"
}

cleanup_tmp() {
    rm -f "${TMP_DOWNLOAD}" "${TMP_DOMAINS}" "${AGH_RULES_NEW}" "${XRAY_JSON_NEW}" "${ASSETS_DIR}/geohide-hosts.txt.new"
}
trap cleanup_tmp EXIT

log "Загрузка исходного списка GeoHideDNS из ${RAW_URL}..."
HTTP_CODE="$(curl -sSL --retry 3 --connect-timeout 15 --max-time 60 -w '%{http_code}' -o "${TMP_DOWNLOAD}" "${RAW_URL}" || echo "000")"
if [[ "${HTTP_CODE}" != "200" || ! -s "${TMP_DOWNLOAD}" ]]; then
    log "ОШИБКА: Код ответа HTTP=${HTTP_CODE} или пустой файл. Рабочая конфигурация не изменена."
    exit 1
fi

awk '
    sub(/\r$/, "") {}
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
        if ($1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || $1 ~ /:/) {
            for (i=2; i<=NF; i++) {
                if ($i ~ /^#/) break
                print tolower($i)
            }
        } else {
            print tolower($1)
        }
    }
' "${TMP_DOWNLOAD}" | sed -e 's/^\*\.//' -e 's/^\.//' | grep -E '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' | sort -u > "${TMP_DOMAINS}.raw"

RAW_COUNT="$(wc -l < "${TMP_DOMAINS}.raw" | tr -d ' ')"
if [[ "${RAW_COUNT}" -lt 10 ]]; then
    log "ОШИБКА: Слишком мало валидных доменов в загруженном файле (${RAW_COUNT}). Отмена обновления."
    rm -f "${TMP_DOMAINS}.raw"
    exit 1
fi

if [[ "${EXCLUDE_GOOGLE_SYS}" == "N" ]]; then
    cat >> "${TMP_DOMAINS}.raw" <<'GDOMS'
apis.google.com
suggestqueries.google.com
clients6.google.com
clients.google.com
withgoogle.com
o.pki.goog
googleapis.com
generativelanguage.googleapis.com
GDOMS
fi

if [[ "${INCLUDE_XBOX_IPIFY}" == "y" ]]; then
    cat >> "${TMP_DOMAINS}.raw" <<'XDOMS'
xboxlive.com
xbox.com
sfx.ms
msgamestudios.com
XDOMS
fi

if [[ -s "${ASSETS_DIR}/custom-allow.txt" ]]; then
    grep -E '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' "${ASSETS_DIR}/custom-allow.txt" >> "${TMP_DOMAINS}.raw" || true
fi

awk -v excl_google="${EXCLUDE_GOOGLE_SYS}" -v incl_xbox="${INCLUDE_XBOX_IPIFY}" '
    $0 == "generativelanguage.googleapis.com" { print; next }

    # Unconditional exclusions (x.com, meta.ai + Wi-Fi Captive Portal detection domains)
    $0 == "x.com" || $0 ~ /\.x\.com$/ { next }
    $0 == "meta.ai" || $0 ~ /\.meta\.ai$/ { next }
    $0 == "connectivitycheck.gstatic.com" || $0 == "connectivitycheck.android.com" { next }
    $0 ~ /^clients[0-9]*\.google\.com$/ { next }
    $0 == "captive.apple.com" || $0 == "connect.rom.miui.com" { next }
    $0 == "msftconnecttest.com" || $0 ~ /\.msftconnecttest\.com$/ { next }
    $0 == "msftncsi.com" || $0 ~ /\.msftncsi\.com$/ { next }

    excl_google == "y" && ( \
        $0 == "apis.google.com" || \
        $0 == "suggestqueries.google.com" || \
        $0 == "o.pki.goog" || \
        $0 == "clients6.google.com" || $0 ~ /\.clients6\.google\.com$/ || \
        $0 == "clients.google.com" || $0 ~ /\.clients\.google\.com$/ || \
        $0 == "withgoogle.com" || $0 ~ /\.withgoogle\.com$/ || \
        $0 == "googleapis.com" || $0 ~ /\.googleapis\.com$/ \
    ) { next }

    incl_xbox == "N" && ( \
        $0 == "xboxlive.com" || $0 ~ /\.xboxlive\.com$/ || \
        $0 == "xbox.com" || $0 ~ /\.xbox\.com$/ \
    ) { next }

    { print }
' "${TMP_DOMAINS}.raw" > "${TMP_DOMAINS}.filtered"

printf 'generativelanguage.googleapis.com\n' >> "${TMP_DOMAINS}.filtered"

if [[ -s "${ASSETS_DIR}/custom-deny.txt" ]]; then
    grep -vFf "${ASSETS_DIR}/custom-deny.txt" "${TMP_DOMAINS}.filtered" | sort -u > "${TMP_DOMAINS}"
else
    sort -u "${TMP_DOMAINS}.filtered" > "${TMP_DOMAINS}"
fi
rm -f "${TMP_DOMAINS}.raw" "${TMP_DOMAINS}.filtered"

FINAL_COUNT="$(wc -l < "${TMP_DOMAINS}" | tr -d ' ')"
if [[ "${FINAL_COUNT}" -lt 5 ]]; then
    log "ОШИБКА: Итоговый список доменов пуст или повреждён (${FINAL_COUNT})."
    exit 1
fi

jq -Rn --arg root_dom "${ROOT_DOMAIN}" --arg dot_dom "${DOT_HOST}" \
       --arg srv_ip4 "${SERVER_IPV4}" --arg srv_ip6 "${SERVER_IPV6:-::1}" '
  [inputs | select(length > 0) | "domain:" + .] as $allowed |
  {
    "routing": {
      "domainStrategy": "AsIs",
      "rules": [
        {
          "type": "field",
          "inboundTag": ["dot-in"],
          "domain": ["full:" + $dot_dom],
          "outboundTag": "dot-backend"
        },
        {
          "type": "field",
          "inboundTag": ["dot-in"],
          "port": "0-65535",
          "outboundTag": "block"
        },
        {
          "type": "field",
          "inboundTag": ["https-in"],
          "domain": [
            "full:" + $root_dom,
            "full:www." + $root_dom,
            "full:" + $dot_dom
          ],
          "outboundTag": "nginx-local"
        },
        {
          "type": "field",
          "inboundTag": ["https-in"],
          "domain": $allowed,
          "outboundTag": "direct-v4"
        },
        {
          "type": "field",
          "inboundTag": ["https-in"],
          "ip": (
            [
              $srv_ip4,
              "127.0.0.0/8",
              "10.0.0.0/8",
              "172.16.0.0/12",
              "192.168.0.0/16",
              "100.64.0.0/10",
              "169.254.0.0/16",
              "::1/128",
              "fc00::/7",
              "fe80::/10"
            ] + (if ($srv_ip6 != "" and $srv_ip6 != "::1") then [$srv_ip6] else [] end)
          ),
          "outboundTag": "block"
        },
        {
          "type": "field",
          "inboundTag": ["https-in"],
          "port": "0-65535",
          "outboundTag": "nginx-local"
        }
      ]
    }
  }
' < "${TMP_DOMAINS}" > "${XRAY_JSON_NEW}"

TEST_DIR="$(mktemp -d /tmp/xray-validate.XXXXXX)"
cp -a /etc/xray/conf.d/00-base.json "${TEST_DIR}/00-base.json"
cp -a "${XRAY_JSON_NEW}" "${TEST_DIR}/10-smartdns-routing.json"
chmod -R 0755 "${TEST_DIR}"

if ! /usr/local/bin/xray run -test -confdir "${TEST_DIR}" >> "${LOG_FILE}" 2>&1; then
    rm -rf "${TEST_DIR}"
    log "КРИТИЧЕСКАЯ ОШИБКА: Сгенерированный 10-smartdns-routing.json не прошёл проверку xray run -test! Отказ от применения."
    exit 1
fi
rm -rf "${TEST_DIR}"

awk -v ip="${SERVER_IPV4}" 'NF > 0 {print "domain:" $1, ip}' "${TMP_DOMAINS}" > "${ASSETS_DIR}/geohide-hosts.txt.new"
chown "${DNS_USER}:xray" "${ASSETS_DIR}/geohide-hosts.txt.new"
chmod 0640 "${ASSETS_DIR}/geohide-hosts.txt.new"
mv -f "${ASSETS_DIR}/geohide-hosts.txt.new" "${ASSETS_DIR}/geohide-hosts.txt"

awk -v ip="${SERVER_IPV4}" 'NF > 0 {
    printf "||%s^$dnstype=A,dnsrewrite=NOERROR;A;%s\n", $0, ip
    printf "||%s^$dnstype=AAAA,dnsrewrite=NOERROR\n", $0
    printf "||%s^$dnstype=HTTPS|SVCB,dnsrewrite=NOERROR\n", $0
}' "${TMP_DOMAINS}" > "${AGH_RULES_NEW}"
chown "${DNS_USER}:xray" "${AGH_RULES_NEW}"
chmod 0640 "${AGH_RULES_NEW}"
mv -f "${AGH_RULES_NEW}" "${AGH_RULES_FINAL}"

chown "${DNS_USER}:xray" "${TMP_DOMAINS}" "${XRAY_JSON_NEW}"
chmod 0640 "${TMP_DOMAINS}" "${XRAY_JSON_NEW}"
mv -f "${TMP_DOMAINS}" "${FINAL_DOMAINS}"
mv -f "${XRAY_JSON_NEW}" "${XRAY_JSON_FINAL}"
ln -sf "${XRAY_JSON_FINAL}" /etc/xray/conf.d/10-smartdns-routing.json

cat > "${STATS_FILE}.tmp" <<STATS
LAST_UPDATE="$(date -Is)"
RAW_DOMAIN_COUNT="${RAW_COUNT}"
FINAL_DOMAIN_COUNT="${FINAL_COUNT}"
XRAY_RULES_STATUS="VERIFIED_OK"
STATS
mv -f "${STATS_FILE}.tmp" "${STATS_FILE}"

if systemctl is-active --quiet "${DNS_ENGINE}"; then
    systemctl reload-or-restart "${DNS_ENGINE}" || true
fi

log "Обновление успешно завершено: исходных=${RAW_COUNT}, итоговых=${FINAL_COUNT}."
EOF
    chmod 0755 /usr/local/bin/update-geohide-domains.sh
}

# ------------------------------ DNS Engine Adapters ---------------------------
render_dns_domain_lists_from_cache() {
    if [[ ! -s "${GEOHIDE_LIST_FILE}" ]]; then
        /usr/local/bin/update-geohide-domains.sh
        return 0
    fi

    awk -v ip="${SERVER_IPV4}" 'NF > 0 {print "domain:" $1, ip}' "${GEOHIDE_LIST_FILE}" > "${GEOHIDE_HOSTS_FILE}.new"
    chown "${DNS_USER}:xray" "${GEOHIDE_HOSTS_FILE}.new"
    chmod 0640 "${GEOHIDE_HOSTS_FILE}.new"
    mv -f "${GEOHIDE_HOSTS_FILE}.new" "${GEOHIDE_HOSTS_FILE}"

    awk -v ip="${SERVER_IPV4}" 'NF > 0 {
        printf "||%s^$dnstype=A,dnsrewrite=NOERROR;A;%s\n", $0, ip
        printf "||%s^$dnstype=AAAA,dnsrewrite=NOERROR\n", $0
        printf "||%s^$dnstype=HTTPS|SVCB,dnsrewrite=NOERROR\n", $0
    }' "${GEOHIDE_LIST_FILE}" > "${AGH_RULES_FILE}.new"
    chown "${DNS_USER}:xray" "${AGH_RULES_FILE}.new"
    chmod 0640 "${AGH_RULES_FILE}.new"
    mv -f "${AGH_RULES_FILE}.new" "${AGH_RULES_FILE}"
}

configure_dns_engine() {
    if [[ "${DNS_ENGINE}" == "oxidns" ]]; then
        log_info "dns.log" "Формирование и проверка конфигурации OxiDNS (/etc/oxidns/config.yaml)..."
        install -d -m 0750 -o oxidns -g oxidns /var/lib/oxidns

        render_dns_domain_lists_from_cache

        cat > /etc/oxidns/config.yaml.tmp <<EOF
log:
  level: info

plugins:
  - tag: ads_domains
    type: geosite
    args:
      file: "/var/lib/dns-assets/geosite.dat"
      selectors:
        - "category-ads-all"

  - tag: proxied_sites
    type: domain_set
    args:
      files:
        - "/var/lib/dns-assets/geohide-domains.txt"

  - tag: smart_a
    type: hosts
    args:
      files:
        - "/var/lib/dns-assets/geohide-hosts.txt"

  - tag: cache
    type: cache
    args:
      size: 4096
      short_circuit: true
      cache_negative: true

  - tag: upstream_doh
    type: forward
    args:
      upstreams:
        - addr: "https://1.1.1.1/dns-query"
        - addr: "https://8.8.8.8/dns-query"

  - tag: main
    type: sequence
    args:
      - matches: "qname \$ads_domains"
        exec: "reject 3"
      - matches:
          - "qname \$proxied_sites"
          - "qtype 64 65"
        exec: "reject 5"
      - matches:
          - "qname \$proxied_sites"
          - "qtype 1 28"
        exec: "\$smart_a"
      - matches: "has_resp"
        exec: "accept"
      - exec: "\$cache"
      - matches: "!has_resp"
        exec: "\$upstream_doh"

  - tag: udp_local
    type: udp_server
    args:
      entry: "main"
      listen: "127.0.0.1:5353"

  - tag: tcp_local
    type: tcp_server
    args:
      entry: "main"
      listen: "127.0.0.1:5353"

  - tag: doh_local
    type: http_server
    args:
      listen: "127.0.0.1:8053"
      entries:
        - path: "/dns-query"
          exec: "main"
EOF
        chown oxidns:oxidns /etc/oxidns/config.yaml.tmp
        chmod 0640 /etc/oxidns/config.yaml.tmp
        mv -f /etc/oxidns/config.yaml.tmp /etc/oxidns/config.yaml
    else
        log_info "dns.log" "Формирование конфигурации AdGuardHome (/etc/adguardhome/AdGuardHome.yaml)..."
        install -d -m 0750 -o adguard -g adguard /etc/adguardhome /var/lib/adguardhome

        render_dns_domain_lists_from_cache

        local existing_agh_user=""
        local existing_agh_pass=""
        if [[ -f "${SECRETS_FILE}" ]]; then
            existing_agh_user="$(awk -F'"' '/^AGH_ADMIN_USER=/ {print $2}' "${SECRETS_FILE}" 2>/dev/null || true)"
            existing_agh_pass="$(awk -F'"' '/^AGH_ADMIN_PASS=/ {print $2}' "${SECRETS_FILE}" 2>/dev/null || true)"
        fi

        if [[ -n "${existing_agh_user}" && -n "${existing_agh_pass}" ]]; then
            AGH_ADMIN_USER="${existing_agh_user}"
            AGH_ADMIN_PASS="${existing_agh_pass}"
        else
            AGH_ADMIN_USER="admin_$(generate_random_lower 6)"
            AGH_ADMIN_PASS="$(generate_random_alnum 24)"
            cat >> "${SECRETS_FILE}" <<EOF
AGH_PANEL_URL="http://127.0.0.1:8053 (через SSH-туннель)"
AGH_ADMIN_USER="${AGH_ADMIN_USER}"
AGH_ADMIN_PASS="${AGH_ADMIN_PASS}"
EOF
        fi

        local agh_pass_hash=""
        if python3 -c "import bcrypt" >/dev/null 2>&1; then
            agh_pass_hash="$(AGH_ADMIN_PASS="${AGH_ADMIN_PASS}" python3 -c 'import bcrypt, os; print(bcrypt.hashpw(os.environ["AGH_ADMIN_PASS"].encode(), bcrypt.gensalt(rounds=10)).decode())')"
        elif command -v htpasswd >/dev/null 2>&1; then
            agh_pass_hash="$(htpasswd -nbB "" "${AGH_ADMIN_PASS}" | cut -d: -f2)"
        else
            log_error "dns.log" "Не найден модуль python3-bcrypt или утилита htpasswd для генерации хэша пароля AdGuardHome."
            exit 1
        fi

        cat > /etc/adguardhome/AdGuardHome.yaml.tmp <<EOF
http:
  address: 127.0.0.1:8053
  session_ttl: 720h
users:
  - name: "${AGH_ADMIN_USER}"
    password: "${agh_pass_hash}"
dns:
  bind_hosts:
    - 127.0.0.1
  port: 5353
  upstream_dns:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  cache_size: 4194304
  ratelimit: 0
  refuse_any: true
  serve_plain_dns: true
tls:
  enabled: false
  server_name: "${ROOT_DOMAIN}"
  port_https: 0
  port_dns_over_tls: 0
  allow_unencrypted_doh: true
filtering:
  protection_enabled: true
  filtering_enabled: true
  filters_update_interval: 24
  safe_fs_patterns:
    - /var/lib/dns-assets/*
    - /var/lib/adguardhome/*
filters:
  - enabled: true
    url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: /var/lib/dns-assets/ag-smartdns-rules.txt
    name: GeoHide SmartDNS Rules
    id: 2
schema_version: 29
EOF
        chown adguard:adguard /etc/adguardhome/AdGuardHome.yaml.tmp
        chmod 0640 /etc/adguardhome/AdGuardHome.yaml.tmp
        mv -f /etc/adguardhome/AdGuardHome.yaml.tmp /etc/adguardhome/AdGuardHome.yaml
    fi
}

# ------------------------------ Xray Configuration ----------------------------
configure_xray_base() {
    log_info "xray.log" "Формирование базовой конфигурации Xray (/etc/xray/conf.d/00-base.json) с поддержкой PROXY protocol..."
    install -d -m 0750 -o xray -g xray /var/log/xray
    touch /var/log/xray/access.log /var/log/xray/error.log
    chown xray:xray /var/log/xray/access.log /var/log/xray/error.log
    chmod 0640 /var/log/xray/access.log /var/log/xray/error.log

    cat > "${XRAY_CONF_DIR}/00-base.json.tmp" <<EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "dns": {
    "servers": [
      "https+local://1.1.1.1/dns-query",
      "https+local://8.8.8.8/dns-query"
    ],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
    {
      "tag": "https-in",
      "listen": "0.0.0.0",
      "port": 8444,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["tls"],
        "routeOnly": false
      },
      "streamSettings": {
        "sockopt": {
          "tcpKeepAliveInterval": 120,
          "tcpNoDelay": true
        }
      }
    },
    {
      "tag": "dot-in",
      "listen": "0.0.0.0",
      "port": 853,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 8853,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["tls"],
        "routeOnly": true
      },
      "streamSettings": {
        "sockopt": {
          "tcpKeepAliveInterval": 60,
          "tcpNoDelay": true
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct-v4",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4"
      },
      "streamSettings": {
        "sockopt": {
          "tcpKeepAliveInterval": 120
        }
      }
    },
    {
      "tag": "nginx-local",
      "protocol": "freedom",
      "settings": {
        "redirect": "127.0.0.1:9444",
        "proxyProtocol": 1
      }
    },
    {
      "tag": "dot-backend",
      "protocol": "freedom",
      "settings": {
        "redirect": "127.0.0.1:8853"
      }
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {}
    }
  ]
}
EOF
    chown root:xray "${XRAY_CONF_DIR}/00-base.json.tmp"
    chmod 0640 "${XRAY_CONF_DIR}/00-base.json.tmp"
    mv -f "${XRAY_CONF_DIR}/00-base.json.tmp" "${XRAY_CONF_DIR}/00-base.json"
}

# ------------------------------ Procedural Cover Site Generator ---------------
html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    s="${s//\'/&#39;}"
    printf '%s' "${s}"
}

rand_u32() {
    od -An -tu4 -N4 /dev/urandom | tr -d ' 
'
}

rand_range() {
    local min="$1"
    local max="$2"
    local span=$((max - min + 1))
    local val
    val="$(rand_u32)"
    printf '%d' $((min + (val % span)))
}

shuffle_indices() {
    local count="$1"
    local -a arr=()
    local i j tmp
    for ((i = 0; i < count; i++)); do
        arr+=("${i}")
    done
    for ((i = count - 1; i > 0; i--)); do
        j="$(rand_range 0 "${i}")"
        tmp="${arr[${i}]}"
        arr[i]="${arr[${j}]}"
        arr[j]="${tmp}"
    done
    printf '%s ' "${arr[@]}"
}

sync_cover_site_domain_metadata() {
    local target_dir="${1:-${WEB_ROOT}}"
    [[ -d "${target_dir}" ]] || return 0

    cat > "${target_dir}/robots.txt" <<EOF
User-agent: *
Allow: /
Sitemap: https://${ROOT_DOMAIN}/sitemap.xml
EOF

    cat > "${target_dir}/sitemap.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://${ROOT_DOMAIN}/</loc>
    <changefreq>monthly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>
EOF
    chmod 0644 "${target_dir}/robots.txt" "${target_dir}/sitemap.xml"
}

validate_generated_cover_site() {
    local stage_dir="$1"
    local prev_hash="${2:-}"

    for req_file in index.html 404.html favicon.svg robots.txt sitemap.xml assets/style.css assets/app.js; do
        if [[ ! -s "${stage_dir}/${req_file}" ]]; then
            log_error "installation.log" "Проверка Cover Site не пройдена: отсутствует или пуст ${req_file}."
            return 1
        fi
    done

    local html_content
    html_content="$(cat "${stage_dir}/index.html")"

    for req_tag in "<!DOCTYPE html>" "<html" "<head>" "<title>" "<body>" "<header" "<main" "<footer" "</html>"; do
        if ! grep -Fq "${req_tag}" <<<"${html_content}"; then
            log_error "installation.log" "Проверка Cover Site не пройдена: отсутствует обязательный тег ${req_tag}."
            return 1
        fi
    done

    local section_count
    section_count="$(grep -c '<section ' <<<"${html_content}" || echo 0)"
    if [[ "${section_count}" -lt 3 ]]; then
        log_error "installation.log" "Проверка Cover Site не пройдена: недостаточно секций (${section_count})."
        return 1
    fi

    # Проверка отсутствия утечек технических терминов и внутренних адресов
    if grep -Eiq '(xray|nginx|oxidns|adguard|adguardhome|telemt|smartdns|dokodemo|ipset|iptables|127\.0\.0\.1)' "${stage_dir}/index.html" "${stage_dir}/404.html" "${stage_dir}/assets/style.css" "${stage_dir}/assets/app.js"; then
        log_error "installation.log" "Проверка безопасности Cover Site не пройдена: обнаружены технические ключевые слова."
        return 1
    fi

    if [[ -n "${SERVER_IPV4:-}" ]] && grep -Fq "${SERVER_IPV4}" "${stage_dir}/index.html" "${stage_dir}/404.html"; then
        log_error "installation.log" "Проверка безопасности Cover Site не пройдена: обнаружен IPv4 сервера в HTML."
        return 1
    fi

    local new_hash
    new_hash="$(sha256sum "${stage_dir}/index.html" | awk '{print $1}')"
    if [[ -n "${prev_hash}" && "${new_hash}" == "${prev_hash}" ]]; then
        log_warn "installation.log" "Сгенерированный index.html совпал по SHA-256 с предыдущим, требуется повторная генерация."
        return 2
    fi

    return 0
}

render_procedural_cover_attempt() {
    local stage_dir="$1"
    install -d -m 0755 "${stage_dir}/assets"

    local seed_hex
    seed_hex="$(od -An -tx4 -N16 /dev/urandom | tr -d ' 
')"

    # 1. Процедурная генерация цветовой палитры (HSL) и контрастов
    local hue_base harmony_mode hue_accent hue_secondary bg_mode
    hue_base="$(rand_range 0 359)"
    harmony_mode="$(rand_range 0 3)"
    case "${harmony_mode}" in
        0) hue_accent="${hue_base}"; hue_secondary="$(((hue_base + 18) % 360))" ;;
        1) hue_accent="$(((hue_base + 150) % 360))"; hue_secondary="$(((hue_base + 210) % 360))" ;;
        2) hue_accent="$(((hue_base + 180) % 360))"; hue_secondary="$(((hue_base + 30) % 360))" ;;
        *) hue_accent="$(((hue_base + 35) % 360))"; hue_secondary="$(((hue_base + 325) % 360))" ;;
    esac

    bg_mode="$(rand_range 0 3)"
    local col_bg col_surface col_surface_alt col_text col_muted col_accent col_accent_soft col_border
    case "${bg_mode}" in
        0) # Warm editorial paper
            col_bg="hsl(${hue_base}, 18%, 96%)"
            col_surface="hsl(${hue_base}, 20%, 99%)"
            col_surface_alt="hsl(${hue_base}, 15%, 92%)"
            col_text="hsl(${hue_base}, 24%, 13%)"
            col_muted="hsl(${hue_base}, 12%, 40%)"
            col_accent="hsl(${hue_accent}, 48%, 31%)"
            col_accent_soft="hsla(${hue_accent}, 48%, 31%, 0.11)"
            col_border="hsl(${hue_base}, 14%, 84%)"
            ;;
        1) # Cool architectural stone
            col_bg="hsl(${hue_base}, 14%, 95%)"
            col_surface="#ffffff"
            col_surface_alt="hsl(${hue_base}, 16%, 90%)"
            col_text="hsl(${hue_base}, 28%, 12%)"
            col_muted="hsl(${hue_base}, 14%, 38%)"
            col_accent="hsl(${hue_accent}, 55%, 34%)"
            col_accent_soft="hsla(${hue_accent}, 55%, 34%, 0.10)"
            col_border="hsl(${hue_base}, 15%, 83%)"
            ;;
        2) # Deep Nordic slate (dark editorial theme)
            col_bg="hsl(${hue_base}, 22%, 11%)"
            col_surface="hsl(${hue_base}, 20%, 15%)"
            col_surface_alt="hsl(${hue_base}, 18%, 19%)"
            col_text="hsl(${hue_base}, 15%, 93%)"
            col_muted="hsl(${hue_base}, 10%, 68%)"
            col_accent="hsl(${hue_accent}, 68%, 62%)"
            col_accent_soft="hsla(${hue_accent}, 68%, 62%, 0.15)"
            col_border="hsl(${hue_base}, 16%, 26%)"
            ;;
        *) # High-contrast gallery white
            col_bg="#fafaf9"
            col_surface="#ffffff"
            col_surface_alt="hsl(${hue_secondary}, 22%, 94%)"
            col_text="#18181b"
            col_muted="#52525b"
            col_accent="hsl(${hue_accent}, 52%, 33%)"
            col_accent_soft="hsla(${hue_accent}, 52%, 33%, 0.10)"
            col_border="#e4e4e7"
            ;;
    esac

    # 2. Типографика, пропорции, радиусы и стилистика оформления
    local font_choice font_heading font_body
    font_choice="$(rand_range 0 3)"
    case "${font_choice}" in
        0)
            font_heading='ui-serif, Georgia, Cambria, "Times New Roman", serif'
            font_body='system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
            ;;
        1)
            font_heading='system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
            font_body='system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
            ;;
        2)
            font_heading='"Trebuchet MS", "Segoe UI", system-ui, sans-serif'
            font_body='ui-serif, Georgia, "Times New Roman", serif'
            ;;
        *)
            font_heading='system-ui, -apple-system, "Segoe UI", sans-serif'
            font_body='"Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
            ;;
    esac

    local container_w radius_px card_style hero_layout header_layout deco_type
    container_w="$(rand_range 1040 1260)"
    local -a radii=(0 3 6 10 16)
    radius_px="${radii[$(rand_range 0 4)]}"
    card_style="$(rand_range 0 3)"
    hero_layout="$(rand_range 0 2)"
    header_layout="$(rand_range 0 2)"
    deco_type="$(rand_range 0 3)"

    # 3. Комбинаторный генератор предметной области и осмысленного контента
    local -a brand_p1=("Vespera" "Krono" "Aether" "Solvik" "Lumen" "Boreal" "Tecton" "Orbis" "Halcyon" "Meridian" "Cairn" "Alba" "Norden" "Strata" "Kestrel" "Veritas")
    local -a brand_p2=("Spatial" "Form" "Civic" "Acoustic" "Material" "Urban" "Ecological" "Heritage" "Structural" "Systems" "Horizon" "Atelier" "Grid" "Field" "Timber" "Metric")
    local -a brand_p3=("Group" "Studio" "Practice" "Lab" "Associates" "Collective" "Works" "Institute" "Partners" "Bureau")

    local b1="${brand_p1[$(rand_range 0 $((${#brand_p1[@]} - 1)))]}"
    local b2="${brand_p2[$(rand_range 0 $((${#brand_p2[@]} - 1)))]}"
    local b3="${brand_p3[$(rand_range 0 $((${#brand_p3[@]} - 1)))]}"
    local brand_name="${b1} ${b2} ${b3}"
    local brand_initials="${b1:0:1}${b2:0:1}"
    local brand_slug
    brand_slug="$(printf '%s%s' "${b1,,}" "${b2,,}")"

    local domain_idx
    domain_idx="$(rand_range 0 4)"
    local site_tagline hero_title hero_lead mission_title mission_body
    local -a svc_titles=() svc_bodies=()
    local -a proj_titles=() proj_meta=() proj_bodies=()
    local -a step_titles=() step_bodies=()
    local -a faq_q=() faq_a=()

    case "${domain_idx}" in
        0) # Sustainable Architecture & Adaptive Reuse
            site_tagline="Contemporary Architecture, Mass-Timber Engineering & Adaptive Reuse"
            hero_title="Tactile Minimalism and Climate-Resilient Civic Environments"
            hero_lead="${brand_name} is an independent architectural and structural engineering practice focused on low-carbon timber construction, daylight optimization, and adaptive heritage reuse."
            mission_title="Environmental Lifecycle Approach"
            mission_body="Every commission begins with micro-climate modeling, embodied carbon budgeting, and regionally sourced structural timber, natural stone, and lime plaster."
            svc_titles=("Civic & Cultural Architecture" "Adaptive Heritage Reuse" "Passive-House Masterplanning" "Structural Timber Consulting")
            svc_bodies=(
                "Full-cycle architectural design from feasibility studies to construction administration for libraries, pavilions, and public workspaces."
                "Structural retrofitting of post-industrial brick and masonry landmarks into energy-positive cultural and educational hubs."
                "Transit-oriented neighborhood frameworks integrating geothermal storage, rainwater retention, and pedestrian greenways."
                "Cross-laminated timber span optimization, acoustic isolation detailing, and prefabricated modular assembly."
            )
            proj_titles=("Fjord Acoustic Hall" "Kallio Foundry Archive" "Linden Courtyard Housing" "Vltava Timber Footbridge")
            proj_meta=("Oslo — 2024" "Helsinki — 2025" "Copenhagen — 2025" "Prague — 2026")
            proj_bodies=(
                "Cantilevered spruce-timber chamber engineered for natural reverberation and passive coastal ventilation."
                "Transformation of a 1928 maritime workshop into a daylight-lit municipal archive and public reading room."
                "Forty-two modular cross-laminated timber residences organized around a shared geothermal winter garden."
                "Lightweight pedestrian and cycle span fabricated from locally harvested glulam beams with weathering steel joints."
            )
            step_titles=("Site & Micro-Climate Audit" "Parametric Massing & Daylight" "Material & Carbon Ledger" "Prefabricated Assembly")
            step_bodies=(
                "Topographic laser scanning, wind-rose simulation, and soil thermal conductivity testing prior to concept sketches."
                "Iterative solar-gain balancing to minimize summer cooling loads while maximizing winter passive heating."
                "Component-level lifecycle assessment verifying net-negative embodied carbon across structural assemblies."
                "Off-site CNC timber milling for quiet, rapid on-site installation with minimal neighborhood disruption."
            )
            faq_q=("How do you evaluate embodied carbon in renovation projects?" "Do you collaborate with municipal planning boards?" "What scale of commissions does the practice undertake?")
            faq_a=(
                "We perform a full cradle-to-site structural audit comparing foundation retention against new-build alternatives before finalizing schematics."
                "Yes, our urbanism team regularly prepares public-realm impact studies, daylight envelopes, and accessibility briefs for civic review."
                "Our portfolio spans bespoke cultural pavilions from 400 square meters up to multi-hectare mixed-use district masterplans."
            )
            ;;
        1) # Acoustic Engineering & Spatial Sound Design
            site_tagline="Architectural Acoustics, Electro-Acoustic Modeling & Quiet Urbanism"
            hero_title="Precision Soundscapes for Cultural and Civic Spaces"
            hero_lead="${brand_name} designs acoustic geometries, vibration-isolated structures, and calm interior environments for concert halls, museums, and modern workspaces."
            mission_title="Physics-Driven Spatial Clarity"
            mission_body="By pairing ray-tracing acoustic simulation with custom micro-perforated timber and mineral wool diffusers, we shape speech intelligibility and musical warmth."
            svc_titles=("Auditorium & Hall Acoustics" "Structural Vibration Isolation" "Workplace Soundscaping" "Environmental Noise Mapping")
            svc_bodies=(
                "3D impulse-response modeling, variable reverberation canopies, and custom reflector geometry for performance venues."
                "Floating slab engineering and elastomeric bearing specification to isolate studios from rail and street vibration."
                "Acoustic zoning, speech-privacy baffling, and reverberation control for open research laboratories and libraries."
                "Outdoor facade attenuation studies and urban sound-barrier design compliant with strict municipal decibel thresholds."
            )
            proj_titles=("Malmo Chamber Auditorium" "Bergen Maritime Museum" "Aarhus Research Atrium" "Zurich Broadcast Wing")
            proj_meta=("Malmo — 2024" "Bergen — 2025" "Aarhus — 2025" "Zurich — 2026")
            proj_bodies=(
                "Variable-volume birch acoustic panels tuned to switch seamlessly between spoken-word symposia and chamber ensembles."
                "Floating glass-and-timber exhibition galleries decoupled from adjacent harbor freight rail vibrations."
                "Suspended felt baffles and micro-slotted ash ceilings reducing ambient reverberation time to 0.45 seconds."
                "Box-in-box recording suites achieving NC-15 background noise ratings within a dense city-center building."
            )
            step_titles=("Impulse & Noise Baseline" "3D Ray-Tracing Simulation" "Prototype Panel Testing" "Commissioning & Tuning")
            step_bodies=(
                "On-site omnidirectional source measurements capturing existing reverberation decay and structural flanking paths."
                "Frequency-band wave modeling from 63 Hz to 8 kHz to eliminate flutter echoes and focal hot spots."
                "Laboratory impedance-tube verification of custom perforated wood and recycled textile absorbers."
                "Post-construction acoustic calibration with calibrated condenser arrays and final spatial tuning."
            )
            faq_q=("When should acoustic consultants join a building project?" "Can historic interiors be treated without visual alteration?" "How do you address low-frequency mechanical noise?")
            faq_a=(
                "Engaging during early massing allows room proportions to prevent standing waves naturally, reducing the need for heavy corrective absorbers."
                "We utilize micro-perforated lime plasters and concealed bass traps behind existing historic paneling to preserve visual authenticity."
                "Our mechanical engineers specify low-velocity ductwork, acoustic plenums, and spring-isolated plant rooms from day one."
            )
            ;;
        2) # Industrial Design & Sustainable Materials Lab
            site_tagline="Circular Industrial Design, Bio-Composites & Tactile Hardware"
            hero_title="Enduring Objects Engineered for Repairability and Circularity"
            hero_lead="${brand_name} develops modular furniture, architectural hardware, and bio-based material systems built for multi-decade service life and clean disassembly."
            mission_title="Mono-Material Engineering"
            mission_body="We eliminate permanent adhesives and mixed-polymer laminates in favor of mechanical fasteners, anodized aluminum, and regenerative mycelium or flax composites."
            svc_titles=("Circular Product Architecture" "Bio-Composite Formulation" "Architectural Hardware Systems" "Design for Disassembly Audits")
            svc_bodies=(
                "End-to-end industrial design of modular seating, lighting fixtures, and workspace tools with replaceable wear components."
                "Testing and tooling of compressed hemp-fiber, cork, and mineral-bound surface panels for interior fit-outs."
                "Precision-milled brass and stainless-steel door furniture, hinges, and modular shelving connectors."
                "Component teardown analysis and digital material-passport documentation for European circular procurement."
            )
            proj_titles=("Kvadrat Modular Task Lamp" "Viken Recycled Aluminium Bench" "Talinn Flax-Core Partition" "Ghent Repairable Transit Seat")
            proj_meta=("Copenhagen — 2024" "Gothenburg — 2025" "Tallinn — 2025" "Ghent — 2026")
            proj_bodies=(
                "Tool-free LED luminaire engineered with a replaceable driver cartridge and spun post-consumer aluminum shade."
                "Public seating system cast from 94% remelted marine alloy with replaceable ash timber slats."
                "Lightweight acoustic room divider pressed from regional flax fibers and natural starch binders."
                "High-durability commuter seating allowing cushion and armrest replacement in under ninety seconds."
            )
            step_titles=("Lifecycle & Use-Case Study" "Mechanical Prototyping" "Accelerated Wear Testing" "Tooling & Material Passport")
            step_bodies=(
                "Field observation of maintenance workflows and failure points across high-traffic public installations."
                "CNC aluminum and 3D-printed functional assemblies tested for ergonomics, tolerances, and repair speed."
                "100,000-cycle mechanical load and surface abrasion verification in our physical testing workshop."
                "Full bill-of-materials registry specifying alloy grades, fastener standards, and end-of-life recovery streams."
            )
            faq_q=("Do you support small-batch architectural production?" "How are bio-composites tested for fire and wear standards?" "Can existing product lines be redesigned for circularity?")
            faq_a=(
                "Yes, we maintain relationships with regional European foundries and CNC workshops capable of runs from 50 to 10,000 units."
                "All surface panels undergo accredited EN 13501 fire-reaction and Taber abrasion testing prior to commercial specification."
                "We frequently re-engineer legacy housings to replace glued joints with standardized Torx fasteners and modular sub-assemblies."
            )
            ;;
        3) # Landscape Ecology & Urban Hydrology
            site_tagline="Landscape Ecology, Sponge-City Hydrology & Botanical Restoration"
            hero_title="Restoring Urban Watersheds and Resilient Public Landscapes"
            hero_lead="${brand_name} plans bio-diverse parklands, stormwater bioswales, and coastal wetland buffers that cool dense cities and protect infrastructure."
            mission_title="Living Hydrological Infrastructure"
            mission_body="We replace impermeable concrete drainage with layered soil bio-retention, native perennial meadows, and seasonal floodable plazas."
            svc_titles=("Sponge-City Stormwater Design" "Coastal & Riparian Restoration" "Urban Heat-Island Mitigation" "Native Seed & Soil Engineering")
            svc_bodies=(
                "Detention basins, permeable stone paving, and vegetated bioswales engineered to capture 1-in-100-year cloudburst events."
                "Salt-tolerant marshland terracing and soft-edge riverbanks that stabilize shorelines while expanding bird habitats."
                "Multi-canopy street tree corridors and reflective mineral surfaces lowering peak summer temperatures by up to 4 degrees."
                "Site-specific mycorrhizal soil blending and regional wildflower meadow establishment for low-irrigation upkeep."
            )
            proj_titles=("Rotterdam Tidal Canal Park" "Uppsala Cloudburst Meadow" "Gdansk Dune Promenade" "Ljubljana Riverfront Arboretum")
            proj_meta=("Rotterdam — 2024" "Uppsala — 2025" "Gdansk — 2025" "Ljubljana — 2026")
            proj_bodies=(
                "Stepped estuarine boardwalk and reed-bed filtration gardens absorbing tidal surges along a former dockyard."
                "Six-hectare sunken botanical park storing 18,000 cubic meters of rainwater while serving as a neighborhood commons."
                "Elevated larch walkways protecting fragile Baltic coastal dunes and native marram grass ecosystems."
                "Continuous riparian forest corridor linking seven urban districts with shaded cycling paths and pollinator habitats."
            )
            step_titles=("Watershed & Soil Survey" "Hydrological Runoff Modeling" "Botanical Palette Selection" "Seasonal Stewardship Plan")
            step_bodies=(
                "Percolation bore-hole testing, groundwater mapping, and existing biodiversity inventory across the site."
                "Dynamic rainfall-runoff simulation sizing retention swales and underground cisterns for extreme weather."
                "Selection of drought-hardy, non-invasive native perennials, sedges, and deep-rooting canopy trees."
                "Three-year ecological establishment protocol guiding municipal gardeners through seasonal pruning and monitoring."
            )
            faq_q=("How quickly do constructed bioswales reach full filtration capacity?" "Are sponge-city parks safe during heavy storm events?" "How do you minimize long-term irrigation costs?")
            faq_a=(
                "Engineered sandy-loam filter media operates from day one, while root-zone microbial filtration matures over two growing seasons."
                "All floodable basins feature gentle 1:6 graded slopes, clear high-water signage, and dry upper promenades for safe public access."
                "By matching deep-rooted native species to local rainfall patterns, established landscapes require zero supplemental watering."
            )
            ;;
        *) # Museum Conservation, Archival Lighting & Exhibition Design
            site_tagline="Museum Exhibition Design, Archival Conservation & Daylight Control"
            hero_title="Preserving Cultural Artifacts Through Precision Light and Climate"
            hero_lead="${brand_name} creates micro-climate display vitrines, low-UV museum lighting systems, and clear spatial narratives for galleries and archives."
            mission_title="Conservation-First Exhibition Craft"
            mission_body="Every gallery environment balances visitor visual comfort with strict lux-hour budgets, passive humidity buffering, and non-offgassing materials."
            svc_titles=("Exhibition Spatial Architecture" "Archival Lighting & Lux Control" "Micro-Climate Vitrine Engineering" "Wayfinding & Graphic Systems")
            svc_bodies=(
                "Modular gallery walls, intuitive visitor flow planning, and tactile exhibition plinths built from archival-grade boards."
                "High-CRI tunable LED luminaires and automated skylight louvers protecting sensitive textiles and works on paper."
                "Airtight low-iron glass display cases with concealed silica-gel cassettes maintaining 50% relative humidity."
                "Bilingual typographic hierarchy, tactile bronze maps, and high-contrast signage designed for universal accessibility."
            )
            proj_titles=("Antwerp Print Cabinet" "Tartu Ethnographic Gallery" "Basel Horology Pavilion" "Trondheim Cathedral Treasury")
            proj_meta=("Antwerp — 2024" "Tartu — 2025" "Basel — 2025" "Trondheim — 2026")
            proj_bodies=(
                "North-lit study room and automated shutter system limiting cumulative annual exposure on 16th-century engravings."
                "Reconfigurable ash-and-linen gallery system hosting rotating textile and ceramic collections without construction waste."
                "Anti-reflective fiber-optic lit vitrines showcasing intricate mechanical timepieces at 50 lux with zero heat gain."
                "Passive humidity-stabilized stone vault and bronze lectern system for medieval manuscripts and liturgical metalwork."
            )
            step_titles=("Curatorial & Conservation Brief" "Lux-Hour & Climate Modeling" "Full-Scale Mockup Review" "Installation & Calibration")
            step_bodies=(
                "Cataloging object sensitivity classes, sightline requirements, and curator narrative sequences."
                "Photometric ray-tracing and air-exchange calculations ensuring zero UV exposure and stable dew points."
                "Physical 1:1 lighting and material sample testing with conservators prior to workshop fabrication."
                "White-glove installation, spectrometer color-rendering verification, and wireless data-logger handover."
            )
            faq_q=("What materials are approved for sealed archival vitrines?" "How do you combine natural daylight with sensitive artifacts?" "Can exhibition walls be reused across multiple shows?")
            faq_a=(
                "We use powder-coated aluminum, low-iron laminated glass, inert silicone gaskets, and Oddy-tested archival textiles."
                "Motorized external louvers linked to roof photosensors modulate incoming daylight while keeping gallery illumination within 50–150 lux."
                "Our bolted aluminum-frame wall modules are engineered for ten or more reconfiguration cycles with minimal surface refinishing."
            )
            ;;
    esac

    # 4. Города и контактные данные на базе ROOT_DOMAIN
    local -a cities=("Stockholm" "Copenhagen" "Oslo" "Helsinki" "Zurich" "Vienna" "Amsterdam" "Prague")
    local -a streets=("Skeppsbron 14" "Bredgade 42" "Karl Johans gate 19" "Esplanadi 31" "Limmatquai 88" "Ringstrasse 12" "Herengracht 210" "Masarykovo nabrezi 26")
    local loc_idx
    loc_idx="$(rand_range 0 $((${#cities[@]} - 1)))"
    local office_city="${cities[${loc_idx}]}"
    local office_street="${streets[${loc_idx}]}"
    local contact_email="info@${ROOT_DOMAIN}"
    local press_email="archive@${ROOT_DOMAIN}"

    # 5. Генерация уникального геометрического favicon.svg
    local svg_shape
    svg_shape="$(rand_range 0 3)"
    local svg_inner=""
    case "${svg_shape}" in
        0)
            svg_inner="<rect x=\"4\" y=\"4\" width=\"56\" height=\"56\" rx=\"${radius_px}\" fill=\"${col_accent}\"/><text x=\"32\" y=\"40\" text-anchor=\"middle\" font-family=\"sans-serif\" font-size=\"24\" font-weight=\"700\" fill=\"#ffffff\">${brand_initials}</text>"
            ;;
        1)
            svg_inner="<circle cx=\"32\" cy=\"32\" r=\"28\" fill=\"${col_accent}\"/><circle cx=\"32\" cy=\"32\" r=\"21\" fill=\"none\" stroke=\"#ffffff\" stroke-width=\"2\"/><text x=\"32\" y=\"39\" text-anchor=\"middle\" font-family=\"serif\" font-size=\"22\" font-weight=\"700\" fill=\"#ffffff\">${brand_initials}</text>"
            ;;
        2)
            svg_inner="<polygon points=\"32,3 59,18 59,46 32,61 5,46 5,18\" fill=\"${col_accent}\"/><text x=\"32\" y=\"39\" text-anchor=\"middle\" font-family=\"sans-serif\" font-size=\"21\" font-weight=\"700\" fill=\"#ffffff\">${brand_initials}</text>"
            ;;
        *)
            svg_inner="<rect x=\"4\" y=\"4\" width=\"56\" height=\"56\" rx=\"${radius_px}\" fill=\"${col_surface}\" stroke=\"${col_accent}\" stroke-width=\"4\"/><rect x=\"12\" y=\"12\" width=\"16\" height=\"16\" fill=\"${col_accent}\"/><text x=\"41\" y=\"46\" text-anchor=\"middle\" font-family=\"sans-serif\" font-size=\"20\" font-weight=\"700\" fill=\"${col_text}\">${brand_initials}</text>"
            ;;
    esac

    cat > "${stage_dir}/favicon.svg" <<EOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  ${svg_inner}
</svg>
EOF

    # 6. Генерация вариативного CSS (assets/style.css)
    local card_css=""
    case "${card_style}" in
        0) card_css="background: var(--surface); border: 1px solid var(--border); border-top: 3px solid var(--accent);" ;;
        1) card_css="background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--accent);" ;;
        2) card_css="background: var(--surface-alt); border: 1px solid transparent;" ;;
        *) card_css="background: var(--surface); border: 1px solid var(--border); box-shadow: 0 6px 22px rgba(0, 0, 0, 0.04);" ;;
    esac

    local deco_css=""
    case "${deco_type}" in
        0) deco_css="background-image: radial-gradient(var(--accent) 1px, transparent 1px); background-size: 18px 18px;" ;;
        1) deco_css="background-image: linear-gradient(to right, var(--border) 1px, transparent 1px), linear-gradient(to bottom, var(--border) 1px, transparent 1px); background-size: 28px 28px;" ;;
        2) deco_css="background: linear-gradient(135deg, var(--accent-soft) 0%, var(--surface-alt) 100%);" ;;
        *) deco_css="background: repeating-linear-gradient(-45deg, var(--surface), var(--surface) 12px, var(--surface-alt) 12px, var(--surface-alt) 24px);" ;;
    esac

    local hero_grid_css=""
    case "${hero_layout}" in
        0) hero_grid_css="grid-template-columns: 1.3fr 0.7fr;" ;;
        1) hero_grid_css="grid-template-columns: 0.75fr 1.25fr;" ;;
        *) hero_grid_css="grid-template-columns: 1fr;" ;;
    esac

    local header_css=""
    case "${header_layout}" in
        0) header_css="display: flex; justify-content: space-between; align-items: center; gap: 1.5rem;" ;;
        1) header_css="display: flex; flex-direction: column; align-items: center; text-align: center; gap: 0.9rem;" ;;
        *) header_css="display: flex; justify-content: space-between; align-items: center; border-left: 4px solid var(--accent); padding-left: 1rem;" ;;
    esac

    local grid_cols_svc grid_cols_proj
    grid_cols_svc="$(rand_range 2 4)"
    grid_cols_proj="$(rand_range 2 3)"

    cat > "${stage_dir}/assets/style.css" <<EOF
:root {
  --bg: ${col_bg};
  --surface: ${col_surface};
  --surface-alt: ${col_surface_alt};
  --text: ${col_text};
  --muted: ${col_muted};
  --accent: ${col_accent};
  --accent-soft: ${col_accent_soft};
  --border: ${col_border};
  --radius: ${radius_px}px;
  --container: ${container_w}px;
  --font-head: ${font_heading};
  --font-body: ${font_body};
}

* { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
  background-color: var(--bg);
  color: var(--text);
  font-family: var(--font-body);
  font-size: 16px;
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}

.wrap {
  max-width: var(--container);
  margin: 0 auto;
  padding: 0 1.75rem;
}

.site-header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 1.25rem 0;
}

.header-inner {
  ${header_css}
}

.brand-mark {
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
  text-decoration: none;
  color: var(--text);
  font-family: var(--font-head);
  font-weight: 700;
  font-size: 1.15rem;
  letter-spacing: 0.04em;
}

.brand-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 2.1rem;
  height: 2.1rem;
  background: var(--accent);
  color: #ffffff;
  border-radius: var(--radius);
  font-size: 0.85rem;
  font-weight: 700;
}

.nav-links {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
}

.nav-links a {
  color: var(--muted);
  text-decoration: none;
  font-size: 0.94rem;
  font-weight: 500;
  transition: color 0.18s ease;
}

.nav-links a:hover {
  color: var(--accent);
}

.hero-block {
  padding: 4.25rem 0 3.25rem;
  border-bottom: 1px solid var(--border);
}

.hero-grid {
  display: grid;
  ${hero_grid_css}
  gap: 2.5rem;
  align-items: stretch;
}

.eyebrow {
  display: inline-block;
  font-size: 0.8rem;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--accent);
  background: var(--accent-soft);
  padding: 0.28rem 0.65rem;
  border-radius: var(--radius);
  margin-bottom: 1rem;
}

.hero-title {
  font-family: var(--font-head);
  font-size: clamp(1.95rem, 3.6vw, 2.95rem);
  line-height: 1.16;
  font-weight: 700;
  margin-bottom: 1.15rem;
}

.hero-lead {
  color: var(--muted);
  font-size: 1.08rem;
  max-width: 64ch;
}

.hero-aside {
  ${card_css}
  border-radius: var(--radius);
  padding: 1.75rem;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: 1.25rem;
}

.deco-strip {
  height: 64px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  ${deco_css}
}

.content-section {
  padding: 3.5rem 0;
  border-bottom: 1px solid var(--border);
}

.section-head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-bottom: 1.85rem;
}

.section-title {
  font-family: var(--font-head);
  font-size: 1.55rem;
  font-weight: 700;
}

.section-sub {
  color: var(--muted);
  font-size: 0.92rem;
}

.grid-svc {
  display: grid;
  grid-template-columns: repeat(${grid_cols_svc}, minmax(0, 1fr));
  gap: 1.4rem;
}

.grid-proj {
  display: grid;
  grid-template-columns: repeat(${grid_cols_proj}, minmax(0, 1fr));
  gap: 1.5rem;
}

.grid-2 {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 1.5rem;
}

.card {
  ${card_css}
  border-radius: var(--radius);
  padding: 1.55rem;
}

.card-kicker {
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--accent);
  margin-bottom: 0.45rem;
}

.card h3 {
  font-family: var(--font-head);
  font-size: 1.14rem;
  margin-bottom: 0.6rem;
}

.card p {
  color: var(--muted);
  font-size: 0.94rem;
}

.faq-list {
  display: grid;
  gap: 0.85rem;
}

.faq-item {
  ${card_css}
  border-radius: var(--radius);
  padding: 1.1rem 1.35rem;
}

.faq-item summary {
  cursor: pointer;
  font-weight: 600;
  font-family: var(--font-head);
  list-style: none;
}

.faq-item summary::-webkit-details-marker { display: none; }

.faq-item p {
  margin-top: 0.75rem;
  color: var(--muted);
  font-size: 0.94rem;
}

.btn-link {
  display: inline-block;
  margin-top: 1.25rem;
  padding: 0.65rem 1.25rem;
  background: var(--accent);
  color: #ffffff;
  text-decoration: none;
  border-radius: var(--radius);
  font-size: 0.9rem;
  font-weight: 600;
}

.site-footer {
  padding: 2.5rem 0;
  color: var(--muted);
  font-size: 0.88rem;
}

.footer-inner {
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 1rem;
}

@media (max-width: 960px) {
  .hero-grid, .grid-svc, .grid-proj { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@media (max-width: 640px) {
  .hero-grid, .grid-svc, .grid-proj, .grid-2 { grid-template-columns: 1fr; }
  .header-inner { flex-direction: column; align-items: flex-start; }
}
EOF

    # 7. Минимальный прогрессивный JS (безопасный, без внешних запросов и eval)
    cat > "${stage_dir}/assets/app.js" <<'EOF'
document.addEventListener("DOMContentLoaded", function () {
  var items = document.querySelectorAll("details.faq-item");
  items.forEach(function (target) {
    target.addEventListener("toggle", function () {
      if (target.open) {
        items.forEach(function (other) {
          if (other !== target) {
            other.removeAttribute("open");
          }
        });
      }
    });
  });
});
EOF

    # 8. Алгоритмическая сборка вариативных секций и их перемешивание
    local esc_brand esc_tagline esc_hero_t esc_hero_l esc_mis_t esc_mis_b esc_city esc_street esc_email esc_press
    esc_brand="$(html_escape "${brand_name}")"
    esc_tagline="$(html_escape "${site_tagline}")"
    esc_hero_t="$(html_escape "${hero_title}")"
    esc_hero_l="$(html_escape "${hero_lead}")"
    esc_mis_t="$(html_escape "${mission_title}")"
    esc_mis_b="$(html_escape "${mission_body}")"
    esc_city="$(html_escape "${office_city}")"
    esc_street="$(html_escape "${office_street}")"
    esc_email="$(html_escape "${contact_email}")"
    esc_press="$(html_escape "${press_email}")"

    local sec_services=""
    sec_services+="<section id=\"services\" class=\"content-section\"><div class=\"wrap\">"
    sec_services+="<div class=\"section-head\"><h2 class=\"section-title\">Core Capabilities</h2><span class=\"section-sub\">Advisory &amp; Technical Disciplines</span></div>"
    sec_services+="<div class=\"grid-svc\">"
    local idx
    for idx in 0 1 2 3; do
        sec_services+="<article class=\"card\"><div class=\"card-kicker\">0$((idx + 1))</div><h3>$(html_escape "${svc_titles[${idx}]}")</h3><p>$(html_escape "${svc_bodies[${idx}]}")</p></article>"
    done
    sec_services+="</div></div></section>"

    local sec_projects=""
    sec_projects+="<section id=\"work\" class=\"content-section\"><div class=\"wrap\">"
    sec_projects+="<div class=\"section-head\"><h2 class=\"section-title\">Selected Commissions</h2><span class=\"section-sub\">Recent European Case Studies</span></div>"
    sec_projects+="<div class=\"grid-proj\">"
    local proj_limit
    proj_limit="$(rand_range 3 4)"
    for ((idx = 0; idx < proj_limit; idx++)); do
        sec_projects+="<article class=\"card\"><div class=\"card-kicker\">$(html_escape "${proj_meta[${idx}]}")</div><h3>$(html_escape "${proj_titles[${idx}]}")</h3><p>$(html_escape "${proj_bodies[${idx}]}")</p></article>"
    done
    sec_projects+="</div></div></section>"

    local sec_method=""
    sec_method+="<section id=\"methodology\" class=\"content-section\"><div class=\"wrap\">"
    sec_method+="<div class=\"section-head\"><h2 class=\"section-title\">Workflow &amp; Methodology</h2><span class=\"section-sub\">Four-Stage Delivery Framework</span></div>"
    sec_method+="<div class=\"grid-2\">"
    for idx in 0 1 2 3; do
        sec_method+="<article class=\"card\"><div class=\"card-kicker\">Phase 0$((idx + 1))</div><h3>$(html_escape "${step_titles[${idx}]}")</h3><p>$(html_escape "${step_bodies[${idx}]}")</p></article>"
    done
    sec_method+="</div></div></section>"

    local sec_faq=""
    sec_faq+="<section id=\"faq\" class=\"content-section\"><div class=\"wrap\">"
    sec_faq+="<div class=\"section-head\"><h2 class=\"section-title\">Technical &amp; Commissioning Notes</h2><span class=\"section-sub\">Frequently Asked Questions</span></div>"
    sec_faq+="<div class=\"faq-list\">"
    for idx in 0 1 2; do
        local open_attr=""
        [[ "${idx}" -eq 0 ]] && open_attr=" open"
        sec_faq+="<details class=\"faq-item\"${open_attr}><summary>$(html_escape "${faq_q[${idx}]}")</summary><p>$(html_escape "${faq_a[${idx}]}")</p></details>"
    done
    sec_faq+="</div></div></section>"

    local sec_contact=""
    sec_contact+="<section id=\"contact\" class=\"content-section\"><div class=\"wrap\">"
    sec_contact+="<div class=\"section-head\"><h2 class=\"section-title\">Office &amp; Inquiries</h2><span class=\"section-sub\">${esc_city} Practice</span></div>"
    sec_contact+="<div class=\"grid-2\">"
    sec_contact+="<div class=\"card\"><div class=\"card-kicker\">Studio Location</div><h3>${esc_city} Office</h3><p>${esc_street}, ${esc_city}<br>Monday – Friday, 09:00 – 18:00 CET</p></div>"
    sec_contact+="<div class=\"card\"><div class=\"card-kicker\">Direct Correspondence</div><h3>New Commissions &amp; Archive</h3><p>General: ${esc_email}<br>Research &amp; Press: ${esc_press}</p></div>"
    sec_contact+="</div></div></section>"

    # Перемешиваем 4 тематические секции и выбираем 3 или 4 из них + фиксируем секцию контактов
    local -a pool_sections=("${sec_services}" "${sec_projects}" "${sec_method}" "${sec_faq}")
    local -a pool_nav=("<a href=\"#services\">Capabilities</a>" "<a href=\"#work\">Commissions</a>" "<a href=\"#methodology\">Methodology</a>" "<a href=\"#faq\">Notes</a>")
    local keep_count
    keep_count="$(rand_range 3 4)"
    local shuffled_order
    shuffled_order="$(shuffle_indices 4)"

    local rendered_sections=""
    local rendered_nav=""
    local picked=0
    local s_idx
    for s_idx in ${shuffled_order}; do
        if [[ "${picked}" -lt "${keep_count}" ]]; then
            rendered_sections+="${pool_sections[${s_idx}]}"$'
'
            rendered_nav+="${pool_nav[${s_idx}]}"
            picked=$((picked + 1))
        fi
    done
    rendered_sections+="${sec_contact}"$'
'
    rendered_nav+="<a href=\"#contact\">Contact</a>"

    local hero_aside_html=""
    if [[ "${hero_layout}" -ne 2 ]]; then
        hero_aside_html="<aside class=\"hero-aside\"><div><div class=\"card-kicker\">Practice Standard</div><h3>${esc_mis_t}</h3><p>${esc_mis_b}</p></div><div class=\"deco-strip\" aria-hidden=\"true\"></div></aside>"
    fi

    cat > "${stage_dir}/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="${esc_brand} — ${esc_tagline}">
  <meta name="generator" content="procedural-static-${seed_hex:0:12}">
  <title>${esc_brand} — ${esc_tagline}</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <header class="site-header">
    <div class="wrap header-inner">
      <a href="/" class="brand-mark"><span class="brand-badge">${brand_initials}</span><span>${esc_brand}</span></a>
      <nav class="nav-links" aria-label="Primary Navigation">
        ${rendered_nav}
      </nav>
    </div>
  </header>

  <main>
    <section class="hero-block">
      <div class="wrap hero-grid">
        <div>
          <span class="eyebrow">${esc_tagline}</span>
          <h1 class="hero-title">${esc_hero_t}</h1>
          <p class="hero-lead">${esc_hero_l}</p>
        </div>
        ${hero_aside_html}
      </div>
    </section>

    ${rendered_sections}
  </main>

  <footer class="site-footer">
    <div class="wrap footer-inner">
      <span>&copy; 2026 ${esc_brand}. All rights reserved.</span>
      <span>${esc_city} &bull; ${brand_slug}</span>
    </div>
  </footer>
  <script src="/assets/app.js" defer></script>
</body>
</html>
EOF

    cat > "${stage_dir}/404.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>404 — Page Not Found | ${esc_brand}</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <header class="site-header">
    <div class="wrap header-inner">
      <a href="/" class="brand-mark"><span class="brand-badge">${brand_initials}</span><span>${esc_brand}</span></a>
      <nav class="nav-links"><a href="/">Overview</a><a href="/#contact">Contact</a></nav>
    </div>
  </header>
  <main>
    <section class="content-section">
      <div class="wrap">
        <div class="card">
          <div class="card-kicker">Error 404</div>
          <h3>Requested Archive Page Not Found</h3>
          <p>The document or project reference you followed is not available in the public index of ${esc_brand}.</p>
          <a href="/" class="btn-link">Return to Overview</a>
        </div>
      </div>
    </section>
  </main>
  <footer class="site-footer">
    <div class="wrap footer-inner"><span>&copy; 2026 ${esc_brand}.</span><span>${esc_city}</span></div>
  </footer>
</body>
</html>
EOF

    sync_cover_site_domain_metadata "${stage_dir}"
}

generate_procedural_cover_site() {
    local target_dir="${1:-${WEB_ROOT}}"
    local force_regen="${2:-0}"

    if [[ "${force_regen}" != "1" && -s "${target_dir}/index.html" && -s "${target_dir}/assets/style.css" ]]; then
        log_info "installation.log" "Существующий Cover Site обнаружен в ${target_dir}; повторная генерация пропущена для сохранения текущей страницы."
        return 0
    fi

    log_info "installation.log" "Запуск процедурной генерации уникального Cover Site в ${target_dir}..."
    local prev_hash=""
    if [[ -f "${target_dir}/index.html" ]]; then
        prev_hash="$(sha256sum "${target_dir}/index.html" | awk '{print $1}')"
    elif [[ -f "${STATE_DIR}/cover-site.sha256" ]]; then
        prev_hash="$(cat "${STATE_DIR}/cover-site.sha256" 2>/dev/null || true)"
    fi

    local stage_dir
    stage_dir="$(mktemp -d /tmp/cover-site-gen.XXXXXX)"
    chmod 0755 "${stage_dir}"

    local attempt=1
    local valid_ok=0
    while [[ "${attempt}" -le 5 ]]; do
        rm -rf "${stage_dir:?}/"*
        render_procedural_cover_attempt "${stage_dir}"
        local rc=0
        validate_generated_cover_site "${stage_dir}" "${prev_hash}" || rc=$?
        if [[ "${rc}" -eq 0 ]]; then
            valid_ok=1
            break
        fi
        attempt=$((attempt + 1))
    done

    if [[ "${valid_ok}" -ne 1 ]]; then
        rm -rf "${stage_dir}"
        log_error "installation.log" "Не удалось сгенерировать уникальный валидный Cover Site после 5 попыток."
        return 1
    fi

    install -d -m 0755 -o root -g root "${target_dir}" "${target_dir}/assets"
    chmod 0755 "${stage_dir}" "${stage_dir}/assets"
    chmod 0644 "${stage_dir}/index.html" "${stage_dir}/404.html" "${stage_dir}/favicon.svg" \
               "${stage_dir}/robots.txt" "${stage_dir}/sitemap.xml" \
               "${stage_dir}/assets/style.css" "${stage_dir}/assets/app.js"
    chown -R root:root "${stage_dir}"

    cp -a "${stage_dir}/." "${target_dir}/"
    rm -rf "${stage_dir}"

    local final_hash
    final_hash="$(sha256sum "${target_dir}/index.html" | awk '{print $1}')"
    if [[ -d "${STATE_DIR}" ]]; then
        printf '%s
' "${final_hash}" > "${STATE_DIR}/cover-site.sha256"
        chmod 0600 "${STATE_DIR}/cover-site.sha256"
    fi
    log_info "installation.log" "Уникальный Cover Site успешно сгенерирован и проверен (SHA-256 index.html: ${final_hash:0:16}...)."
}

configure_nginx() {
    log_info "installation.log" "Генерация конфигурации Nginx (9443 direct + 9444 PROXY protocol, DoH и /auth/ на ROOT_DOMAIN)..."
    install -d -m 0750 -o www-data -g adm /var/log/nginx
    touch /var/log/nginx/doh-auth.log /var/log/nginx/dot-auth.log
    chown www-data:adm /var/log/nginx/doh-auth.log /var/log/nginx/dot-auth.log
    chmod 0640 /var/log/nginx/doh-auth.log /var/log/nginx/dot-auth.log

    cat > /etc/nginx/nginx.conf.tmp <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 2048;
    multi_accept on;
}

# Internal DoT TLS terminator (receives SNI-verified stream from Xray dot-in)
stream {
    log_format dot_stream '\$time_iso8601|\$remote_addr|\$protocol|\$status|\$bytes_sent|\$bytes_received';

    server {
        listen 127.0.0.1:8853 ssl;
        ssl_certificate ${CERT_DIR}/fullchain.pem;
        ssl_certificate_key ${CERT_DIR}/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_handshake_timeout 10s;

        proxy_pass 127.0.0.1:5353;
        proxy_timeout 30s;
        proxy_connect_timeout 5s;
        access_log /var/log/nginx/dot-auth.log dot_stream;
    }
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    server_tokens off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;

    # Never log \$request_uri so secret DOH_PATH is never written to disk
    log_format doh_auth_fmt '\$time_iso8601|\$remote_addr|\$status|\$upstream_status|\$upstream_http_content_type|\$bytes_sent';
    log_format web_auth_fmt '\$time_iso8601|\$remote_addr|\$status|200|web-auth-verified|\$bytes_sent';
    log_format safe_main '\$remote_addr - [\$time_local] "\$request_method \$scheme://\$host/" \$status \$body_bytes_sent';

    access_log /var/log/nginx/access.log safe_main;
    error_log /var/log/nginx/error.log warn;

    limit_req_zone \$binary_remote_addr zone=doh_ratelimit:10m rate=200r/s;
    limit_req_zone \$binary_remote_addr zone=web_ratelimit:10m rate=30r/s;

    map "\$request_method:\$arg_dns" \$doh_get_ok {
        "~^GET:[A-Za-z0-9_=-]{12,2048}\$" 1;
        default 0;
    }

    map "\$request_method:\$content_type" \$doh_post_ok {
        "~*^POST:application/dns-message" 1;
        default 0;
    }

    map "\$doh_get_ok:\$doh_post_ok" \$doh_req_valid {
        "1:0" 1;
        "0:1" 1;
        default 0;
    }

    map "\$request_method" \$web_auth_method_ok {
        GET 1;
        HEAD 1;
        default 0;
    }

    map "\$status:\$upstream_status:\$upstream_http_content_type" \$doh_verified {
        "200:200:application/dns-message" 1;
        default 0;
    }

    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;

        location ~ ^/(generate_204|gen_204)\$ {
            return 204;
        }

        location / {
            return 301 https://\$host\$request_uri;
        }
    }

    # Unified Stealth Server: Studio Nord Website + Root Domain DoH & Web-Auth
    server {
        listen 9443 ssl default_server;
        listen [::]:9443 ssl default_server;
        listen 127.0.0.1:9444 ssl proxy_protocol default_server;
        http2 on;
        server_name ${ROOT_DOMAIN} www.${ROOT_DOMAIN} ${DOT_HOST} _;

        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;

        ssl_certificate ${CERT_DIR}/fullchain.pem;
        ssl_certificate_key ${CERT_DIR}/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;

        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header Content-Security-Policy "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'none'; object-src 'none'" always;

        root ${WEB_ROOT};
        index index.html;
        error_page 404 /404.html;

        location = /404.html {
            internal;
        }

        # Secret Browser Bookmark Endpoint for one-tap Wi-Fi IP authorization
        location = /auth/${DOH_PATH} {
            limit_req zone=web_ratelimit burst=15 nodelay;
            if (\$web_auth_method_ok = 0) {
                return 404;
            }
            default_type text/html;
            charset utf-8;
            add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
            add_header Pragma "no-cache" always;
            add_header X-Robots-Tag "noindex, nofollow" always;
            access_log /var/log/nginx/doh-auth.log web_auth_fmt;
            return 200 '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Studio Nord — Client Session Active</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><link rel="stylesheet" href="/assets/style.css"></head><body><header><div class="nav-container"><a href="/" class="brand">Studio Nord</a></div></header><section class="section"><div class="card"><h3>Client Portal / Session Synchronized</h3><p>Network endpoint <strong>\$remote_addr</strong> is verified for active workspace access (24h lease).</p><a href="/" class="btn">Return to Studio Overview</a></div></section><footer>&copy; 2026 Studio Nord Architecture AB.</footer></body></html>';
        }

        # Secret DoH Endpoint disguised inside root domain
        location = /resolve/${DOH_PATH} {
            limit_req zone=doh_ratelimit burst=300 nodelay;
            if (\$doh_req_valid = 0) {
                return 404;
            }

            proxy_http_version 1.1;
            proxy_request_buffering on;
            proxy_buffering on;
            proxy_set_header Host \$host;
            proxy_set_header Connection "";
            proxy_hide_header Server;
            proxy_hide_header X-Powered-By;
            proxy_pass http://127.0.0.1:8053/dns-query;

            access_log /var/log/nginx/doh-auth.log doh_auth_fmt if=\$doh_verified;
        }

        location / {
            limit_req zone=web_ratelimit burst=40 nodelay;
            try_files \$uri \$uri/ =404;
        }
    }
}
EOF
    mv -f /etc/nginx/nginx.conf.tmp /etc/nginx/nginx.conf
    nginx -t
}

# ------------------------------ Dynamic Allowlist Watchers --------------------
install_ipset_watchers() {
    log_info "firewall.log" "Создание служб динамической авторизации IP для DoH, Web-Auth и DoT..."

    cat > /usr/local/bin/doh-ipset-watcher.sh <<'EOF'
#!/usr/bin/env bash
set -uo pipefail

LOG_FILE="/var/log/nginx/doh-auth.log"
FIREWALL_LOG="/var/log/oxidns-installer/firewall.log"
IPSET_SAVE="/var/lib/oxidns-installer/ipset-whitelist.save"

mkdir -p "$(dirname "${LOG_FILE}")" "$(dirname "${FIREWALL_LOG}")"
touch "${LOG_FILE}" "${FIREWALL_LOG}"

declare -A LAST_SEEN
LAST_PERSIST=0

is_valid_ipv4() {
    local ip="$1"
    [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    read -r o1 o2 o3 o4 <<<"${ip}"
    [[ "${o1}" -le 255 && "${o2}" -le 255 && "${o3}" -le 255 && "${o4}" -le 255 ]]
}

is_valid_ipv6() {
    local ip="$1"
    [[ "${ip}" =~ ^[0-9a-fA-F:]+$ ]] && [[ "${ip}" == *:* ]]
}

tail -n 0 -F "${LOG_FILE}" 2>/dev/null | while IFS='|' read -r ts client_ip status up_status ctype bytes_sent; do
    [[ "${status:-}" == "200" && "${up_status:-}" == "200" ]] || continue
    [[ "${ctype:-}" == "application/dns-message" || "${ctype:-}" == "web-auth-verified" ]] || continue
    [[ "${bytes_sent:-0}" =~ ^[0-9]+$ && "${bytes_sent}" -ge 12 ]] || continue

    client_ip="${client_ip#::ffff:}"
    now="$(date +%s)"
    key="${ctype}:${client_ip}"
    prev="${LAST_SEEN[${key}]:-0}"

    if [[ "${ctype}" != "web-auth-verified" && $((now - prev)) -lt 60 ]]; then
        continue
    fi

    if is_valid_ipv4 "${client_ip}"; then
        [[ "${client_ip}" =~ ^(127\.|10\.|192\.168\.|169\.254\.) ]] && continue
        if ipset add smartdns_clients "${client_ip}" timeout 86400 -exist 2>/dev/null; then
            LAST_SEEN["${key}"]="${now}"
            if [[ "${ctype}" == "web-auth-verified" ]]; then
                ipset add dot_clients "${client_ip}" timeout 86400 -exist 2>/dev/null || true
                printf '[%s] [WEB-AUTH] Авторизован IPv4 %s через веб-закладку (TTL 86400s)\n' "$(date -Is)" "${client_ip}" >> "${FIREWALL_LOG}"
            else
                printf '[%s] [DOH-AUTH] Авторизован IPv4 %s (TTL 86400s)\n' "$(date -Is)" "${client_ip}" >> "${FIREWALL_LOG}"
            fi
        fi
    elif is_valid_ipv6 "${client_ip}"; then
        [[ "${client_ip}" == "::1" || "${client_ip}" =~ ^fe80: || "${client_ip}" =~ ^fc00: || "${client_ip}" =~ ^fd00: ]] && continue
        if ipset add smartdns_clients6 "${client_ip}" timeout 86400 -exist 2>/dev/null; then
            LAST_SEEN["${key}"]="${now}"
            if [[ "${ctype}" == "web-auth-verified" ]]; then
                ipset add dot_clients6 "${client_ip}" timeout 86400 -exist 2>/dev/null || true
                printf '[%s] [WEB-AUTH] Авторизован IPv6 %s через веб-закладку (TTL 86400s)\n' "$(date -Is)" "${client_ip}" >> "${FIREWALL_LOG}"
            else
                printf '[%s] [DOH-AUTH] Авторизован IPv6 %s (TTL 86400s)\n' "$(date -Is)" "${client_ip}" >> "${FIREWALL_LOG}"
            fi
        fi
    fi

    if [[ "${ctype}" == "web-auth-verified" || $((now - LAST_PERSIST)) -ge 30 ]]; then
        ipset save > "${IPSET_SAVE}.tmp" 2>/dev/null && mv -f "${IPSET_SAVE}.tmp" "${IPSET_SAVE}" || true
        LAST_PERSIST="${now}"
    fi
done
EOF
    chmod 0755 /usr/local/bin/doh-ipset-watcher.sh

    cat > /usr/local/bin/dot-ipset-watcher.sh <<'EOF'
#!/usr/bin/env bash
set -uo pipefail

XRAY_ACCESS_LOG="/var/log/xray/access.log"
FIREWALL_LOG="/var/log/oxidns-installer/firewall.log"
SETTINGS_FILE="/var/lib/oxidns-installer/settings"
IPSET_SAVE="/var/lib/oxidns-installer/ipset-whitelist.save"

mkdir -p "$(dirname "${XRAY_ACCESS_LOG}")" "$(dirname "${FIREWALL_LOG}")"
touch "${XRAY_ACCESS_LOG}" "${FIREWALL_LOG}"

declare -A LAST_DOT_SEEN
LAST_PERSIST=0

tail -n 0 -F "${XRAY_ACCESS_LOG}" 2>/dev/null | while IFS= read -r line; do
    [[ "${line}" == *"[dot-in -> dot-backend]"* || "${line}" == *"[dot-in >> dot-backend]"* ]] || continue

    src_token="$(awk '{for(i=1;i<=NF;i++) if($i=="from") {print $(i+1); exit}}' <<<"${line}")"
    src_token="${src_token#tcp:}"
    client_ip="${src_token%:*}"
    client_ip="${client_ip#[}"
    client_ip="${client_ip%]}"
    client_ip="${client_ip#::ffff:}"

    now="$(date +%s)"
    prev="${LAST_DOT_SEEN[${client_ip}]:-0}"
    [[ $((now - prev)) -ge 60 ]] || continue

    dot_wl_mode="shared"
    if [[ -f "${SETTINGS_FILE}" ]]; then
        dot_wl_mode="$(awk -F'"' '/^DOT_WHITELIST_MODE=/ {print $2}' "${SETTINGS_FILE}" 2>/dev/null || echo "shared")"
    fi

    if [[ "${client_ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        [[ "${client_ip}" =~ ^(127\.|10\.|192\.168\.|169\.254\.) ]] && continue
        if ipset add smartdns_clients "${client_ip}" timeout 86400 -exist 2>/dev/null; then
            LAST_DOT_SEEN["${client_ip}"]="${now}"
            if [[ "${dot_wl_mode}" == "separate" ]]; then
                ipset add dot_clients "${client_ip}" timeout 86400 -exist 2>/dev/null || true
            fi
            printf '[%s] [DOT-AUTH] Авторизован IPv4 %s через DoT (TTL 86400s, режим %s)\n' "$(date -Is)" "${client_ip}" "${dot_wl_mode}" >> "${FIREWALL_LOG}"
        fi
    elif [[ "${client_ip}" =~ ^[0-9a-fA-F:]+$ ]] && [[ "${client_ip}" == *:* ]]; then
        [[ "${client_ip}" == "::1" || "${client_ip}" =~ ^fe80: || "${client_ip}" =~ ^fc00: || "${client_ip}" =~ ^fd00: ]] && continue
        if ipset add smartdns_clients6 "${client_ip}" timeout 86400 -exist 2>/dev/null; then
            LAST_DOT_SEEN["${client_ip}"]="${now}"
            if [[ "${dot_wl_mode}" == "separate" ]]; then
                ipset add dot_clients6 "${client_ip}" timeout 86400 -exist 2>/dev/null || true
            fi
            printf '[%s] [DOT-AUTH] Авторизован IPv6 %s через DoT (TTL 86400s, режим %s)\n' "$(date -Is)" "${client_ip}" "${dot_wl_mode}" >> "${FIREWALL_LOG}"
        fi
    fi

    if [[ $((now - LAST_PERSIST)) -ge 30 ]]; then
        ipset save > "${IPSET_SAVE}.tmp" 2>/dev/null && mv -f "${IPSET_SAVE}.tmp" "${IPSET_SAVE}" || true
        LAST_PERSIST="${now}"
    fi
done
EOF
    chmod 0755 /usr/local/bin/dot-ipset-watcher.sh
}

# ------------------------------ Firewall, ipset & Sysctl ----------------------
configure_firewall_and_sysctl() {
    log_info "firewall.log" "Настройка sysctl (TCP Keepalive + MTU Probing) и межсетевого экрана (UFW + iptables + ipset)..."

    cat > /etc/sysctl.d/90-smartdns-keepalive.conf <<'EOF'
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 4
net.ipv4.tcp_mtu_probing = 1
EOF
    sysctl --system >/dev/null 2>&1 || true

    cat > /usr/local/bin/smartdns-firewall-apply.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

# shellcheck disable=SC1091
source /var/lib/oxidns-installer/settings

STATE_DIR="/var/lib/oxidns-installer"
IPSET_SAVE_FILE="${STATE_DIR}/ipset-whitelist.save"
FW_BACKUP_DIR="${STATE_DIR}/fw-backup"
mkdir -p "${FW_BACKUP_DIR}"
chmod 0700 "${FW_BACKUP_DIR}"

iptables-save > "${FW_BACKUP_DIR}/iptables.v4.bak" 2>/dev/null || true
ip6tables-save > "${FW_BACKUP_DIR}/iptables.v6.bak" 2>/dev/null || true
ipset save > "${FW_BACKUP_DIR}/ipset.bak" 2>/dev/null || true

# 1. Create or ensure ipset tables exist
ipset create smartdns_clients hash:ip family inet timeout 86400 -exist
ipset create smartdns_clients6 hash:ip family inet6 timeout 86400 -exist
ipset create dot_clients hash:ip family inet timeout 86400 -exist
ipset create dot_clients6 hash:ip family inet6 timeout 86400 -exist

if [[ -s "${IPSET_SAVE_FILE}" ]]; then
    ipset restore -! < "${IPSET_SAVE_FILE}" 2>/dev/null || true
fi

DOT_WL_ENABLED="${DOT_WHITELIST_ENABLED:-false}"
DOT_WL_MODE="${DOT_WHITELIST_MODE:-shared}"

if [[ "${DOT_WL_MODE}" == "separate" ]]; then
    DOT_SET_V4="dot_clients"
    DOT_SET_V6="dot_clients6"
else
    DOT_SET_V4="smartdns_clients"
    DOT_SET_V6="smartdns_clients6"
fi

# 2. Cleanly recreate dedicated IPv4 chains
iptables -t nat -N SMARTDNS_PREROUTING 2>/dev/null || iptables -t nat -F SMARTDNS_PREROUTING
iptables -t filter -N SMARTDNS_INPUT 2>/dev/null || iptables -t filter -F SMARTDNS_INPUT
iptables -t filter -N SMARTDNS_OUTPUT 2>/dev/null || iptables -t filter -F SMARTDNS_OUTPUT

for cidr in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 "${SERVER_IPV4}/32"; do
    iptables -t nat -A SMARTDNS_PREROUTING -s "${cidr}" -j RETURN
done

iptables -t nat -A SMARTDNS_PREROUTING -p tcp --dport 443 -m set --match-set smartdns_clients src -j REDIRECT --to-ports 8444
if [[ "${DOT_WL_MODE}" == "separate" ]]; then
    iptables -t nat -A SMARTDNS_PREROUTING -p tcp --dport 443 -m set --match-set dot_clients src -j REDIRECT --to-ports 8444
fi
iptables -t nat -A SMARTDNS_PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 9443

if ! iptables -t nat -C PREROUTING -j SMARTDNS_PREROUTING 2>/dev/null; then
    iptables -t nat -I PREROUTING 1 -j SMARTDNS_PREROUTING
fi

# INPUT Chain Protection (IPv4)
iptables -t filter -A SMARTDNS_INPUT -p tcp ! --syn -m conntrack --ctstate INVALID -j REJECT --reject-with tcp-reset
iptables -t filter -A SMARTDNS_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

if [[ "${DOT_WL_ENABLED}" == "true" ]]; then
    iptables -t filter -A SMARTDNS_INPUT -p tcp --dport 853 -m set --match-set "${DOT_SET_V4}" src \
        -m hashlimit --hashlimit-name dot_v4_rate --hashlimit-mode srcip --hashlimit-upto 30/min --hashlimit-burst 40 -j ACCEPT
    iptables -t filter -A SMARTDNS_INPUT -p tcp --dport 853 -j DROP
else
    iptables -t filter -A SMARTDNS_INPUT -p tcp --dport 853 --syn \
        -m hashlimit --hashlimit-name dot_v4_rate --hashlimit-mode srcip --hashlimit-above 30/min --hashlimit-burst 40 -j DROP
    iptables -t filter -A SMARTDNS_INPUT -p tcp --dport 853 -j ACCEPT
fi

iptables -t filter -A SMARTDNS_INPUT -i lo -j ACCEPT
iptables -t filter -A SMARTDNS_INPUT -p tcp --dport 9443 -m conntrack --ctstate DNAT --ctorigdstport 443 -j ACCEPT
iptables -t filter -A SMARTDNS_INPUT -p tcp --dport 9443 -j DROP
iptables -t filter -A SMARTDNS_INPUT -p tcp -m multiport --dports 8443,9444,8853,5353,8053,3000 -j DROP
iptables -t filter -A SMARTDNS_INPUT -p udp --dport 5353 -j DROP
iptables -t filter -A SMARTDNS_INPUT -p tcp --dport 8444 -m conntrack --ctstate DNAT --ctorigdstport 443 -m set --match-set smartdns_clients src -j ACCEPT
if [[ "${DOT_WL_MODE}" == "separate" ]]; then
    iptables -t filter -A SMARTDNS_INPUT -p tcp --dport 8444 -m conntrack --ctstate DNAT --ctorigdstport 443 -m set --match-set dot_clients src -j ACCEPT
fi
iptables -t filter -A SMARTDNS_INPUT -p tcp --dport 8444 -j DROP

if ! iptables -t filter -C INPUT -j SMARTDNS_INPUT 2>/dev/null; then
    iptables -t filter -I INPUT 1 -j SMARTDNS_INPUT
fi

# OUTPUT Chain Anti-Loop & Anti-SSRF for Xray user (allows local ports 9443, 9444, 8853)
XRAY_UID="$(id -u xray)"
iptables -t filter -A SMARTDNS_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A SMARTDNS_OUTPUT -m owner --uid-owner "${XRAY_UID}" -d 127.0.0.1/32 -p tcp -m multiport --dports 9443,9444,8853 -j ACCEPT
for cidr in "${SERVER_IPV4}/32" 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16; do
    iptables -t filter -A SMARTDNS_OUTPUT -m owner --uid-owner "${XRAY_UID}" -p tcp -d "${cidr}" -j REJECT --reject-with tcp-reset
    iptables -t filter -A SMARTDNS_OUTPUT -m owner --uid-owner "${XRAY_UID}" -d "${cidr}" -j DROP
done

if ! iptables -t filter -C OUTPUT -j SMARTDNS_OUTPUT 2>/dev/null; then
    iptables -t filter -I OUTPUT 1 -j SMARTDNS_OUTPUT
fi

# 3. IPv6 Protection
ip6tables -t nat -N SMARTDNS6_PREROUTING 2>/dev/null || ip6tables -t nat -F SMARTDNS6_PREROUTING
ip6tables -t filter -N SMARTDNS6_INPUT 2>/dev/null || ip6tables -t filter -F SMARTDNS6_INPUT
ip6tables -t filter -N SMARTDNS6_OUTPUT 2>/dev/null || ip6tables -t filter -F SMARTDNS6_OUTPUT

for cidr6 in ::1/128 fe80::/10 fc00::/7; do
    ip6tables -t nat -A SMARTDNS6_PREROUTING -s "${cidr6}" -j RETURN
done
if [[ -n "${SERVER_IPV6:-}" ]]; then
    ip6tables -t nat -A SMARTDNS6_PREROUTING -s "${SERVER_IPV6}/128" -j RETURN
fi
ip6tables -t nat -A SMARTDNS6_PREROUTING -p tcp --dport 443 -m set --match-set smartdns_clients6 src -j REDIRECT --to-ports 8444
if [[ "${DOT_WL_MODE}" == "separate" ]]; then
    ip6tables -t nat -A SMARTDNS6_PREROUTING -p tcp --dport 443 -m set --match-set dot_clients6 src -j REDIRECT --to-ports 8444
fi
ip6tables -t nat -A SMARTDNS6_PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 9443

if ! ip6tables -t nat -C PREROUTING -j SMARTDNS6_PREROUTING 2>/dev/null; then
    ip6tables -t nat -I PREROUTING 1 -j SMARTDNS6_PREROUTING
fi

ip6tables -t filter -A SMARTDNS6_INPUT -p tcp ! --syn -m conntrack --ctstate INVALID -j REJECT --reject-with tcp-reset
ip6tables -t filter -A SMARTDNS6_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

if [[ "${DOT_WL_ENABLED}" == "true" ]]; then
    ip6tables -t filter -A SMARTDNS6_INPUT -p tcp --dport 853 -m set --match-set "${DOT_SET_V6}" src \
        -m hashlimit --hashlimit-name dot_v6_rate --hashlimit-mode srcip --hashlimit-upto 30/min --hashlimit-burst 40 -j ACCEPT
    ip6tables -t filter -A SMARTDNS6_INPUT -p tcp --dport 853 -j DROP
else
    ip6tables -t filter -A SMARTDNS6_INPUT -p tcp --dport 853 --syn \
        -m hashlimit --hashlimit-name dot_v6_rate --hashlimit-mode srcip --hashlimit-above 30/min --hashlimit-burst 40 -j DROP
    ip6tables -t filter -A SMARTDNS6_INPUT -p tcp --dport 853 -j ACCEPT
fi

ip6tables -t filter -A SMARTDNS6_INPUT -i lo -j ACCEPT
ip6tables -t filter -A SMARTDNS6_INPUT -p tcp --dport 9443 -m conntrack --ctstate DNAT --ctorigdstport 443 -j ACCEPT
ip6tables -t filter -A SMARTDNS6_INPUT -p tcp --dport 9443 -j DROP
ip6tables -t filter -A SMARTDNS6_INPUT -p tcp -m multiport --dports 8443,9444,8853,5353,8053,3000 -j DROP
ip6tables -t filter -A SMARTDNS6_INPUT -p tcp --dport 8444 -m conntrack --ctstate DNAT --ctorigdstport 443 -m set --match-set smartdns_clients6 src -j ACCEPT
if [[ "${DOT_WL_MODE}" == "separate" ]]; then
    ip6tables -t filter -A SMARTDNS6_INPUT -p tcp --dport 8444 -m conntrack --ctstate DNAT --ctorigdstport 443 -m set --match-set dot_clients6 src -j ACCEPT
fi
ip6tables -t filter -A SMARTDNS6_INPUT -p tcp --dport 8444 -j DROP
ip6tables -t filter -A SMARTDNS6_INPUT -p udp --dport 5353 -j DROP

if ! ip6tables -t filter -C INPUT -j SMARTDNS6_INPUT 2>/dev/null; then
    ip6tables -t filter -I INPUT 1 -j SMARTDNS6_INPUT
fi

ip6tables -t filter -A SMARTDNS6_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for cidr6 in ::1/128 fe80::/10 fc00::/7; do
    ip6tables -t filter -A SMARTDNS6_OUTPUT -m owner --uid-owner "${XRAY_UID}" -p tcp -d "${cidr6}" -j REJECT --reject-with tcp-reset
    ip6tables -t filter -A SMARTDNS6_OUTPUT -m owner --uid-owner "${XRAY_UID}" -d "${cidr6}" -j DROP
done
if [[ -n "${SERVER_IPV6:-}" ]]; then
    ip6tables -t filter -A SMARTDNS6_OUTPUT -m owner --uid-owner "${XRAY_UID}" -p tcp -d "${SERVER_IPV6}/128" -j REJECT --reject-with tcp-reset
    ip6tables -t filter -A SMARTDNS6_OUTPUT -m owner --uid-owner "${XRAY_UID}" -d "${SERVER_IPV6}/128" -j DROP
fi
if ! ip6tables -t filter -C OUTPUT -j SMARTDNS6_OUTPUT 2>/dev/null; then
    ip6tables -t filter -I OUTPUT 1 -j SMARTDNS6_OUTPUT
fi

ipset save > "${IPSET_SAVE_FILE}.tmp" 2>/dev/null && mv -f "${IPSET_SAVE_FILE}.tmp" "${IPSET_SAVE_FILE}" || true
EOF
    chmod 0755 /usr/local/bin/smartdns-firewall-apply.sh

    local ssh_port
    ssh_port="$(ss -tlnp | awk '/sshd/ {split($4,a,":"); print a[length(a)]; exit}')"
    ssh_port="${ssh_port:-22}"

    ufw allow "${ssh_port}/tcp" comment 'SSH Access' >/dev/null
    ufw allow 80/tcp comment 'HTTP Redirect' >/dev/null
    ufw allow 443/tcp comment 'SmartDNS HTTPS / SNI Proxy' >/dev/null
    ufw allow 853/tcp comment 'SmartDNS DoT' >/dev/null
    ufw --force enable >/dev/null

    /usr/local/bin/smartdns-firewall-apply.sh
    seed_initial_admin_ip
    log_info "firewall.log" "Правила UFW, iptables (${IPTABLES_BACKEND}) и ipset успешно применены (DoT Whitelist: ${DOT_WHITELIST_ENABLED}, режим: ${DOT_WHITELIST_MODE})."
}

seed_initial_admin_ip() {
    local admin_ip=""
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        admin_ip="$(awk '{print $1}' <<<"${SSH_CLIENT}")"
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        admin_ip="$(awk '{print $1}' <<<"${SSH_CONNECTION}")"
    fi
    admin_ip="${admin_ip#::ffff:}"

    if [[ -z "${admin_ip}" ]]; then
        return 0
    fi

    if validate_single_ipv4 "${admin_ip}"; then
        if [[ ! "${admin_ip}" =~ ^(127\.|10\.|192\.168\.|169\.254\.) ]]; then
            ipset add smartdns_clients "${admin_ip}" timeout 86400 -exist
            ipset add dot_clients "${admin_ip}" timeout 86400 -exist
            persist_ipset_state
            log_info "firewall.log" "Автоматически добавлен IPv4 текущей SSH-сессии администратора (${admin_ip}) в smartdns_clients и dot_clients (TTL 86400s)."
        fi
    elif validate_single_ipv6 "${admin_ip}"; then
        if [[ "${admin_ip}" != "::1" && ! "${admin_ip}" =~ ^fe80: && ! "${admin_ip}" =~ ^fc00: && ! "${admin_ip}" =~ ^fd00: ]]; then
            ipset add smartdns_clients6 "${admin_ip}" timeout 86400 -exist
            ipset add dot_clients6 "${admin_ip}" timeout 86400 -exist
            persist_ipset_state
            log_info "firewall.log" "Автоматически добавлен IPv6 текущей SSH-сессии администратора (${admin_ip}) в smartdns_clients6 и dot_clients6 (TTL 86400s)."
        fi
    fi
}

# ------------------------------ Systemd Units ---------------------------------
write_dns_engine_systemd_unit() {
    if [[ "${DNS_ENGINE}" == "oxidns" ]]; then
        cat > /etc/systemd/system/oxidns.service <<'EOF'
[Unit]
Description=OxiDNS SmartDNS Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=oxidns
Group=oxidns
SupplementaryGroups=xray
WorkingDirectory=/var/lib/oxidns
ExecStartPre=/usr/local/bin/oxidns check -c /etc/oxidns/config.yaml -d /var/lib/oxidns
ExecStart=/usr/local/bin/oxidns start -c /etc/oxidns/config.yaml -d /var/lib/oxidns
Restart=on-failure
RestartSec=3s
TimeoutStartSec=20s
TimeoutStopSec=15s

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/var/lib/oxidns
ReadOnlyPaths=/etc/oxidns /var/lib/dns-assets

[Install]
WantedBy=multi-user.target
EOF
    else
        cat > /etc/systemd/system/adguardhome.service <<'EOF'
[Unit]
Description=AdGuardHome SmartDNS Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=adguard
Group=adguard
SupplementaryGroups=xray
WorkingDirectory=/var/lib/adguardhome
ExecStart=/usr/local/bin/AdGuardHome -c /etc/adguardhome/AdGuardHome.yaml -w /var/lib/adguardhome --no-check-update
Restart=on-failure
RestartSec=3s

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/etc/adguardhome /var/lib/adguardhome
ReadOnlyPaths=/var/lib/dns-assets

[Install]
WantedBy=multi-user.target
EOF
    fi
}

install_systemd_units() {
    log_info "installation.log" "Создание изолированных systemd units с минимальными привилегиями..."

    cat > /etc/systemd/system/smartdns-firewall.service <<'EOF'
[Unit]
Description=SmartDNS ipset and Netfilter Rules Manager
After=network-online.target ufw.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/smartdns-firewall-apply.sh
ExecStop=/bin/sh -c 'ipset save > /var/lib/oxidns-installer/ipset-whitelist.save'

[Install]
WantedBy=multi-user.target
EOF

    write_dns_engine_systemd_unit

    cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Transparent SNI Proxy Service
After=network-online.target smartdns-firewall.service
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=xray
Group=xray
ExecStartPre=/usr/local/bin/xray run -test -confdir /etc/xray/conf.d
ExecStart=/usr/local/bin/xray run -confdir /etc/xray/conf.d
Restart=on-failure
RestartSec=3s
TimeoutStartSec=20s
TimeoutStopSec=15s

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/var/log/xray
ReadOnlyPaths=/etc/xray/conf.d /etc/xray/rules.d

[Install]
WantedBy=multi-user.target
EOF

    cat > /usr/local/bin/xray-safe-reload.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

exec 9>/run/lock/xray-safe-reload.lock
if ! flock -n 9; then
    exit 0
fi

LOG_FILE="/var/log/oxidns-installer/xray.log"
BACKUP_GOOD="/var/lib/oxidns-installer/10-smartdns-routing.json.lastgood"
TARGET_JSON="/etc/xray/rules.d/10-smartdns-routing.json"

if /usr/local/bin/xray run -test -confdir /etc/xray/conf.d >> "${LOG_FILE}" 2>&1; then
    cp -a "${TARGET_JSON}" "${BACKUP_GOOD}"
    systemctl restart xray
    printf '[%s] [XRAY-RELOAD] Проверка пройдена, Xray успешно перезагружен.\n' "$(date -Is)" >> "${LOG_FILE}"
else
    printf '[%s] [XRAY-RELOAD] ОШИБКА проверки конфигурации! Восстановление предыдущего рабочего JSON.\n' "$(date -Is)" >> "${LOG_FILE}"
    if [[ -f "${BACKUP_GOOD}" ]]; then
        cp -a "${BACKUP_GOOD}" "${TARGET_JSON}"
    fi
    exit 1
fi
EOF
    chmod 0755 /usr/local/bin/xray-safe-reload.sh

    cat > /etc/systemd/system/xray-reload.path <<'EOF'
[Unit]
Description=Monitor /etc/xray/rules.d/10-smartdns-routing.json for changes

[Path]
PathChanged=/etc/xray/rules.d/10-smartdns-routing.json
Unit=xray-reload.service

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/xray-reload.service <<'EOF'
[Unit]
Description=Validated Xray Configuration Reload Service
After=xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xray-safe-reload.sh
EOF

    install -d -m 0755 /etc/systemd/system/nginx.service.d
    cat > /etc/systemd/system/nginx.service.d/hardening.conf <<'EOF'
[Service]
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
EOF

    cat > /etc/systemd/system/doh-ipset-watcher.service <<'EOF'
[Unit]
Description=SmartDNS DoH Authorization ipset Watcher
After=nginx.service smartdns-firewall.service
Requires=smartdns-firewall.service
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/doh-ipset-watcher.sh
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/dot-ipset-watcher.service <<'EOF'
[Unit]
Description=SmartDNS DoT Authorization ipset Watcher
After=xray.service nginx.service smartdns-firewall.service
Requires=smartdns-firewall.service
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/dot-ipset-watcher.sh
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/geosite-update.service <<'EOF'
[Unit]
Description=Update geosite.dat for SmartDNS
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-geosite.sh
EOF

    cat > /etc/systemd/system/geosite-update.timer <<'EOF'
[Unit]
Description=Daily geosite.dat update at 04:00 Europe/Moscow

[Timer]
OnCalendar=*-*-* 04:00:00 Europe/Moscow
Persistent=true

[Install]
WantedBy=timers.target
EOF

    cat > /etc/systemd/system/geohide-update.service <<'EOF'
[Unit]
Description=Update GeoHideDNS domains and Xray routing rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-geohide-domains.sh
EOF

    cat > /etc/systemd/system/geohide-update.timer <<'EOF'
[Unit]
Description=Daily GeoHideDNS update at 04:05 Europe/Moscow

[Timer]
OnCalendar=*-*-* 04:05:00 Europe/Moscow
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable smartdns-firewall.service "${DNS_ENGINE}.service" xray.service \
        xray-reload.path nginx.service doh-ipset-watcher.service dot-ipset-watcher.service \
        geosite-update.timer geohide-update.timer

    systemctl restart smartdns-firewall.service
    systemctl restart "${DNS_ENGINE}.service"
    systemctl restart nginx.service
    systemctl restart xray.service
    systemctl start xray-reload.path
    systemctl restart doh-ipset-watcher.service dot-ipset-watcher.service
    systemctl start geosite-update.timer geohide-update.timer

    for _ in {1..15}; do
        if ss -ulnp 2>/dev/null | grep -q ":5353 "; then
            break
        fi
        sleep 1
    done
}

# ------------------------------ Isolated Backend Verification & Switcher ------
verify_dns_backend_isolated() {
    local expected_engine="${DNS_ENGINE}"
    local other_engine="adguardhome"
    [[ "${expected_engine}" == "adguardhome" ]] && other_engine="oxidns"

    printf '==============================================================================\n'
    printf '       ИЗОЛИРОВАННОЕ ТЕСТИРОВАНИЕ DNS BACKEND: %-20s          \n' "${expected_engine}"
    printf '==============================================================================\n'

    # 1. Service state & no port conflict
    if ! systemctl is-active --quiet "${expected_engine}"; then
        log_error "dns.log" "Служба ${expected_engine} не активна!"
        return 1
    fi
    if systemctl is-active --quiet "${other_engine}" 2>/dev/null; then
        log_error "dns.log" "Конфликт: альтернативный движок ${other_engine} всё ещё активен!"
        return 1
    fi
    printf '[ PASS ] Служба %s активна, конфликт с %s отсутствует\n' "${expected_engine}" "${other_engine}"

    # 2. Listening sockets check (127.0.0.1:5353 UDP/TCP and 127.0.0.1:8053 TCP)
    if ss -ulnp | grep -q "127.0.0.1:5353 " && ss -tlnp | grep -q "127.0.0.1:5353 " && ss -tlnp | grep -q "127.0.0.1:8053 "; then
        printf '[ PASS ] Сокеты 127.0.0.1:5353 (UDP/TCP) и 127.0.0.1:8053 (TCP DoH) прослушиваются\n'
    else
        log_error "dns.log" "Не обнаружены ожидаемые сокеты 127.0.0.1:5353 / 127.0.0.1:8053 для ${expected_engine}."
        return 1
    fi

    # 3. Upstream A resolution + Cache test
    local upstream_ip
    upstream_ip="$(dig +time=4 +tries=2 +short @127.0.0.1 -p 5353 example.com A | sed -n '1p' || true)"
    if ! validate_single_ipv4 "${upstream_ip}" || [[ "${upstream_ip}" == "${SERVER_IPV4}" ]]; then
        log_error "dns.log" "Ошибка разрешения обычного домена example.com через ${expected_engine} (получено: ${upstream_ip:-пусто})."
        return 1
    fi
    local cached_ip
    cached_ip="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 5353 example.com A | sed -n '1p' || true)"
    if [[ "${cached_ip}" != "${upstream_ip}" ]]; then
        log_error "dns.log" "Ошибка повторного (кэшированного) запроса example.com."
        return 1
    fi
    printf '[ PASS ] Upstream DNS и кэш работают (example.com -> %s)\n' "${upstream_ip}"

    # 4. SmartDNS A spoofing (дожидаемся компиляции фильтров при первом запуске)
    local spoofed_ip=""
    for i in {1..15}; do
        spoofed_ip="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 5353 "probe-${i}.generativelanguage.googleapis.com" A | sed -n '1p' || true)"
        if [[ "${spoofed_ip}" == "${SERVER_IPV4}" ]]; then
            break
        fi
        sleep 1
    done
    spoofed_ip="$(dig +time=3 +tries=2 +short @127.0.0.1 -p 5353 generativelanguage.googleapis.com A | sed -n '1p' || true)"
    if [[ "${spoofed_ip}" != "${SERVER_IPV4}" ]]; then
        log_error "dns.log" "Подмена A-записи не сработала в ${expected_engine} (ожидался ${SERVER_IPV4}, получено: ${spoofed_ip:-пусто})."
        return 1
    fi
    printf '[ PASS ] Правила SmartDNS подменяют проксируемый домен на %s\n' "${SERVER_IPV4}"

    # 5. AAAA NODATA & HTTPS TYPE65
    local aaaa_resp https_resp
    aaaa_resp="$(dig +time=3 +tries=2 @127.0.0.1 -p 5353 generativelanguage.googleapis.com AAAA || true)"
    https_resp="$(dig +time=3 +tries=2 @127.0.0.1 -p 5353 generativelanguage.googleapis.com TYPE65 || true)"
    if ! grep -q "status: NOERROR" <<<"${aaaa_resp}" || ! grep -q "ANSWER: 0" <<<"${aaaa_resp}"; then
        log_error "dns.log" "Некорректный ответ AAAA для проксируемого домена в ${expected_engine}."
        return 1
    fi
    if ! grep -Eq "status: (NOERROR|REFUSED)" <<<"${https_resp}" || ! grep -q "ANSWER: 0" <<<"${https_resp}"; then
        log_error "dns.log" "Некорректный ответ HTTPS (TYPE65) для проксируемого домена в ${expected_engine}."
        return 1
    fi
    printf '[ PASS ] Ответы AAAA (NOERROR/NODATA) и HTTPS TYPE65 (пустой ответ) валидны\n'

    # 6. Ad-blocking filter test (allow up to 10s on first AdGuardHome start while filter list initializes)
    local ad_blocked=0
    for _ in {1..10}; do
        local ad_out
        ad_out="$(dig +time=2 +tries=1 @127.0.0.1 -p 5353 doubleclick.net A || true)"
        if grep -q "NXDOMAIN" <<<"${ad_out}" || grep -Eq '[[:space:]]0\.0\.0\.0$' <<<"${ad_out}"; then
            ad_blocked=1
            break
        fi
        sleep 1
    done
    if [[ "${ad_blocked}" -ne 1 ]]; then
        log_error "dns.log" "Фильтрация рекламы (doubleclick.net) не сработала в ${expected_engine}."
        return 1
    fi
    printf '[ PASS ] Фильтрация рекламных доменов (doubleclick.net) активна\n'

    # 7. Direct RFC 8484 HTTP DoH POST on 127.0.0.1:8053/dns-query
    local local_doh_check
    local_doh_check="$(printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' | \
        curl -s -o /dev/null -w '%{http_code}:%{content_type}' \
        -H 'Content-Type: application/dns-message' --data-binary @- \
        'http://127.0.0.1:8053/dns-query' || echo '000:none')"
    if [[ "${local_doh_check}" != "200:application/dns-message" ]]; then
        log_error "dns.log" "Прямой DoH POST на http://127.0.0.1:8053/dns-query вернул ${local_doh_check}."
        return 1
    fi
    printf '[ PASS ] Прямой RFC 8484 HTTP DoH POST на 127.0.0.1:8053/dns-query работает (%s)\n' "${local_doh_check}"
    printf '==============================================================================\n'
    return 0
}

run_switch_engine() {
    local target_engine="${1:-}"
    if [[ "${target_engine}" != "oxidns" && "${target_engine}" != "adguardhome" ]]; then
        printf 'ОШИБКА: Укажите целевой DNS backend: %s --switch-engine [oxidns|adguardhome]\n' "${SCRIPT_NAME}" >&2
        exit 1
    fi

    if [[ ! -f "${SETTINGS_FILE}" || ! -f "${SECRETS_FILE}" ]]; then
        printf 'ОШИБКА: Система не установлена (%s не найден).\n' "${SETTINGS_FILE}" >&2
        exit 1
    fi

    detect_environment
    # shellcheck disable=SC1091
    source "${SETTINGS_FILE}"
    # shellcheck disable=SC1091
    source "${SECRETS_FILE}"

    local previous_engine="${DNS_ENGINE}"
    if [[ "${previous_engine}" == "${target_engine}" ]] && systemctl is-active --quiet "${target_engine}"; then
        printf 'DNS backend %s уже активен. Запуск проверок...\n' "${target_engine}"
        verify_dns_backend_isolated
        run_test_suite
        return 0
    fi

    if [[ "${target_engine}" == "oxidns" && "${CPU_ARCH}" != "x86_64" ]]; then
        printf 'ОШИБКА: OxiDNS поддерживает только x86_64.\n' >&2
        exit 1
    fi

    log_info "dns.log" "Запуск транзакционного переключения DNS backend: ${previous_engine} -> ${target_engine}..."
    create_system_backup
    TRANSACTION_ACTIVE=1

    if [[ "${target_engine}" == "adguardhome" ]]; then
        if [[ ! -x /usr/local/bin/AdGuardHome ]]; then
            install_adguardhome_binary
        fi
        DNS_ENGINE="adguardhome"
        DNS_USER="adguard"
    else
        if [[ ! -x /usr/local/bin/oxidns ]]; then
            install_oxidns_binary
        fi
        DNS_ENGINE="oxidns"
        DNS_USER="oxidns"
    fi

    setup_users_and_dirs
    save_persistent_settings
    configure_dns_engine
    write_dns_engine_systemd_unit
    systemctl daemon-reload

    log_info "dns.log" "Остановка ${previous_engine}.service (конфигурация сохраняется) и запуск ${target_engine}.service..."
    systemctl disable --now "${previous_engine}.service" 2>/dev/null || true

    for _ in {1..10}; do
        if ! ss -ulnp 2>/dev/null | grep -q ":5353 " && ! ss -tlnp 2>/dev/null | grep -q ":8053 "; then
            break
        fi
        sleep 1
    done

    systemctl enable --now "${target_engine}.service"

    local ready=0
    for _ in {1..15}; do
        if ss -ulnp 2>/dev/null | grep -q "127.0.0.1:5353 " && ss -tlnp 2>/dev/null | grep -q "127.0.0.1:8053 "; then
            ready=1
            break
        fi
        sleep 1
    done

    if [[ "${ready}" -ne 1 ]]; then
        log_error "dns.log" "Служба ${target_engine} не открыла порты 5353/8053 в отведённое время."
        return 1
    fi

    verify_dns_backend_isolated
    nginx -t && systemctl reload nginx
    run_test_suite

    TRANSACTION_ACTIVE=0
    log_info "dns.log" "Переключение DNS backend на ${target_engine} успешно завершено и проверено."

    if [[ "${target_engine}" == "adguardhome" ]]; then
        # shellcheck disable=SC1091
        source "${SECRETS_FILE}"
        printf '\n==============================================================================\n'
        printf ' УСПЕШНОЕ ПЕРЕКЛЮЧЕНИЕ НА ADGUARDHOME (СЕРТИФИКАТЫ И СЕКРЕТЫ СОХРАНЕНЫ)\n'
        printf '==============================================================================\n'
        printf 'Активный DNS backend      : AdGuardHome (127.0.0.1:5353 / 127.0.0.1:8053)\n'
        printf 'Веб-интерфейс AdGuardHome : http://127.0.0.1:8053 (доступ только через SSH-туннель)\n'
        printf 'Логин администратора      : %s\n' "${AGH_ADMIN_USER:-см. secrets.env}"
        printf 'Пароль администратора     : [сохранён в %s]\n' "${SECRETS_FILE}"
        printf 'Возврат к OxiDNS          : sudo %s --switch-engine oxidns\n' "${SCRIPT_NAME}"
        printf '==============================================================================\n'
    else
        printf '\n==============================================================================\n'
        printf ' УСПЕШНЫЙ ВОЗВРАТ К OXIDNS (СЕРТИФИКАТЫ И СЕКРЕТЫ СОХРАНЕНЫ)\n'
        printf '==============================================================================\n'
    fi
}

# ------------------------------ DoT Whitelist Management ----------------------
load_whitelist_sets() {
    if [[ ! -f "${SETTINGS_FILE}" ]]; then
        printf 'ОШИБКА: Файл настроек %s не найден. Сначала выполните --install.\n' "${SETTINGS_FILE}" >&2
        exit 1
    fi
    # shellcheck disable=SC1091
    source "${SETTINGS_FILE}"
    if [[ "${DOT_WHITELIST_MODE:-shared}" == "separate" ]]; then
        ACTIVE_DOT_SET_V4="dot_clients"
        ACTIVE_DOT_SET_V6="dot_clients6"
    else
        ACTIVE_DOT_SET_V4="smartdns_clients"
        ACTIVE_DOT_SET_V6="smartdns_clients6"
    fi
}

persist_ipset_state() {
    ipset save > "${IPSET_SAVE_FILE}.tmp" 2>/dev/null && mv -f "${IPSET_SAVE_FILE}.tmp" "${IPSET_SAVE_FILE}"
    chmod 0600 "${IPSET_SAVE_FILE}"
}

run_whitelist_status() {
    load_whitelist_sets
    local wl_banner="DISABLED"
    [[ "${DOT_WHITELIST_ENABLED:-false}" == "true" ]] && wl_banner="ENABLED"

    printf '==============================================================================\n'
    printf 'DoT IP-whitelist: %s\n' "${wl_banner}"
    printf 'DOT_WHITELIST_ENABLED : %s\n' "${DOT_WHITELIST_ENABLED:-false}"
    printf 'Режим whitelist       : %s (наборы DoT: %s / %s)\n' "${DOT_WHITELIST_MODE:-shared}" "${ACTIVE_DOT_SET_V4}" "${ACTIVE_DOT_SET_V6}"
    printf 'TTL записей           : 86400 секунд\n'
    printf 'Файл сохранения       : %s\n' "${IPSET_SAVE_FILE}"
    printf -- '------------------------------------------------------------------------------\n'
    printf 'Разрешённые IPv4-адреса в %s (DoT 853/TCP) и оставшийся TTL:\n' "${ACTIVE_DOT_SET_V4}"
    ipset list "${ACTIVE_DOT_SET_V4}" 2>/dev/null | awk '/^[0-9]/ {print "  - " $0}' || printf '  (список пуст)\n'
    if [[ "${DOT_WHITELIST_MODE:-shared}" == "separate" ]]; then
        printf -- '------------------------------------------------------------------------------\n'
        printf 'Разрешённые IPv4-адреса в smartdns_clients (DoH / SNI Proxy 443/TCP):\n'
        ipset list smartdns_clients 2>/dev/null | awk '/^[0-9]/ {print "  - " $0}' || printf '  (список пуст)\n'
    fi
    printf -- '------------------------------------------------------------------------------\n'
    printf 'Разрешённые IPv6-адреса (%s) и оставшийся TTL:\n' "${ACTIVE_DOT_SET_V6}"
    ipset list "${ACTIVE_DOT_SET_V6}" 2>/dev/null | awk '/^[0-9a-fA-F:]/ && $0 ~ /:/ && $0 !~ /^Name|^Type|^Revision|^Header|^Size|^References|^Number|^Members/ {print "  - " $0}' || printf '  (список пуст)\n'
    printf '==============================================================================\n'
}

run_whitelist_add() {
    local target_ip="${1:-}"
    if [[ -z "${target_ip}" ]]; then
        printf 'ОШИБКА: Укажите IPv4 или IPv6 адрес. Пример: %s --whitelist-add 203.0.113.10\n' "${SCRIPT_NAME}" >&2
        exit 1
    fi
    if [[ "${target_ip}" == *"/"* ]]; then
        printf 'ОШИБКА: Добавление CIDR-диапазонов запрещено политикой безопасности. Укажите одиночный IP-адрес.\n' >&2
        exit 1
    fi
    load_whitelist_sets

    if validate_single_ipv4 "${target_ip}"; then
        ipset add "${ACTIVE_DOT_SET_V4}" "${target_ip}" timeout 86400 -exist
        ipset add smartdns_clients "${target_ip}" timeout 86400 -exist
        persist_ipset_state
        log_info "firewall.log" "Вручную добавлен IPv4 ${target_ip} в ${ACTIVE_DOT_SET_V4} и smartdns_clients (TTL 86400s)."
        printf 'УСПЕШНО: IPv4 %s добавлен в %s и smartdns_clients (TTL: 86400 сек).\n' "${target_ip}" "${ACTIVE_DOT_SET_V4}"
    elif validate_single_ipv6 "${target_ip}"; then
        ipset add "${ACTIVE_DOT_SET_V6}" "${target_ip}" timeout 86400 -exist
        ipset add smartdns_clients6 "${target_ip}" timeout 86400 -exist
        persist_ipset_state
        log_info "firewall.log" "Вручную добавлен IPv6 ${target_ip} в ${ACTIVE_DOT_SET_V6} и smartdns_clients6 (TTL 86400s)."
        printf 'УСПЕШНО: IPv6 %s добавлен в %s и smartdns_clients6 (TTL: 86400 сек).\n' "${target_ip}" "${ACTIVE_DOT_SET_V6}"
    else
        printf 'ОШИБКА: Некорректный формат IPv4/IPv6 адреса: %s\n' "${target_ip}" >&2
        exit 1
    fi
}

run_whitelist_remove() {
    local target_ip="${1:-}"
    if [[ -z "${target_ip}" ]]; then
        printf 'ОШИБКА: Укажите IPv4 или IPv6 адрес для удаления.\n' >&2
        exit 1
    fi
    load_whitelist_sets

    if validate_single_ipv4 "${target_ip}"; then
        ipset del "${ACTIVE_DOT_SET_V4}" "${target_ip}" -exist
        ipset del smartdns_clients "${target_ip}" -exist
        persist_ipset_state
        log_info "firewall.log" "Удалён IPv4 ${target_ip} из ${ACTIVE_DOT_SET_V4} и smartdns_clients."
        printf 'УСПЕШНО: IPv4 %s удалён из %s и smartdns_clients.\n' "${target_ip}" "${ACTIVE_DOT_SET_V4}"
    elif validate_single_ipv6 "${target_ip}"; then
        ipset del "${ACTIVE_DOT_SET_V6}" "${target_ip}" -exist
        ipset del smartdns_clients6 "${target_ip}" -exist
        persist_ipset_state
        log_info "firewall.log" "Удалён IPv6 ${target_ip} из ${ACTIVE_DOT_SET_V6} и smartdns_clients6."
        printf 'УСПЕШНО: IPv6 %s удалён из %s и smartdns_clients6.\n' "${target_ip}" "${ACTIVE_DOT_SET_V6}"
    else
        printf 'ОШИБКА: Некорректный формат IPv4/IPv6 адреса: %s\n' "${target_ip}" >&2
        exit 1
    fi
}

run_whitelist_flush() {
    load_whitelist_sets
    ipset flush "${ACTIVE_DOT_SET_V4}"
    ipset flush "${ACTIVE_DOT_SET_V6}"
    persist_ipset_state
    log_info "firewall.log" "Очищены списки DoT whitelist (${ACTIVE_DOT_SET_V4}, ${ACTIVE_DOT_SET_V6})."
    printf 'УСПЕШНО: Списки %s и %s полностью очищены.\n' "${ACTIVE_DOT_SET_V4}" "${ACTIVE_DOT_SET_V6}"
}

run_whitelist_toggle() {
    local desired="${1:-toggle}"
    if [[ ! -f "${SETTINGS_FILE}" ]]; then
        printf 'ОШИБКА: Файл настроек %s не найден. Сначала выполните --install.\n' "${SETTINGS_FILE}" >&2
        exit 1
    fi
    # shellcheck disable=SC1091
    source "${SETTINGS_FILE}"

    local current_state="${DOT_WHITELIST_ENABLED:-false}"
    local new_state=""

    case "${desired,,}" in
        toggle|"")
            if [[ "${current_state}" == "true" ]]; then
                new_state="false"
            else
                new_state="true"
            fi
            ;;
        on|enable|enabled|true|1)
            new_state="true"
            ;;
        off|disable|disabled|false|0)
            new_state="false"
            ;;
        *)
            printf 'ОШИБКА: Недопустимое значение "%s". Используйте: %s --whitelist-toggle [on|off]\n' "${desired}" "${SCRIPT_NAME}" >&2
            exit 1
            ;;
    esac

    if grep -q '^DOT_WHITELIST_ENABLED=' "${SETTINGS_FILE}"; then
        sed -i "s|^DOT_WHITELIST_ENABLED=.*|DOT_WHITELIST_ENABLED=\"${new_state}\"|" "${SETTINGS_FILE}"
    else
        printf 'DOT_WHITELIST_ENABLED="%s"\n' "${new_state}" >> "${SETTINGS_FILE}"
    fi

    if [[ -f "${ROUTING_VARS_FILE}" ]]; then
        if grep -q '^DOT_WHITELIST_ENABLED=' "${ROUTING_VARS_FILE}"; then
            sed -i "s|^DOT_WHITELIST_ENABLED=.*|DOT_WHITELIST_ENABLED=\"${new_state}\"|" "${ROUTING_VARS_FILE}"
        else
            printf 'DOT_WHITELIST_ENABLED="%s"\n' "${new_state}" >> "${ROUTING_VARS_FILE}"
        fi
    fi

    /usr/local/bin/smartdns-firewall-apply.sh
    if [[ "${new_state}" == "true" ]]; then
        seed_initial_admin_ip
    fi

    log_info "firewall.log" "Режим DoT IP-whitelist (TCP 853) переключён: ${current_state} -> ${new_state} (режим наборов: ${DOT_WHITELIST_MODE:-shared})."
    printf 'УСПЕШНО: DoT IP-whitelist (TCP 853) переключён: %s -> %s.\n\n' "${current_state}" "${new_state}"
    run_whitelist_status
}

run_whitelist_mode() {
    local new_mode="${1:-}"
    if [[ "${new_mode}" != "shared" && "${new_mode}" != "separate" ]]; then
        printf 'ОШИБКА: Укажите режим whitelist: %s --whitelist-mode [shared|separate]\n' "${SCRIPT_NAME}" >&2
        exit 1
    fi
    if [[ ! -f "${SETTINGS_FILE}" ]]; then
        printf 'ОШИБКА: Файл настроек %s не найден. Сначала выполните --install.\n' "${SETTINGS_FILE}" >&2
        exit 1
    fi
    # shellcheck disable=SC1091
    source "${SETTINGS_FILE}"

    local old_mode="${DOT_WHITELIST_MODE:-shared}"
    if grep -q '^DOT_WHITELIST_MODE=' "${SETTINGS_FILE}"; then
        sed -i "s|^DOT_WHITELIST_MODE=.*|DOT_WHITELIST_MODE=\"${new_mode}\"|" "${SETTINGS_FILE}"
    else
        printf 'DOT_WHITELIST_MODE="%s"\n' "${new_mode}" >> "${SETTINGS_FILE}"
    fi

    if [[ -f "${ROUTING_VARS_FILE}" ]]; then
        if grep -q '^DOT_WHITELIST_MODE=' "${ROUTING_VARS_FILE}"; then
            sed -i "s|^DOT_WHITELIST_MODE=.*|DOT_WHITELIST_MODE=\"${new_mode}\"|" "${ROUTING_VARS_FILE}"
        else
            printf 'DOT_WHITELIST_MODE="%s"\n' "${new_mode}" >> "${ROUTING_VARS_FILE}"
        fi
    fi

    /usr/local/bin/smartdns-firewall-apply.sh
    if [[ "${DOT_WHITELIST_ENABLED:-false}" == "true" ]]; then
        seed_initial_admin_ip
    fi

    log_info "firewall.log" "Режим наборов DoT whitelist изменён: ${old_mode} -> ${new_mode}."
    printf 'УСПЕШНО: Режим наборов DoT whitelist изменён: %s -> %s.\n\n' "${old_mode}" "${new_mode}"
    run_whitelist_status
}

# ------------------------------ IP Synchronization (--sync-ip) ----------------
run_sync_ip() {
    if [[ ! -f "${SETTINGS_FILE}" ]]; then
        printf 'ОШИБКА: Файл настроек %s не найден. Сначала выполните --install.\n' "${SETTINGS_FILE}" >&2
        exit 1
    fi

    local old_ipv4 old_ipv6
    old_ipv4="$(awk -F'"' '/^SERVER_IPV4=/ {print $2}' "${SETTINGS_FILE}" 2>/dev/null || true)"
    old_ipv6="$(awk -F'"' '/^SERVER_IPV6=/ {print $2}' "${SETTINGS_FILE}" 2>/dev/null || true)"

    detect_environment
    if [[ -z "${SERVER_IPV4}" ]]; then
        log_error "update.log" "Не удалось определить текущий глобальный IPv4-адрес сервера."
        exit 1
    fi

    local new_ipv4="${SERVER_IPV4}"
    local new_ipv6="${SERVER_IPV6:-}"

    # shellcheck disable=SC1091
    source "${SETTINGS_FILE}"
    SERVER_IPV4="${new_ipv4}"
    SERVER_IPV6="${new_ipv6}"

    log_info "update.log" "Запуск синхронизации IP-адреса: старый IPv4=${old_ipv4:-нет} -> новый IPv4=${new_ipv4} (IPv6=${new_ipv6:-нет})"

    create_system_backup
    TRANSACTION_ACTIVE=1

    sed -i "s|^SERVER_IPV4=.*|SERVER_IPV4=\"${new_ipv4}\"|" "${SETTINGS_FILE}" "${ROUTING_VARS_FILE}"
    sed -i "s|^SERVER_IPV6=.*|SERVER_IPV6=\"${new_ipv6}\"|" "${SETTINGS_FILE}"
    sed -i "s|^HAS_IPV6=.*|HAS_IPV6=\"${HAS_IPV6}\"|" "${SETTINGS_FILE}"
    sed -i "s|^PRIMARY_IFACE=.*|PRIMARY_IFACE=\"${PRIMARY_IFACE}\"|" "${SETTINGS_FILE}"

    if ! sync_cloudflare_dns_records "${new_ipv4}" "${new_ipv6}"; then
        log_warn "update.log" "Предупреждение: не удалось автоматически обновить записи в Cloudflare API. Проверьте их вручную."
    fi

    /usr/local/bin/update-geohide-domains.sh
    /usr/local/bin/smartdns-firewall-apply.sh

    systemctl restart "${DNS_ENGINE}" xray
    nginx -t && systemctl reload nginx

    run_test_suite
    TRANSACTION_ACTIVE=0
    log_info "update.log" "Синхронизация нового IP (${new_ipv4}) успешно завершена."
}

# ------------------------------ Fast Domain Change (--change-domain) ----------
run_change_domain() {
    if [[ ! -f "${SETTINGS_FILE}" || ! -f "${SECRETS_FILE}" ]]; then
        printf 'ОШИБКА: Файлы настроек не найдены. Сначала выполните --install.\n' >&2
        exit 1
    fi

    detect_environment
    # shellcheck disable=SC1091
    source "${SETTINGS_FILE}"
    # shellcheck disable=SC1091
    source "${SECRETS_FILE}"

    local old_root_domain="${ROOT_DOMAIN}"
    local old_dot_host="${DOT_HOST}"

    local dot_prefix="${old_dot_host%.${old_root_domain}}"
    if [[ -z "${dot_prefix}" || "${dot_prefix}" == "${old_dot_host}" ]]; then
        dot_prefix="${old_dot_host%%.*}"
    fi

    printf '\n==============================================================================\n'
    printf '     БЫСТРАЯ СМЕНА ДОМЕНА (С СОХРАНЕНИЕМ ПОДДОМЕНА DoT И СЕКРЕТНЫХ ПУТЕЙ)     \n'
    printf '==============================================================================\n'
    printf 'Текущий основной домен (ROOT_DOMAIN) : %s\n' "${old_root_domain}"
    printf 'Текущий поддомен DoT (DOT_HOST)      : %s (префикс "%s" сохраняется)\n' "${old_dot_host}" "${dot_prefix}"
    printf 'Секретный путь DoH (DOH_PATH)        : [СОХРАНЯЕТСЯ БЕЗ ИЗМЕНЕНИЙ, %d симв.]\n\n' "${#DOH_PATH}"

    local new_root_domain="${1:-}"
    if [[ -n "${new_root_domain}" ]]; then
        new_root_domain="${new_root_domain,,}"
        if ! validate_domain_syntax "${new_root_domain}"; then
            printf 'ОШИБКА: Некорректный синтаксис переданного домена: %s\n' "${new_root_domain}" >&2
            exit 1
        fi
    else
        while true; do
            read -r -p "Введите новый основной домен (ROOT_DOMAIN, например newdomain.com): " new_root_domain
            new_root_domain="${new_root_domain,,}"
            if validate_domain_syntax "${new_root_domain}"; then
                break
            fi
            printf 'ОШИБКА: Некорректный синтаксис доменного имени.\n'
        done
    fi

    local new_dot_host="${dot_prefix}.${new_root_domain}"

    if [[ -t 0 ]]; then
        read -r -s -p "Введите Cloudflare API Token для зоны ${new_root_domain} (Enter — использовать текущий токен): " input_cf_token
        printf '\n'
        if [[ -n "${input_cf_token}" ]]; then
            CF_API_TOKEN="${input_cf_token}"
        fi
    fi

    if [[ -z "${CF_API_TOKEN:-}" || "${CF_API_TOKEN}" == "REUSE_EXISTING_CERT_TOKEN" ]]; then
        printf 'ОШИБКА: Для выпуска сертификата на новый домен необходим действующий Cloudflare API Token.\n' >&2
        exit 1
    fi

    printf '\nПлан смены домена:\n'
    printf '  - Новый ROOT_DOMAIN (Сайт + DoH) : %s\n' "${new_root_domain}"
    printf '  - Новый DOT_HOST (TCP 853)       : %s (префикс "%s" не изменён)\n' "${new_dot_host}" "${dot_prefix}"
    printf '  - Секретный путь DoH / Web-Auth  : сохраняется прежний\n'
    if [[ -t 0 ]]; then
        read -r -p "Применить смену домена и выпустить новый сертификат? [y/N]: " confirm_dom
        if [[ ! "${confirm_dom:-N}" =~ ^[Yy]$ ]]; then
            printf 'Операция отменена пользователем.\n'
            exit 0
        fi
    fi

    create_system_backup
    TRANSACTION_ACTIVE=1

    ROOT_DOMAIN="${new_root_domain}"
    DOH_HOST="${new_root_domain}"
    DOT_HOST="${new_dot_host}"
    ACME_EMAIL="admin@${new_root_domain}"

    save_persistent_settings

    log_info "update.log" "Синхронизация A/AAAA записей для нового домена ${ROOT_DOMAIN} в Cloudflare..."
    sync_cloudflare_dns_records "${SERVER_IPV4}" "${SERVER_IPV6:-}" || true

    log_info "certificate.log" "Выпуск wildcard-сертификата для нового домена ${ROOT_DOMAIN}..."
    issue_wildcard_certificate

    sync_cover_site_domain_metadata
    configure_nginx

    if [[ "${DNS_ENGINE}" == "adguardhome" && -f /etc/adguardhome/AdGuardHome.yaml ]]; then
        sed -i "s|^  server_name:.*|  server_name: \"${ROOT_DOMAIN}\"|" /etc/adguardhome/AdGuardHome.yaml
    fi

    /usr/local/bin/update-geohide-domains.sh

    systemctl restart "${DNS_ENGINE}" xray
    nginx -t && systemctl reload nginx

    run_test_suite
    TRANSACTION_ACTIVE=0

    log_info "update.log" "Смена домена успешно завершена: ${old_root_domain} -> ${ROOT_DOMAIN} (DoT: ${DOT_HOST})."
    printf '\n==============================================================================\n'
    printf ' ДОМЕН УСПЕШНО ИЗМЕНЁН (ПОДДОМЕН DoT И СЕКРЕТНЫЙ ПУТЬ СОХРАНЕНЫ)\n'
    printf '==============================================================================\n'
    printf 'Новый DoH URL             : https://%s/resolve/%s\n' "${ROOT_DOMAIN}" "${DOH_PATH}"
    printf 'Новая ссылка авторизации  : https://%s/auth/%s\n' "${ROOT_DOMAIN}" "${DOH_PATH}"
    printf 'Новый хост DoT (853/TCP)  : %s\n' "${DOT_HOST}"
    printf '==============================================================================\n'
}

# ------------------------------ Comprehensive Test Suite ----------------------
run_test_suite() {
    detect_environment
    if [[ ! -f "${SETTINGS_FILE}" ]]; then
        printf 'ОШИБКА: Файл настроек %s не найден. Сначала выполните --install.\n' "${SETTINGS_FILE}" >&2
        exit 1
    fi
    # shellcheck disable=SC1091
    source "${SETTINGS_FILE}"
    # shellcheck disable=SC1091
    source "${SECRETS_FILE}"
    load_whitelist_sets

    local failures=0
    printf '==============================================================================\n'
    printf '         КОМПЛЕКСНОЕ ТЕСТИРОВАНИЕ UNIFIED SMARTDNS + SNI PROXY                \n'
    printf '         Активный DNS backend: %-45s  \n' "${DNS_ENGINE}"
    printf '==============================================================================\n'

    check_step() {
        local name="$1"
        local result="$2"
        if [[ "${result}" == "PASS" ]]; then
            printf '[ PASS ] %s\n' "${name}"
        else
            printf '[ FAIL ] %s\n' "${name}"
            failures=$((failures + 1))
        fi
    }

    # 1. Service status & non-root execution
    for svc in "${DNS_ENGINE}" xray nginx doh-ipset-watcher dot-ipset-watcher; do
        if systemctl is-active --quiet "${svc}"; then
            check_step "Служба ${svc} активна" "PASS"
        else
            check_step "Служба ${svc} активна" "FAIL"
        fi
    done

    local xray_proc_user
    xray_proc_user="$(ps -o user= -C xray | sed -n '1p' | tr -d ' ')"
    check_step "Процесс Xray работает без root (user=${xray_proc_user})" "$( [[ "${xray_proc_user}" == "xray" ]] && echo PASS || echo FAIL )"

    # 2. Certificate cryptographic verification
    if /usr/local/bin/verify-tls-keys.sh "${CERT_DIR}/fullchain.pem" "${CERT_DIR}/privkey.pem" "${ROOT_DOMAIN}" >/dev/null 2>&1; then
        check_step "Сертификат SAN и SHA-256 ключей валидны" "PASS"
    else
        check_step "Сертификат SAN и SHA-256 ключей валидны" "FAIL"
    fi

    # 3. Ordinary DNS resolution via internal listener
    local normal_a
    normal_a="$(dig +time=3 +tries=2 +short @127.0.0.1 -p 5353 example.com A || true)"
    normal_a="$(printf '%s\n' "${normal_a}" | sed -n '1p')"
    check_step "Обычный домен (example.com) разрешается в реальный IP (${normal_a})" "$( validate_single_ipv4 "${normal_a}" && [[ "${normal_a}" != "${SERVER_IPV4}" ]] && echo PASS || echo FAIL )"

    # 4. SmartDNS A spoofing for proxied domain & subdomains
    local spoof_a
    spoof_a="$(dig +time=3 +tries=2 +short @127.0.0.1 -p 5353 generativelanguage.googleapis.com A || true)"
    spoof_a="$(printf '%s\n' "${spoof_a}" | sed -n '1p')"
    check_step "SmartDNS подменяет A-запись проксируемого домена на ${SERVER_IPV4}" "$( [[ "${spoof_a}" == "${SERVER_IPV4}" ]] && echo PASS || echo FAIL )"

    # 5. NODATA (NOERROR + empty ANSWER) for AAAA and NOERROR/REFUSED for HTTPS (TYPE65)
    local aaaa_out
    aaaa_out="$(dig +time=3 +tries=2 @127.0.0.1 -p 5353 generativelanguage.googleapis.com AAAA || true)"
    if grep -q "status: NOERROR" <<<"${aaaa_out}" && grep -q "ANSWER: 0" <<<"${aaaa_out}"; then
        check_step "Обработка AAAA возвращает корректный NOERROR/NODATA" "PASS"
    else
        check_step "Обработка AAAA возвращает корректный NOERROR/NODATA" "FAIL"
    fi

    local https_out
    https_out="$(dig +time=3 +tries=2 @127.0.0.1 -p 5353 generativelanguage.googleapis.com TYPE65 || true)"
    if grep -Eq "status: (NOERROR|REFUSED)" <<<"${https_out}" && grep -q "ANSWER: 0" <<<"${https_out}"; then
        check_step "Обработка HTTPS (qtype 65) возвращает пустой ответ (NOERROR/REFUSED)" "PASS"
    else
        check_step "Обработка HTTPS (qtype 65) возвращает пустой ответ (NOERROR/REFUSED)" "FAIL"
    fi

    # 6. Negative Test: Wrong DoH path on ROOT_DOMAIN returns disguised 404
    local wrong_doh_code
    wrong_doh_code="$(curl -sk -o /dev/null -w '%{http_code}' --resolve "${ROOT_DOMAIN}:9443:127.0.0.1" "https://${ROOT_DOMAIN}:9443/resolve/wrongpath12345" || echo 000)"
    check_step "Негативный тест: неверный путь DoH на ${ROOT_DOMAIN} маскируется под 404 (HTTP ${wrong_doh_code})" "$( [[ "${wrong_doh_code}" == "404" ]] && echo PASS || echo FAIL )"

    # 7. Valid DoH RFC 8484 query on ROOT_DOMAIN
    local valid_doh_ctype
    valid_doh_ctype="$(curl -sk -o /dev/null -w '%{content_type}' --resolve "${ROOT_DOMAIN}:9443:127.0.0.1" \
        "https://${ROOT_DOMAIN}:9443/resolve/${DOH_PATH}?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" || true)"
    check_step "Корректный DoH-запрос (A) на корневом домене ${ROOT_DOMAIN} работает" "$( [[ "${valid_doh_ctype}" == "application/dns-message" ]] && echo PASS || echo FAIL )"

    # 8. Web-Auth bookmark endpoint check
    local web_auth_check
    web_auth_check="$(curl -sk --resolve "${ROOT_DOMAIN}:9443:127.0.0.1" "https://${ROOT_DOMAIN}:9443/auth/${DOH_PATH}" || true)"
    check_step "Секретная ссылка веб-авторизации /auth/ работает" "$( grep -q "Session Synchronized" <<<"${web_auth_check}" && echo PASS || echo FAIL )"

    # 9. DoT IPv4/IPv6 Whitelist, TTL Expiration, Re-auth, and Wrong SNI Checks
    if [[ "${DOT_WHITELIST_ENABLED:-false}" == "true" ]]; then
        ipset del "${ACTIVE_DOT_SET_V4}" 127.0.0.2 -exist
        if ! timeout 2 openssl s_client -connect 127.0.0.2:853 -servername "${DOT_HOST}" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
            check_step "DoT Whitelist (ENABLED): запрещённый IPv4 блокируется firewall на 853/TCP" "PASS"
        else
            check_step "DoT Whitelist (ENABLED): запрещённый IPv4 блокируется firewall на 853/TCP" "FAIL"
        fi

        ipset add "${ACTIVE_DOT_SET_V4}" 127.0.0.1 timeout 86400 -exist
        if timeout 4 openssl s_client -connect 127.0.0.1:853 -servername "${DOT_HOST}" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
            check_step "DoT Whitelist (ENABLED): разрешённый IPv4 успешно подключается к 853/TCP" "PASS"
        else
            check_step "DoT Whitelist (ENABLED): разрешённый IPv4 успешно подключается к 853/TCP" "FAIL"
        fi

        if ! timeout 3 openssl s_client -connect 127.0.0.1:853 -servername "invalid.sni.${ROOT_DOMAIN}" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
            check_step "DoT Whitelist (ENABLED): неверный SNI с разрешённого IPv4 не получает сертификат" "PASS"
        else
            check_step "DoT Whitelist (ENABLED): неверный SNI с разрешённого IPv4 не получает сертификат" "FAIL"
        fi

        ipset del "${ACTIVE_DOT_SET_V6}" ::1 -exist
        if ! timeout 2 openssl s_client -6 -connect "[::1]:853" -servername "${DOT_HOST}" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
            check_step "DoT Whitelist (ENABLED): запрещённый IPv6 блокируется firewall на 853/TCP" "PASS"
        else
            check_step "DoT Whitelist (ENABLED): запрещённый IPv6 блокируется firewall на 853/TCP" "FAIL"
        fi

        ipset add "${ACTIVE_DOT_SET_V6}" ::1 timeout 86400 -exist
        if ipset test "${ACTIVE_DOT_SET_V6}" ::1 >/dev/null 2>&1 && ip6tables -t filter -C SMARTDNS6_INPUT -p tcp --dport 853 -m set --match-set "${ACTIVE_DOT_SET_V6}" src -m hashlimit --hashlimit-name dot_v6_rate --hashlimit-mode srcip --hashlimit-upto 30/min --hashlimit-burst 40 -j ACCEPT 2>/dev/null; then
            check_step "DoT Whitelist (ENABLED): правило разрешённого IPv6 активно в ip6tables и ipset" "PASS"
        else
            check_step "DoT Whitelist (ENABLED): правило разрешённого IPv6 активно в ip6tables и ipset" "FAIL"
        fi
        ipset del "${ACTIVE_DOT_SET_V6}" ::1 -exist

        ipset add "${ACTIVE_DOT_SET_V4}" 198.51.100.250 timeout 2 -exist
        sleep 3
        if ! ipset test "${ACTIVE_DOT_SET_V4}" 198.51.100.250 >/dev/null 2>&1; then
            check_step "DoT Whitelist: автоматическое истечение TTL записи в ipset работает" "PASS"
        else
            check_step "DoT Whitelist: автоматическое истечение TTL записи в ipset работает" "FAIL"
        fi

        ipset add "${ACTIVE_DOT_SET_V4}" 198.51.100.250 timeout 100 -exist
        ipset add "${ACTIVE_DOT_SET_V4}" 198.51.100.250 timeout 86400 -exist
        local refreshed_ttl
        refreshed_ttl="$(ipset list "${ACTIVE_DOT_SET_V4}" | awk '$1 == "198.51.100.250" {print $3}')"
        ipset del "${ACTIVE_DOT_SET_V4}" 198.51.100.250 -exist
        ipset del "${ACTIVE_DOT_SET_V4}" 127.0.0.1 -exist
        check_step "DoT Whitelist: повторная авторизация обновляет TTL до 86400s (TTL=${refreshed_ttl:-0})" "$( [[ "${refreshed_ttl:-0}" -gt 86000 ]] && echo PASS || echo FAIL )"
    else
        ipset del "${ACTIVE_DOT_SET_V4}" 127.0.0.1 -exist
        if ! timeout 3 openssl s_client -connect 127.0.0.1:853 -servername "invalid.sni.${ROOT_DOMAIN}" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
            check_step "DoT Whitelist (DISABLED): неверный SNI на 853/TCP блокируется Xray" "PASS"
        else
            check_step "DoT Whitelist (DISABLED): неверный SNI на 853/TCP блокируется Xray" "FAIL"
        fi

        if timeout 5 openssl s_client -connect 127.0.0.1:853 -servername "${DOT_HOST}" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
            check_step "DoT Whitelist (DISABLED): подключение без IP-фильтрации с валидным DOT_HOST работает" "PASS"
        else
            check_step "DoT Whitelist (DISABLED): подключение без IP-фильтрации с валидным DOT_HOST работает" "FAIL"
        fi
    fi

    # 10. Persistence & Internal Ports Protection Check
    if systemctl is-enabled --quiet smartdns-firewall.service && [[ -f "${IPSET_SAVE_FILE}" ]] && iptables -t filter -C SMARTDNS_INPUT -p tcp -m multiport --dports 8443,9444,8853,5353,8053,3000 -j DROP 2>/dev/null; then
        check_step "Сохранение настроек после перезагрузки и защита внутренних портов (включая 9444 и 8053) активны" "PASS"
    else
        check_step "Сохранение настроек после перезагрузки и защита внутренних портов (включая 9444 и 8053) активны" "FAIL"
    fi

    # 11. Procedural Cover Site availability & structural integrity check
    local site_html site_code css_code
    site_code="$(curl -sk -o /dev/null -w '%{http_code}' --resolve "${ROOT_DOMAIN}:9443:127.0.0.1" "https://${ROOT_DOMAIN}:9443/" || echo 000)"
    site_html="$(curl -sk --resolve "${ROOT_DOMAIN}:9443:127.0.0.1" "https://${ROOT_DOMAIN}:9443/" || true)"
    css_code="$(curl -sk -o /dev/null -w '%{http_code}' --resolve "${ROOT_DOMAIN}:9443:127.0.0.1" "https://${ROOT_DOMAIN}:9443/assets/style.css" || echo 000)"
    if [[ "${site_code}" == "200" && "${css_code}" == "200" ]] && grep -Fq "<!DOCTYPE html>" <<<"${site_html}" && grep -Fq "<main>" <<<"${site_html}" && grep -Fq "<footer" <<<"${site_html}"; then
        check_step "Процедурный Cover Site доступен (HTTP 200), CSS загружается и разметка валидна" "PASS"
    else
        check_step "Процедурный Cover Site доступен (HTTP 200), CSS загружается и разметка валидна" "FAIL"
    fi

    # 12. Negative Test: Damaged JSON rejected by xray-safe-reload
    local tmp_bad="/tmp/bad-routing.json"
    printf '{ "routing": INVALID_JSON }' > "${tmp_bad}"
    if ! /usr/local/bin/xray run -test -config "${XRAY_CONF_DIR}/00-base.json" -config "${tmp_bad}" >/dev/null 2>&1; then
        check_step "Негативный тест: повреждённый JSON блокируется проверкой xray run -test" "PASS"
    else
        check_step "Негативный тест: повреждённый JSON блокируется проверкой xray run -test" "FAIL"
    fi
    rm -f "${tmp_bad}"

    # 13. Firewall & ipset status check
    if ipset list smartdns_clients >/dev/null 2>&1 && iptables -t nat -C PREROUTING -j SMARTDNS_PREROUTING 2>/dev/null; then
        check_step "Цепочки Firewall (PREROUTING/INPUT/OUTPUT) и ipset активны" "PASS"
    else
        check_step "Цепочки Firewall (PREROUTING/INPUT/OUTPUT) и ipset активны" "FAIL"
    fi

    printf '==============================================================================\n'
    if [[ "${failures}" -eq 0 ]]; then
        printf 'РЕЗУЛЬТАТ: Все проверки успешно пройдены!\n'
        return 0
    else
        printf 'РЕЗУЛЬТАТ: Обнаружено ошибок: %d. Проверьте журналы в %s.\n' "${failures}" "${LOG_DIR}"
        return 1
    fi
}

# ------------------------------ Installation Report ---------------------------
generate_installation_report() {
    # shellcheck disable=SC1091
    source "${SETTINGS_FILE}"
    # shellcheck disable=SC1091
    source "${VERSIONS_FILE}"
    # shellcheck disable=SC1091
    source "${SECRETS_FILE}"
    # shellcheck disable=SC1091
    [[ -f "${STATE_DIR}/geohide-stats.env" ]] && source "${STATE_DIR}/geohide-stats.env"
    load_whitelist_sets

    local report_file="${LAUNCH_DIR}/smartdns-installation-report-${TIMESTAMP}.txt"
    local secret_report_file="${STATE_DIR}/credentials-${TIMESTAMP}.txt"
    local auth_ip_count
    auth_ip_count="$(ipset list smartdns_clients 2>/dev/null | awk '/Number of entries:/ {print $4}' || echo 0)"
    local dot_ip4_count
    dot_ip4_count="$(ipset list "${ACTIVE_DOT_SET_V4}" 2>/dev/null | awk '/Number of entries:/ {print $4}' || echo 0)"
    local dot_ip6_count
    dot_ip6_count="$(ipset list "${ACTIVE_DOT_SET_V6}" 2>/dev/null | awk '/Number of entries:/ {print $4}' || echo 0)"
    local dot_wl_banner="DISABLED"
    [[ "${DOT_WHITELIST_ENABLED:-false}" == "true" ]] && dot_wl_banner="ENABLED"

    cat > "${report_file}" <<EOF
================================================================================
     ИТОГОВЫЙ ОТЧЁТ УСТАНОВКИ UNIFIED SMARTDNS + SNI PROXY (STEALTH MODE)
================================================================================
1. ОБЩАЯ ИНФОРМАЦИЯ
   Дата установки            : ${INSTALL_DATE}
   Версия установщика        : ${INSTALLER_VERSION}
   Операционная система      : ${OS_PRETTY} (${CPU_ARCH}, ядро ${KERNEL_VER})
   Публичный IPv4            : ${SERVER_IPV4}
   Публичный IPv6            : ${SERVER_IPV6:-отсутствует}
   Выбранный DNS-движок      : ${DNS_ENGINE}
   Версия DNS-движка         : ${DNS_VERSION}
   Версия Xray-core          : ${XRAY_VERSION}
   Версия Nginx              : ${NGINX_VERSION}

2. ИСТОЧНИКИ И СОСТОЯНИЕ СПИСКОВ (OxiDNS & GeoHideDNS)
   OxiDNS repository         : ${OXIDNS_REPO}
   OxiDNS release            : ${DNS_VERSION}
   OxiDNS binary             : /usr/local/bin/oxidns
   GeoHideDNS repository     : ${GEOHIDE_REPO}
   GeoHideDNS source         : ${GEOHIDE_RAW_URL}
   Последнее обновление      : ${LAST_UPDATE:-неизвестно}
   Количество исходных домен.: ${RAW_DOMAIN_COUNT:-0}
   Количество итоговых домен.: ${FINAL_DOMAIN_COUNT:-0}
   EXCLUDE_GOOGLE_SYS        : ${EXCLUDE_GOOGLE_SYS}
   INCLUDE_XBOX_IPIFY        : ${INCLUDE_XBOX_IPIFY}
   Xray rules                : ${XRAY_RULES_STATUS:-VERIFIED_OK}

3. DNS, МАСКИРОВКА И ФИЛЬТРАЦИЯ
   Единый домен (Сайт + DoH) : https://${ROOT_DOMAIN}/resolve/[СКРЫТО_В_ФАЙЛЕ_СЕКРЕТОВ]
   Веб-авторизация Wi-Fi     : https://${ROOT_DOMAIN}/auth/[СКРЫТО_В_ФАЙЛЕ_СЕКРЕТОВ]
   DoT Hostname              : ${DOT_HOST} (порт 853/TCP)
   DNS Upstream              : Cloudflare (1.1.1.1), Google (8.8.8.8) по HTTPS
   Расписание обновлений     : 04:00 MSK (geosite.dat), 04:05 MSK (GeoHideDNS)

4. КОНТРОЛЬ ДОСТУПА DoT (TCP 853 WHITELIST)
   DoT IP-whitelist: ${dot_wl_banner}
   DOT_WHITELIST_ENABLED     : ${DOT_WHITELIST_ENABLED:-false}
   Режим whitelist           : ${DOT_WHITELIST_MODE:-shared} (${ACTIVE_DOT_SET_V4} / ${ACTIVE_DOT_SET_V6})
   Количество разрешённых IP : IPv4=${dot_ip4_count}, IPv6=${dot_ip6_count}
   TTL записей               : 86400 секунд
   Состояние firewall        : $(systemctl is-active smartdns-firewall) (${IPTABLES_BACKEND})
   Команды управления        :
     - ${SCRIPT_NAME} --switch-engine [oxidns|adguardhome]
     - ${SCRIPT_NAME} --whitelist-status
     - ${SCRIPT_NAME} --whitelist-toggle [on|off]
     - ${SCRIPT_NAME} --whitelist-mode [shared|separate]
     - ${SCRIPT_NAME} --whitelist-add IP
     - ${SCRIPT_NAME} --whitelist-remove IP
     - ${SCRIPT_NAME} --whitelist-flush
     - ${SCRIPT_NAME} --sync-ip
     - ${SCRIPT_NAME} --change-domain [NEW_DOMAIN]

5. XRAY TRANSPARENT SNI PROXY
   Статус службы             : $(systemctl is-active xray)
   Входящие (Inbounds)       : https-in (0.0.0.0:8444 dokodemo-door), dot-in (0.0.0.0:853)
   Исходящие (Outbounds)     : direct-v4 (UseIPv4), nginx-local (127.0.0.1:9444 PROXY protocol), dot-backend (127.0.0.1:8853), block
   Проксируемых доменов      : ${FINAL_DOMAIN_COUNT:-0}
   Автоперезагрузка правил   : $(systemctl is-active xray-reload.path)

6. NGINX И САЙТ-ЗАГЛУШКА STUDIO NORD
   Статус службы             : $(systemctl is-active nginx)
   Домен сайта Studio Nord   : https://${ROOT_DOMAIN}
   Внутренние TLS-порты      : 9443/TCP (DNAT), 127.0.0.1:9444/TCP (PROXY protocol от Xray)
   Сертификат TLS            : ${CERT_DIR}/fullchain.pem (SAN: ${ROOT_DOMAIN}, *.${ROOT_DOMAIN})

7. FIREWALL И IPSET
   Используемый backend      : ${IPTABLES_BACKEND} + UFW
   Публичные порты           : 80/TCP, 443/TCP, 853/TCP
   Закрытые внутренние порты : 8444, 9444, 8853, 5353, 8053, 3000
   Набор ipset               : smartdns_clients (TTL 86400s), авторизовано IP: ${auth_ip_count}
   Состояние защиты IPv6     : Активна (ip6tables + smartdns_clients6 + DNS NODATA для AAAA)
================================================================================
EOF
    chmod 0640 "${report_file}"

    cat > "${secret_report_file}" <<EOF
================================================================================
 СЕКРЕТНЫЕ ДАННЫЕ ПОДКЛЮЧЕНИЯ (ХРАНИТЬ В БЕЗОПАСНОМ МЕСТЕ, ПРАВА 0600)
================================================================================
Полный DoH URL (используется корневой домен без поддоменов):
  https://${ROOT_DOMAIN}/resolve/${DOH_PATH}

Секретная ссылка-закладка для быстрой авторизации нового Wi-Fi с телефона:
  https://${ROOT_DOMAIN}/auth/${DOH_PATH}

Хост DoT (для Android Private DNS / роутеров, порт 853/TCP):
  ${DOT_HOST}
EOF
    if [[ "${DNS_ENGINE}" == "adguardhome" ]]; then
        cat >> "${secret_report_file}" <<EOF

Учётные данные панели AdGuardHome (доступ только через SSH-туннель 127.0.0.1:8053):
  Логин             : ${AGH_ADMIN_USER:-admin}
  Временный пароль  : ${AGH_ADMIN_PASS:-см. мастер}
EOF
    fi
    chmod 0600 "${secret_report_file}"

    cat "${report_file}"
    printf '\nПубличный отчёт сохранён в: %s\n' "${report_file}"
    printf 'Секретные параметры сохранены в: %s (права 0600)\n' "${secret_report_file}"

    read -r -p "Показать секретные ссылки DoH и /auth/ прямо сейчас в терминале? [y/N]: " show_sec
    if [[ "${show_sec:-N}" =~ ^[Yy]$ ]]; then
        cat "${secret_report_file}"
    fi
}

run_regenerate_cover() {
    detect_environment
    if [[ ! -f "${SETTINGS_FILE}" ]]; then
        printf 'ОШИБКА: Файл настроек %s не найден. Сначала выполните --install.\n' "${SETTINGS_FILE}" >&2
        exit 1
    fi
    # shellcheck disable=SC1091
    source "${SETTINGS_FILE}"

    create_system_backup
    TRANSACTION_ACTIVE=1
    generate_procedural_cover_site "${WEB_ROOT}" "1"
    nginx -t && systemctl reload nginx
    run_test_suite
    TRANSACTION_ACTIVE=0
    log_info "installation.log" "Перегенерация уникального Cover Site успешно завершена."
}

# ------------------------------ Status / Update / Uninstall -------------------
run_status() {
    detect_environment
    printf '=== СТАТУС СЛУЖБ SMARTDNS + SNI PROXY ===\n'
    if [[ -f "${SETTINGS_FILE}" ]]; then
        printf '  %-26s : %s\n' "Активный DNS_ENGINE" "$(awk -F'"' '/^DNS_ENGINE=/ {print $2}' "${SETTINGS_FILE}" 2>/dev/null || echo unknown)"
    fi
    for svc in smartdns-firewall oxidns adguardhome xray xray-reload.path nginx doh-ipset-watcher dot-ipset-watcher geosite-update.timer geohide-update.timer; do
        if systemctl list-unit-files "${svc}*" >/dev/null 2>&1; then
            printf '  %-26s : %s\n' "${svc}" "$(systemctl is-active "${svc}" 2>/dev/null || echo inactive)"
        fi
    done
    if [[ -f "${SETTINGS_FILE}" ]]; then
        printf '\n'
        run_whitelist_status
    fi
}

run_update() {
    detect_environment
    if [[ ! -f "${SETTINGS_FILE}" ]]; then
        printf 'ОШИБКА: Система не установлена.\n' >&2
        exit 1
    fi
    # shellcheck disable=SC1091
    source "${SETTINGS_FILE}"
    DOH_HOST="${ROOT_DOMAIN}"
    sed -i "s/^DOH_HOST=.*/DOH_HOST=\"${ROOT_DOMAIN}\"/" "${SETTINGS_FILE}"
    # shellcheck disable=SC1091
    source "${SECRETS_FILE}"

    create_system_backup
    TRANSACTION_ACTIVE=1
    setup_users_and_dirs
    install_xray_binary
    if [[ "${DNS_ENGINE}" == "oxidns" ]]; then
        install_oxidns_binary
    else
        install_adguardhome_binary
    fi
    sync_cloudflare_dns_records "${SERVER_IPV4}" "${SERVER_IPV6:-}" || true
    install_domain_update_scripts
    configure_xray_base
    /usr/local/bin/update-geosite.sh
    /usr/local/bin/update-geohide-domains.sh
    configure_dns_engine
    generate_procedural_cover_site "${WEB_ROOT}" "0"
    configure_nginx
    install_ipset_watchers
    configure_firewall_and_sysctl
    record_installed_versions
    systemctl restart "${DNS_ENGINE}" xray nginx doh-ipset-watcher dot-ipset-watcher
    verify_dns_backend_isolated
    run_test_suite
    TRANSACTION_ACTIVE=0
    log_info "update.log" "Обновление всех компонентов, маскировки и списков успешно завершено."
}

run_uninstall() {
    read -r -p "ВНИМАНИЕ: Вы действительно хотите удалить стек SmartDNS + Xray? [y/N]: " confirm_uninst
    if [[ ! "${confirm_uninst:-N}" =~ ^[Yy]$ ]]; then
        exit 0
    fi
    for svc in doh-ipset-watcher dot-ipset-watcher xray-reload.path xray oxidns adguardhome geosite-update.timer geohide-update.timer smartdns-firewall; do
        systemctl disable --now "${svc}" 2>/dev/null || true
    done
    iptables -t nat -D PREROUTING -j SMARTDNS_PREROUTING 2>/dev/null || true
    iptables -t filter -D INPUT -j SMARTDNS_INPUT 2>/dev/null || true
    iptables -t filter -D OUTPUT -j SMARTDNS_OUTPUT 2>/dev/null || true
    ip6tables -t nat -D PREROUTING -j SMARTDNS6_PREROUTING 2>/dev/null || true
    ip6tables -t filter -D INPUT -j SMARTDNS6_INPUT 2>/dev/null || true
    ip6tables -t filter -D OUTPUT -j SMARTDNS6_OUTPUT 2>/dev/null || true
    printf 'Службы и правила маршрутизации отключены. Резервные копии сохранены в %s.\n' "${BACKUP_ROOT}"
}

# ------------------------------ Full Installation Flow ------------------------
run_install() {
    detect_environment
    validate_os_and_resources
    run_interactive_wizard

    init_logging
    log_info "installation.log" "Запуск транзакционной установки Unified SmartDNS + SNI Proxy (${INSTALLER_VERSION})..."

    setup_users_and_dirs
    create_system_backup
    TRANSACTION_ACTIVE=1

    save_persistent_settings
    install_system_packages
    install_xray_binary
    if [[ "${DNS_ENGINE}" == "oxidns" ]]; then
        install_oxidns_binary
    else
        install_adguardhome_binary
    fi
    record_installed_versions

    log_info "installation.log" "Синхронизация DNS-записей домена ${ROOT_DOMAIN} в Cloudflare..."
    if ! sync_cloudflare_dns_records "${SERVER_IPV4}" "${SERVER_IPV6:-}"; then
        log_warn "installation.log" "Не удалось автоматически обновить A/AAAA записи через Cloudflare API. Проверьте их в панели Cloudflare."
    fi

    issue_wildcard_certificate
    install_domain_update_scripts
    configure_xray_base
    /usr/local/bin/update-geosite.sh
    /usr/local/bin/update-geohide-domains.sh
    configure_dns_engine

    generate_procedural_cover_site "${WEB_ROOT}" "1"
    configure_nginx
    install_ipset_watchers
    configure_firewall_and_sysctl
    install_systemd_units

    verify_dns_backend_isolated
    run_test_suite
    TRANSACTION_ACTIVE=0
    generate_installation_report
}

# ------------------------------ CLI Argument Parser ---------------------------
print_help() {
    cat <<EOF
Использование: ${SCRIPT_NAME} [РЕЖИМ]

Доступные режимы работы:
  --help                           Вывести эту справку
  --preflight                      Проверка готовности сервера в режиме только чтения (без изменений)
  --install                        Полная интерактивная транзакционная установка стека
  --switch-engine [oxidns|adguardhome]
                                   Транзакционное переключение DNS backend с сохранением сертификатов и OxiDNS
  --sync-ip                        Автоматическое обновление IP сервера в локальных конфигах и Cloudflare DNS
  --change-domain [DOM]            Быстрая смена домена и перевыпуск сертификата без смены префикса DoT и путей
  --update                         Безопасное обновление компонентов и списков (с сохранением Cover Site)
  --regenerate-cover               Осознанная перегенерация уникального Cover Site с резервным копированием
  --status                         Просмотр текущего состояния служб, DNS_ENGINE и ipset
  --test                           Запуск комплексного набора функциональных и негативных тестов
  --backup                         Создание внеплановой резервной копии конфигураций и правил
  --rollback                       Аварийный откат к последней рабочей резервной копии
  --uninstall                      Корректное отключение служб и очистка правил перенаправления

Управление DoT IP-whitelist (TCP 853):
  --whitelist-status               Просмотр статуса DoT whitelist, списка разрешённых IPv4/IPv6 и их TTL
  --whitelist-toggle [on|off]      Включить, выключить или переключить (без аргумента) IP-whitelist для DoT (TCP 853)
  --whitelist-mode [shared|separate]
                                   Выбрать общий (smartdns_clients) или отдельный (dot_clients) набор IP для DoT
  --whitelist-add IP               Добавить одиночный IPv4 или IPv6 адрес в whitelist на 86400 секунд
  --whitelist-remove IP            Удалить одиночный IPv4 или IPv6 адрес из whitelist
  --whitelist-flush                Полностью очистить список разрешённых IP-адресов
EOF
}

main() {
    if [[ $# -eq 0 ]]; then
        print_help
        exit 0
    fi

    case "$1" in
        --help|-h)
            ACTION_MODE="help"
            print_help
            ;;
        --preflight)
            ACTION_MODE="preflight"
            check_root
            run_preflight
            ;;
        --install)
            ACTION_MODE="install"
            check_root
            acquire_lock
            run_install
            ;;
        --switch-engine)
            ACTION_MODE="switch-engine"
            check_root
            acquire_lock
            init_logging
            run_switch_engine "${2:-}"
            ;;
        --sync-ip)
            ACTION_MODE="sync-ip"
            check_root
            acquire_lock
            init_logging
            run_sync_ip
            ;;
        --change-domain)
            ACTION_MODE="change-domain"
            check_root
            acquire_lock
            init_logging
            run_change_domain "${2:-}"
            ;;
        --update)
            ACTION_MODE="update"
            check_root
            acquire_lock
            init_logging
            run_update
            ;;
        --regenerate-cover)
            ACTION_MODE="regenerate-cover"
            check_root
            acquire_lock
            init_logging
            run_regenerate_cover
            ;;
        --status)
            ACTION_MODE="status"
            check_root
            run_status
            ;;
        --test)
            ACTION_MODE="test"
            check_root
            run_test_suite
            ;;
        --backup)
            ACTION_MODE="backup"
            check_root
            acquire_lock
            init_logging
            create_system_backup
            ;;
        --rollback)
            ACTION_MODE="rollback"
            check_root
            acquire_lock
            init_logging
            perform_rollback "${2:-}"
            ;;
        --uninstall)
            ACTION_MODE="uninstall"
            check_root
            acquire_lock
            init_logging
            run_uninstall
            ;;
        --whitelist-status)
            ACTION_MODE="whitelist"
            check_root
            run_whitelist_status
            ;;
        --whitelist-toggle)
            ACTION_MODE="whitelist"
            check_root
            acquire_lock
            init_logging
            run_whitelist_toggle "${2:-toggle}"
            ;;
        --whitelist-mode)
            ACTION_MODE="whitelist"
            check_root
            acquire_lock
            init_logging
            run_whitelist_mode "${2:-}"
            ;;
        --whitelist-add)
            ACTION_MODE="whitelist"
            check_root
            acquire_lock
            init_logging
            run_whitelist_add "${2:-}"
            ;;
        --whitelist-remove)
            ACTION_MODE="whitelist"
            check_root
            acquire_lock
            init_logging
            run_whitelist_remove "${2:-}"
            ;;
        --whitelist-flush)
            ACTION_MODE="whitelist"
            check_root
            acquire_lock
            init_logging
            run_whitelist_flush
            ;;
        *)
            printf 'Неизвестный параметр: %s\n' "$1" >&2
            print_help
            exit 1
            ;;
    esac
}

main "$@"
