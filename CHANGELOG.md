# Changelog

## Unreleased — provider hostname profile / профиль имени хоста

- Added `--integrate-existing --no-authorization` to persistently allow all client IPs for managed target domains. Rerunning integration without the flag restores the default 24-hour authorization. Existing installations update only relay policy and connection information; failed relay activation restores the previous configuration/code.
- Добавлен флаг `--no-authorization` для режима интеграции: доступ к целевым доменам разрешается всем IP, настройка сохраняется после перезапуска. Запуск без флага возвращает авторизацию на 24 часа; перезапускается только реле.

- Added `--integrate-existing`: reuse the existing Xray REALITY listener and AdGuard DoH/DoT, add managed target-domain DNS rewrites and a UNIX-socket SNI relay with secret-link IP authorization for 24 hours. Back up configurations and roll back failed activation.
- Existing services keep their ports, REALITY client settings, routing and AdGuard TLS/filter configuration; only the fallback destination, managed rules and authorization location change. A refused stale UNIX socket can be removed after proving it has no listener.
- Expected fresh-install port conflicts now exit with code 2 without triggering the critical ERR trap. Added TLS parser, authorization/expiry, DNS/public-address, stale-socket and refusal regression coverage.
- Добавлен `--integrate-existing`: существующие Xray REALITY и AdGuard DoH/DoT сохраняются; добавляются правила DNS, SNI-реле и секретная авторизация IP на 24 часа. При сбое активации выполняется откат. Занятый порт при новой установке вызывает ожидаемый отказ с кодом 2 вместо критической ошибки.

- Added a separate installer for external provider DNS and an existing single-host Certbot certificate; the Cloudflare installer is preserved.
- Hostname/IP inputs come from environment variables or interactive prompts, are validated and saved for lifecycle commands and certificate renewal. No VPS-specific hostname or IP is built into the new script.
- Added read-only hostname checks, HTTP-01 challenge routing, a lineage-specific renewal hook, shared DoT IP authorization and protection against installing over existing services.
- Added bilingual hostname-profile messages, portable regression tests and an environment-variable setup guide.
- Добавлен отдельный установщик для DNS провайдера и существующего сертификата Certbot; исходный вариант Cloudflare сохранён. Имя хоста и IP вводятся пользователем, проверяются и сохраняются. Добавлены проверка без изменений, поддержка продления HTTP-01, защита существующих служб, сообщения RU/EN и тесты.
- Validation: Bash syntax and ShellCheck with the repository exclusions; portable tests and separate live DNS/certificate checks. Full-stack installation was not performed on the occupied VPS.

Все значимые изменения проекта **Unified SmartDNS + Transparent SNI Proxy Installer** документируются в этом файле.
Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/).

---

## [v2.10.0-stealth] — 2026-11-15

### Новые возможности (Added)
* **Двуязычный интерфейс командной строки (`RU / EN`):** добавлен интерактивный выбор языка при запуске (`1) Русский`, `2) English`) с централизованным словарём сообщений (`MSG_RU` / `MSG_EN`, 274 ключа) и поддержкой переменной окружения `SCRIPT_LANG` для неинтерактивного запуска (`cron` / `systemd` / `EOF`).
* **Горячее переключение DNS-движков (`--switch-engine`):** добавлена транзакционная смена активного DNS-движка между **OxiDNS** (Rust) и **AdGuardHome** (Go) на работающем сервере с сохранением TLS-сертификатов, секретного пути `DOH_PATH` и правил firewall.
* **Быстрая смена основного домена (`--change-domain`):** добавлен мастер замены `ROOT_DOMAIN` с автоматической синхронизацией A/AAAA-записей в Cloudflare, перевыпуском wildcard-сертификата Let's Encrypt и сохранением префикса `DOT_HOST` и пути `DOH_PATH`.
* **Автоматическая синхронизация IP сервера (`--sync-ip`):** добавлено определение нового публичного IPv4/IPv6 после миграции или смены IP на VPS с обновлением конфигов, цепочек `iptables`/`ip6tables` и DNS-записей Cloudflare.
* **Процедурный уникальный Cover Site (`--regenerate-cover`):** реализована генерация индивидуального статического сайта-заглушки (HTML5 + CSS3) без технических маркеров и утечек IP сервера.
* **Гибкое управление белым списком DoT (`--whitelist-*`):** добавлены команды `--whitelist-status`, `--whitelist-toggle`, `--whitelist-mode [shared|separate]`, `--whitelist-add`, `--whitelist-remove` и `--whitelist-flush` с TTL 24 часа (`86400s`).
* **Расширенный комплекс самодиагностики (`--test`):** добавлено 25 функциональных и негативных автотестов (проверка DoH RFC 8484, DoT SNI, `NODATA` для `AAAA` и `HTTPS/TYPE65`, блокировка невалидных JSON в Xray и защита внутренних портов).
* **Документация и инфраструктура репозитория:** добавлена полная английская документация (`README_EN.md`), раздел устранения неполадок (проверка ТСПУ/DPI, DoH/DoT и утечек IPv6), CI-проверка `ShellCheck`, шаблоны Issue/PR, `SECURITY.md`, `SUPPORT.md` и `CONTRIBUTING.md`.

### Исправления ошибок (Fixed)
* Устранено расхождение версии в заголовке скрипта (`# Version: 2.10.0-stealth` синхронизировано с `INSTALLER_VERSION="2.10.0-stealth"`).
* Исправлены предупреждения статического анализатора `ShellCheck` (`SC2155`) путём разделения объявления локальных переменных и присваивания результатов подстановки команд.
* Исправлена обработка закрытого потока ввода (`EOF` / `</dev/null`) при старте скрипта в режиме `set -e`, исключающая зависание при вызове из планировщиков задач.

### Изменения безопасности (Security)
* Все рабочие службы (`xray`, `oxidns`, `adguardhome`, `nginx`) переведены на запуск от выделенных непривилегированных системных учётных записей с минимальными правами (`NoNewPrivileges`, `ProtectSystem`).
* Добавлена обязательная проверка контрольных сумм `SHA-256` для загружаемых релизов `Xray-core`, `OxiDNS` и `AdGuardHome`.
* Закрыт внешний доступ ко всем внутренним портам (`5353`, `8053`, `8444`, `8853`, `9443`, `9444`); доступ к веб-панели AdGuardHome ограничен исключительно интерфейсом `127.0.0.1:8053` (через SSH-туннель).
* Запрещено добавление широких CIDR-подсетей через `--whitelist-add` (разрешены только одиночные IPv4/IPv6-адреса с автоматическим истечением TTL 86400 сек).

### Изменения совместимости и миграции (Compatibility & Upgrade Notes)
* **Для уже установленных серверов (v2.9.x -> v2.10.0-stealth):** обновление выполняется командой `sudo ./smartdns-installer-v2.10.0-stealth.sh --update`. Существующий `Cover Site`, `DOH_PATH`, `DOT_HOST` и выпущенные сертификаты Let's Encrypt сохраняются без изменений.
* **Для автоматизации (`cron` / `systemd`):** при обновлении скрипта на сервере добавьте переменную окружения `SCRIPT_LANG=ru` (или `SCRIPT_LANG=en`) и перенаправление `</dev/null` в существующие задачи.
* **Архитектуры CPU:** `OxiDNS` поддерживается только на `x86_64` (`amd64`); для серверов `aarch64` (`arm64`) используйте движок `AdGuardHome`.

### Известные ограничения (Known Limitations)
* Сервер должен иметь выделенный статический публичный IPv4-адрес; работа за NAT провайдера (CG-NAT) не поддерживается.
* В панели Cloudflare для всех DNS-записей домена (`@`, `*`, `DOT_HOST`) должен быть активен режим **DNS Only (серое облако)** — включение Cloudflare Proxy (оранжевое облако) нарушает работу SNI-прокси и DoT.
* На клиентских устройствах и роутерах необходимо отключать резервный DNS провайдера (`peerdns = 0`) и ECH/ESNI для целевых доменов, чтобы исключить утечку запросов мимо SmartDNS.
