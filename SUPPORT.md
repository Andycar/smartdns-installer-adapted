# Поддержка и диагностика / Support & Diagnostics

## Перед обращением за помощью

1. Изучите раздел **[9. Устранение неполадок (Troubleshooting)](README.md#9-устранение-неполадок-troubleshooting)** в документации (`README.md` / `README_EN.md`).
2. Запустите встроенный комплекс из 25 автотестов на сервере:

    sudo ./smartdns-installer-v2.10.0-stealth.sh --test

3. Проверьте состояние служб и белого списка IP:

    sudo ./smartdns-installer-v2.10.0-stealth.sh --status
    sudo ./smartdns-installer-v2.10.0-stealth.sh --whitelist-status

## Куда обращаться

* **Ошибки и сбои установки:** создайте обращение через форму **[Ошибка / Bug Report](https://github.com/EvgenyElizarenko/smartdns-installer/issues/new?template=bug_report.yml)**, приложив вывод `--test` и фрагмент журнала из `/var/log/oxidns-installer/`.
* **Идеи и предложения по улучшению:** используйте форму **[Предложение / Feature Request](https://github.com/EvgenyElizarenko/smartdns-installer/issues/new?template=feature_request.yml)**.

> **Важно:** перед публикацией логов обязательно удалите свой **Cloudflare API Token**, 48-символьный секретный путь **DOH_PATH** и реальное доменное имя.
