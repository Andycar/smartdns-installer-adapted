## Описание изменений / Summary of Changes

Кратко опишите суть вносимых изменений и причину их необходимости.
*Briefly describe the changes made and the motivation behind them.*

## Тип изменений / Type of Change

- [ ] Исправление ошибки / Bug fix
- [ ] Новая функциональность / New feature
- [ ] Локализация интерфейса (RU / EN) / Interface localization
- [ ] Документация или CI / Documentation or CI workflow

## Чек-лист перед отправкой / Pre-Submit Checklist

- [ ] Синтаксис проверен локально командой `bash -n smartdns-installer-v2.10.0-stealth.sh`
- [ ] Статический анализ пройден без предупреждений: `shellcheck -S warning -e SC1090,SC2034,SC2154 smartdns-installer-v2.10.0-stealth.sh`
- [ ] Новые пользовательские сообщения добавлены в оба словаря локализации (`MSG_RU` и `MSG_EN`)
- [ ] Изменения не нарушают транзакционный откат (`--rollback`) и правила firewall (`SMARTDNS_*`)
- [ ] В коде отсутствуют хардкод-токены, пароли и приватные домены
