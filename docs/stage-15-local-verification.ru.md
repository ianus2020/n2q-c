# Этап 15 — итог локальных работ и сохранённые проверки

Проверяемый код: `80595e058fcf62138af8489d03c5e71eea68d0fc`.
Репозиторий private, работа в draft PR №1. Выполнены согласованные локальные
этапы: закрытый дополнительный криптоанализ, исправления, backend якоря CoNe,
HTTPS-стенд/конфигурации и инструменты offline-миграции.

## Результаты

- [Закрытый криптографический отчёт](cryptographic-audit-2026-10-19.ru.md):
  11 семейств экспериментов, исходные измерения/SAT-модели/хэши. Исправлены
  convergent key boundary, heap overflow C и сравнение commitment.
- [CoNe backend](../tools/anchor/README.md): реальный mTLS C callback,
  транзакционный сохраняемый счётчик, concurrency, restart, rollback подписанта,
  неопределённый сетевой результат и tenant binding проверены локально.
- [HTTPS-стенд](../tools/local_stand/README.md): запущен локально на
  `https://localhost:9443/`, anchor — `localhost:9444`. Только публичный
  signing fixture, тестовая PKI и синтетические данные. Private state/PKI
  лежат в ignored `.local-stand/`; в Git и evidence их нет.
- [Offline migration](../tools/migration/README.md): explicit v1 recovery/v2
  rekey, trusted hashes/length, no-replace output, read-back, Argon2id new/restore
  и ограниченное изолированное legacy PW recovery. Реальных данных не переносили.

## Локальная проверка

`scripts/check.sh` завершён с exit code 0 после добавления отсутствовавших Go/PHP.
Пройдены 37 Python-тестов, C ASan/UBSan/TSan, Rust, WASM bindings, Go race,
PHP/Swift и межъязыковой обмен файлами между всеми шестью портами. Это устранило
прежнюю локальную блокировку отсутствующими инструментами. Версии: Go 1.27.2,
PHP 8.5.11, Rust 1.96.1; CI по-прежнему задаёт свою Go 1.26.x.

После финального уточнения типа manifest version отдельно пройдены четыре
теста HTTPS/publication, включая quota и сохранение current при ошибке.
Полные браузерные сценарии пройдены по HTTPS с явным флагом test CA.
Клиенты Python/C отдельно проверяют сертификаты и hostname без обхода.
Управляемое завершение supervisor по SIGTERM закрыло оба дочерних порта.
Миграция: 10 Python + 2 Rust теста PASS; legacy-векторы сверены с исходным кодом
771c1a5. Реальный record >64 КиБ разбит на bounded v2 records после явного
разрешения его лимита; проверен concurrent empty destination/no-replace.

Сохранены [метаданные/хэши](audit/2026-10-19-local/verification.json) и
[логи](audit/2026-10-19-local/), включая первый отказ CI этапа 12.
SKI/AKI ошибка воспроизведена отдельно: исходный генератор + LibreSSL 3.3.6
и strict OpenSSL 3.5.9 дают `Missing Authority Key Identifier`. Генератор явно
добавляет идентификаторы; шесть тестов новой версии в этой комбинации PASS.
Проверка сертификатов осталась строгой.

## GitHub CI на момент записи

Последний полностью успешный CI до новых сервисных этапов:
[39274707825](https://github.com/ianus2020/n2q-c/actions/runs/39274707825),
`873df5e`, пять заданий PASS. На первом этапе 12 Linux anchor PASS,
macOS native FAIL из-за описанной test PKI; исправление сохранено отдельно.

Повторные запуски новых ревизий остаются в очереди GitHub. Для `80595e0`:
[39280524733](https://github.com/ianus2020/n2q-c/actions/runs/39280524733), queued.
Ожидаются семь заданий: native, web, fuzz, dependencies, cryptanalysis, anchor,
migration. Успех этого CI не заявлен. Почасовая автоматизация `n2q` ACTIVE и
проверяет текущий PR/head, поэтому последующие результаты нужно сверять с ней
и журналом, а не считать этот снимок вечным текущим статусом.

## Границы завершения

Локальная реализация и испытания не подтверждают 128/256 бит стойкости,
независимую внешнюю экспертизу, отдельный от rollback подписанта эксплуатационный
домен якоря, реальные power-loss/backup-restore испытания или миграцию реального
архива. Linux systemd файлы — подготовленные шаблоны, не выполненное развёртывание.
Внешнюю экспертизу можно организовать конфиденциально; публикация исходников
и результатов требует отдельного решения владельца.
