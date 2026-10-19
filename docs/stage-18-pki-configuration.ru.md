# Этап 18 — изоляция конфигурации тестовой PKI

## Подтверждённая причина native CI FAIL

Повтор [39287720266](https://github.com/ianus2020/n2q-c/actions/runs/39287720266)
для `7988f1e`: шесть заданий PASS; native FAIL. Evidence показывает OpenSSL CLI
1.1.1w и Python 3.14.7 / OpenSSL 3.6.4. После устранения DNS timeout отчёт явно
показал `unable to get local issuer certificate` при проверке web и anchor.

Старый генератор воспроизведён в изолированном Debian bullseye container с
OpenSSL 1.1.1w. В CA появились по два Basic Constraints и Subject Key Identifier:
`req -x509 -addext` дописывал их к `x509_extensions` системного openssl.cnf.
OpenSSL 1.1.1w и современный OpenSSL 4.0.3 отклонили такую цепочку (error 20).
Публичное описание сертификата и логи сохранены; private keys не включены.
Container был удалён, внешние порты не открывались.

## Изменение

Генератор передаёт отдельный полный `ca.cnf` с одним набором CA расширений,
явными SKI/AKI и своим DN. Тот же config используется для CSR; leaf расширения
берутся из отдельных явных extfiles. На ambient CA/CSR settings он не полагается.
После создания корня и каждого leaf запускается strict verification с CAfile и
правильным purpose: serverAuth/clientAuth. Ошибки команды включают диагностический
stderr; приватные ключи не выводятся. Cert/hostname/mTLS проверки не отключены.

## Проверки

- Воспроизведение старого генератора на OpenSSL 1.1.1w: ожидаемый FAIL error 20.
- Исправленный генератор на том же CLI: strict CA/server/client проверки PASS.
- С сертификатами, созданными именно 1.1.1w, все шесть anchor integration tests
  на Python 3.14.8/OpenSSL 4.0.3 и фактический C/libcurl callback PASS (8.640 с).
- Регрессия с посторонним OPENSSL_CONF, добавляющим nameConstraints: новый
  генератор изолирован и цепочка PASS. Прежняя реализация ожидаемо FAIL теста.
- Та же регрессия PASS с OpenSSL 4 CLI и LibreSSL 3.3.6 CLI.
- Все 42 Python-теста PASS (28.804 с), включая offline Rust key CLI.
- Отдельный новый синтетический стенд: HTTPS + фактический mTLS C signer PASS.
  Оба процесса завершены, прежние рабочие счётчики не сбрасывались.

[Логи, публичные метаданные и SHA-256](audit/2026-10-19-pki-configuration/).
Повтор всего GitHub CI для коммита этого этапа проверяется отдельно; локальные
результаты не объявляются успехом macOS CI заранее.

Контрольный Docker image: debian:bullseye-slim,
`sha256:e5b6442dd2e9684cf5e87d8338b5968f3b348636fc0be6d7850a381e3731a2bd`.
Реальные ключи/архивы, production и независимая внешняя криптоэкспертиза
не входят в результат этого технического исправления.
