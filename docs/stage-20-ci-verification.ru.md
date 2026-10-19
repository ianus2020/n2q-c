# Этап 20 — подтверждённый результат всех проверок CI

Проверенный исходный код: `c5564365002b9675c17e6f8c61ac219d35f7bc48`.
GitHub [39289459101](https://github.com/ianus2020/n2q-c/actions/runs/39289459101):
status completed, conclusion success, все семь jobs PASS.

| Задание | Результат |
|---|---|
| native / macOS 15 | PASS: 42 Python-теста, C ASan/UBSan/TSan, Rust/WASM bindings, Go race, PHP/Swift, файловая матрица всех шести портов |
| web / Ubuntu 24.04 | PASS: WASM build, обычный host, новый HTTPS/mTLS стенд, versioned releases и Chromium security scenarios |
| fuzz | PASS: C/Rust smoke по пяти целям с заданными бюджетами |
| dependencies | PASS: пять Cargo.lock / cargo-audit, npm audit и Gitleaks history |
| cryptanalysis | PASS: exact components, fresh bounded experiments и перепроверка архивной арифметики |
| anchor | PASS: реальный C/libcurl callback, strict mTLS, сохранение/гонки/rollback/сетевые отказы |
| migration | PASS: Rust key CLI и синтетические offline migration/recovery тесты |

В native реально использовались Python 3.14.7 / OpenSSL 3.6.4 и CLI OpenSSL
1.1.1w — та же комбинация, которая ранее давала issuer failure. Это подтвердило
исправление изоляции CA extensions в CI. В пяти cargo-audit отчётах и npm audit
0 известных уязвимостей; Gitleaks 0 находок после точечно проверенных исключений.

Сохранены [полный лог, jobs, отчёты dependencies и SHA-256](audit/2026-10-19-ci-success/).
Результаты относятся к указанному source commit; следующие commits документации
проходят собственный CI. Статус latest head дополнительно проверяется в GitHub.

## Выполненная работа этого продолжения

- `7988f1e`: libcurl headers в web CI, source-hash exception и устранение
  неограниченного reverse DNS до готовности локального сервера.
- `f3b43bc`: общий deadline TLS-запроса и slow-header/saturation/recovery
  регрессии с контролем на прежней реализации.
- `c556436`: независимая от ambient openssl.cnf конфигурация test PKI,
  strict verification и регрессия посторонних CA constraints.
- `e1b66d1`: все семь CI jobs обязательны для main и привязаны к GitHub Actions.

Локально также пройдены 42 Python-теста, legacy CLI → современный SSL с шестью
реальными C/mTLS тестами и full browser HTTPS. Рабочая `.local-stand` запущена
с исправленным кодом; логические counters и журнал сохранены при перезапуске.
Тестовые временные PKI, использованные для воспроизведения, удалены.

Репозиторий private, PR №1 draft. Hourly automation n2q ACTIVE. Независимая
внешняя криптоэкспертиза, эксплуатационный off-host monotonic backend CoNe,
миграция настоящих данных и физические/инфраструктурные испытания остаются
открытыми. Выполненные тесты не доказывают 128/256 бит стойкости.
