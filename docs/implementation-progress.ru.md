# Исполнение этапов

Работа идёт в PR №1, ветка codex/security-hardening. Каждый этап сохраняется
отдельным коммитом; исправления обнаруженных CI-ошибок имеют отдельные коммиты.

| Этап | Коммит/проверка | Статус |
|---|---|---|
| 0: план и исходные риски | 4170eb7 | Сохранён |
| 1: границы FireLine | 11cf611, CI 39247989097 | native/web PASS |
| 2: C/Rust фаззинг | 5f00bf1 + исправление каталога 77a405f, CI 39249622756 | native/web/fuzz PASS; 5 x 2000 запусков без сбоев |
| 3: CoNe и контракты состояния | 0a5066f, CI 39250946073 | native/web/fuzz PASS; ASan/UBSan и ThreadSanitizer PASS |
| 4: KDF, ресурсы и ключи | 0f1c442, CI 39252663701 | native/web/fuzz PASS; Argon2id RFC vector и lockfiles PASS |
| 5: потоковые файловые API | f492029, CI 39253676632 | native/web/fuzz PASS; short IO, staging cleanup, in-place и шесть портов PASS |
| 6: фронтенд и комплект JS/WASM | c244dbf + test-header fix cca0d1f, CI 39254989733 | native/web/fuzz PASS; дедлайны, crash и mismatched assets PASS |
| 7: C init, зависимости и evidence | 91df2bc + точечные KAT exceptions 6d5fd11, CI 39256779040 | native/web/fuzz/dependencies PASS; RustSec/npm 0, 35 коммитов проверены Gitleaks |
| 8: доступ и настройки репозитория | b85131c | GitHub private=true, main protected=true; локальная ветка обновлена, почасовые отчёты ACTIVE |
| 9: инструменты дополнительного криптоанализа | 0e7a594 | Полный перебор компонентов, QP-320/640, SAT, измерения и отдельное задание CI; отчёт — этап 11 |
| 10: ошибки, найденные дополнительной проверкой | 11b763c | Convergent key boundary и C capacities/overflow, сравнение commitment, методология; CI 39272081407 все 5 заданий PASS |
| 11: закрытый отчёт и evidence криптоанализа | 873df5e | 11 семейств; 40 784 roundtrip, 662 648 отклонённых изменений, 80 000 подделок, 1,6 млн timing; CI 39274707825 все 5 PASS; сырые данные/модели/логи сохранены |
| 12: локальный backend CoNe | 2d99cb1 + PKI fix 4864be0 | mTLS, SQLite WAL/FULL, C callback, concurrency/restart/rollback/network-failure tests PASS локально; первый native CI FAIL на PKI, причина воспроизведена/исправлена, повтор в очереди |
| 13: локальный HTTPS-стенд и конфигурации | 0ec3a89 + cleanup 086afd4 | Versioned atomic releases, private test PKI, allowlist/headers/quota; TLS/C signer/Chromium PASS; Linux templates не запускались |
| 14: offline-миграция и PW recovery | c1d7cbe + validation 80595e0 | 10 Python + 2 Rust теста PASS; inventory, trusted-evidence recovery/rekey, private no-replace output, Argon2id new/restore и isolated legacy PW; реальных данных не переносили |
| 15: итог локальных проверок | 80595e0 + docs f937866 | Полный native PASS (6 портов), HTTPS browser PASS, strict SSL/LibreSSL compatibility PASS; последний GitHub CI queued, не объявлен успешным; подробности stage-15-local-verification.ru.md |
| 16: исправления по фактическому CI | 7988f1e | Установлены libcurl headers для web, проверено точечное исключение source SHA-256; устранён reverse DNS startup delay, native локально PASS (39 Python + 6 портов); повтор CI 39287720266 всё ещё выявляет issuer validation на macOS |
| 17: общий TLS request deadline | отдельный коммит этого этапа | slow headers/saturation/recovery и handshake PASS; контроль на старом коде FAIL, 41 Python и новый HTTPS стенд/Chromium PASS |

На этапах 0–7 планировщик отклонял создание отчётов, локальная файловая система
была read-only. После предоставления доступа 19.10.2026 настроена активная
почасовая автоматизация n2q, локальная ветка обновлена fast-forward до 6d5fd11.
Изменения настроек и их проверка записаны в [этапе 8](stage-8-repository-access.ru.md).

Внешний монотонный якорь CoNe, физические испытания питания/устройств и независимая
криптографическая экспертиза не считаются выполненными тестами библиотеки.

12:45 UTC / 15:45 Israel: первый ручной часовой отчёт отправлен в чат.
12:52 UTC: GitHub API показал visibility=public и main protected=false.
Первоначальный браузерный доступ к настройкам был отклонён. После разрешения
пользователя и открытия нового доступа GitHub CLI выполнил смену видимости:
13:10 UTC API подтвердил private=true. Затем main protected=true подтверждена
отдельным GET; обязательны PR и четыре успешных задания GitHub Actions.
