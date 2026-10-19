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
| 12: локальный backend CoNe | 2d99cb1 + PKI fix 4864be0 | mTLS, SQLite WAL/FULL, C callback, concurrency/restart/rollback/network-failure tests PASS локально; первый native CI FAIL на PKI; SKI/AKI и duplicate extensions устранены, CI 39289459101 PASS |
| 13: локальный HTTPS-стенд и конфигурации | 0ec3a89 + cleanup 086afd4 | Versioned atomic releases, private test PKI, allowlist/headers/quota; TLS/C signer/Chromium PASS; Linux templates не запускались |
| 14: offline-миграция и PW recovery | c1d7cbe + validation 80595e0 | 10 Python + 2 Rust теста PASS; inventory, trusted-evidence recovery/rekey, private no-replace output, Argon2id new/restore и isolated legacy PW; реальных данных не переносили |
| 15: итог локальных проверок | 80595e0 + docs f937866 | Полный native PASS (6 портов), HTTPS browser PASS, strict SSL/LibreSSL compatibility PASS; первый снимок GitHub CI queued; актуальное подтверждение — этап 20; подробности stage-15-local-verification.ru.md |
| 16: исправления по фактическому CI | 7988f1e | Установлены libcurl headers для web, проверено точечное исключение source SHA-256; устранён reverse DNS startup delay, native локально PASS (39 Python + 6 портов); первый повтор CI 39287720266 выявил issuer validation; устранено этапом 18 |
| 17: общий TLS request deadline | f3b43bc | slow headers/saturation/recovery и handshake PASS; контроль на старом коде FAIL, 41 Python и новый HTTPS стенд/Chromium PASS |
| 18: конфигурация PKI и совместимость CLI | c556436 | Дубликаты CA расширений воспроизведены с OpenSSL 1.1.1w и устранены; strict chains, 6 anchor tests с legacy PKI, 42 Python и HTTPS/C signer PASS; CI 39289459101 все 7 PASS |
| 19: обязательные 7 CI checks | e1b66d1 | GitHub GET/PATCH/GET подтвердил strict + app_id=15368 для всех 7 jobs, остальные поля защиты сохранены; live stand restart/state/HTTPS/mTLS/Chromium PASS |
| 20: сохранённое подтверждение CI | source c556436 | CI 39289459101 — все 7 PASS; jobs/full log/dependency reports/SHA-256 сохранены, native включает 42 Python и 6-port interop |
| 21: строгий отказ C sanitizer gates | 682f325 | Воспроизведён UBSan report с exit=0 на fixture; fno-sanitize-recover + ASan/UBSan controls PASS macOS/Linux, полный native/42 Python/6 портов PASS; CI 39295178168 все 7 PASS |
| 22: новые fuzz targets и измеримые отчёты | ed175fe | 7 x 1000 smoke PASS, 958 modes / 976 convergent property cases; исходные хэши, corpora и failure controls сохранены; CI 39297156434 все 7 PASS |
| 23: независимые fuzz controls и большие смещения | 8f8b23a + evidence | 13 209 выполнений на 7 целях PASS, включая 1951 modes / 1162 convergent property cases; все 72 source hashes и corpus coordinates/capacities проверены; Linux offline |

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
