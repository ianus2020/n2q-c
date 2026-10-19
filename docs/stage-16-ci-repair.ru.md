# Этап 16 — исправления по фактическому CI

Проверен CI [39281145770](https://github.com/ianus2020/n2q-c/actions/runs/39281145770)
для `f937866`: migration, anchor, cryptanalysis и fuzz PASS; native, web и
dependencies FAIL. Эти результаты заменяют прежний снимок «в очереди».

## Причины и изменения

1. Linux web дошёл до HTTPS-стенда, но не смог собрать C callback:
   `curl/curl.h: No such file or directory`. Установка `libcurl4-openssl-dev`
   теперь явно задана для этого задания; проверка реального C подписанта
   сохранена. В Linux anchor тот же callback уже прошёл.
2. Gitleaks нашёл одну строку в сохранённых метаданных: SHA-256 исходника
   `impl/n2q-c-ref/examples/migration_keys.rs`. Значение сверено с реальным
   файлом. Добавлено одно исключение commit/path/rule/line; правила и сканирование
   всей истории не отключены. RustSec для всех пяти lockfiles и npm: 0 уязвимостей.
3. macOS native: шесть startup timeout якоря и две ошибки TLS web. Отдельно
   воспроизведено ожидание `socket.getfqdn('127.0.0.1')` 35.005 с в Homebrew
   Python 3.14/OpenSSL 4.0.3. HTTPServer выполнял его до готовности сервера,
   превышая 10-секундный deadline. Loopback сервер теперь сохраняет числовое
   имя без reverse DNS. Тест запрещает DNS и проверяет успешный bind.
   Независимая причина двух ошибок issuer в CI пока не подтверждена:
   локальные strict TLS проверки проходят. Повтор GitHub нужен для проверки.

Проверка сертификатов/hostname/mTLS не ослаблена; тайм-ауты не увеличены.
В CI evidence добавлены версии SSL Python, OpenSSL CLI и хэш генератора PKI.
Никакие private PKI, ключи или рабочие данные в evidence не включены.

## Проверки

- Python 3.14.8 / OpenSSL 4.0.3 + LibreSSL 3.3.6 CLI: anchor 6 тестов PASS
  (9.756 с), HTTPS publication 4 PASS (2.106 с).
- До исправления в той же комбинации anchor: все 6 startup FAIL; web 37.148 с.
- После точечного исключения Gitleaks 8.30.1: 46 коммитов, 0 находок.
- Regression bind без DNS и тесты публичных verification records PASS.
- Полный native и повтор GitHub фиксируются в журнале после завершения.
- [Сохранённые логи и SHA-256](audit/2026-10-19-ci-repair/) включают CI FAIL,
  локальный startup FAIL до исправления и успешные повторные проверки.

Это этап исправления реализации и среды проверок. Production, реальные данные,
независимая внешняя криптоэкспертиза и стойкость авторского шифра им не подтверждаются.
