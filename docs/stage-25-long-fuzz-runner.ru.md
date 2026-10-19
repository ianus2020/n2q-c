# Этап 25 — управление длительной серией фаззинга

Подтверждена ошибка runner этапа 24: SIGTERM завершал родительский Python
с кодом −15, summary оставался running, а wrapper и его дочерний процесс
продолжали работу. Воспроизведение использовало только контролируемые fixture
процессы; после наблюдения тест сам остановил свою process group. Это ошибка
управления тестами, а не найденный криптографический дефект.

## Исправления

- `fuzz-campaign.py` атомарно сохраняет summary после смены цели, результата
  и по мере поступления новых строк лога. В промежуточном отчёте статус running;
  успешное завершение подтверждается только после выхода процесса и всех проверок.
- SIGINT/SIGTERM/SIGHUP приводят к статусу interrupted и коду 130. Runner
  останавливает всю process group, через 5 секунд применяет SIGKILL при необходимости,
  завершает watchdog и освобождает обработчики сигналов. Сигнал при создании
  процесса откладывается до готовности cleanup.
- Общий child-process deadline охватывает shell, сборку и все семь targets:
  по умолчанию 600 + 7 × (seconds_per_target + 5) секунд, override —
  `--wall-seconds`. Превышение даёт timed_out / 124, даже если wrapper успел
  завершиться с кодом 0, оставив потомка с открытым stdout.
- `fuzz-series.py` последовательно запускает уникальные seed, проверяет
  неизменность source inputs между кампаниями и останавливается при первом
  failed/interrupted/timed_out. series.json содержит план, PID и состояние
  каждой кампании. Успешна только полностью завершённая серия.
- Корпус передаётся от предыдущего seed; его начальный/конечный архив сохраняется
  отдельно в каждой кампании. Это warm start, а не независимые испытания.
- CI verification manifest теперь включает оба runner и их regression tests.

Пример длительного запуска:

```sh
CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/audit/target \
  N2Q_SOURCE_COMMIT=<полный SHA проверяемого исходника> \
  python3 scripts/fuzz-series.py --output /audit/long \
    --seeds 20261019 20261020 20261021 --runs 1000000000 --seconds 600
```

## Подтверждения

Восемь новых integration controls проверяют SIGTERM/process-group cleanup,
принудительный deadline, exited wrapper с живым потомком, приватные/полные
отчёты, diagnostic/missing target/source-change failure, полную успешную серию,
остановку на неуспешном seed и прерывание серии. Старый SIGTERM control FAIL;
исправленный runner — 8/8 PASS на macOS и Linux. На macOS все 50 Python tests PASS.
Минимальному Debian image дополнительно понадобился procps для наблюдения за
fixture-процессами; первая проверка без ps не засчитана успешной.

Настоящие C/Rust targets, ASan/UBSan, два seed, запрос 1000 / 20 с на цель:

| Seed | Фактические выполнения | Modes property sets | Convergent property sets |
|---|---:|---:|---:|
| 20261019 | 7536 | 1511 | 957 |
| 20261020 | 6987 | 992 | 967 |

Итого 14 523, все семь целей/8 modes/2 convergent profiles PASS, диагностик нет.
Первый modes target выполнил 1536 вместо 1000: загрузка/инициализация seed corpus
может превысить малый run request. Второй convergent остановился по времени на
987. Property sets входят в executions; к общему числу их не прибавляют.

Precommit snapshot имеет synthetic Git SHA; все 74 source hashes сверены с
рабочим деревом перед коммитом. [Evidence](audit/2026-10-19-long-runner/) содержит
старое воспроизведение, логи controls/50 Python, обе кампании/corpora и SHA256SUMS.
Следующий этап запускает длительную серию из зафиксированного коммита; этот
короткий прогон не считается завершённым многочасовым тестированием.
