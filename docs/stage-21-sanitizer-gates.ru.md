# Этап 21 — обязательный отказ при ошибке C-санитайзера

## Подтверждённая ошибка критерия CI

C-команды задавали `-fsanitize=address,undefined`, но не отключали recovery для
UndefinedBehaviorSanitizer. Контрольная программа с volatile `INT_MAX + 1`
напечатала signed integer overflow и вернула exit=0. Задание, проверяющее только
exit status, могло остаться успешным при подобной диагностике. Это воспроизведение
критерия проверки на намеренно некорректной fixture, не найденный дефект шифра.

Добавлен `-fno-sanitize-recover=all` во все C ASan/UBSan команды native/fuzz и
в instrumented C callback integration. Новая `scripts/check-sanitizers.sh`
проверяет clean control, затем ожидаемые отказы signed overflow и heap UAF;
ненулевой exit без ожидаемой диагностики тоже считается ошибкой. Контрольные
логи не смешиваются с логами обычных тестов, core dumps отключены.
Состав verification record включает script и контрольный исходник.

## Проверки

- Тот же signed-overflow control с прежними флагами: exit=0; со строгими: exit=134.
- Реальные ASan/UBSan controls PASS на macOS и Linux aarch64/Clang 14.0.6.
- В slim Linux окружении отсутствие compiler-rt было обнаружено как ошибка
  линковки; после явной установки `libclang-rt-14-dev` controls PASS.
- Полный локальный `scripts/check.sh` со строгими флагами PASS: 42 Python,
  C ASan/UBSan/TSan, Rust/WASM, Go race, PHP/Swift и interop шести портов.
- Тесты verification records PASS, `git diff --check` PASS.

[Логи и SHA-256](audit/2026-10-19-sanitizer-gates/).
Повтор CI нового коммита проверяется отдельно. Стойкость 128/256 бит,
независимая внешняя экспертиза и инфраструктурные условия этим не подтверждаются.
