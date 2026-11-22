# Claude Desktop / MSIX: проверенный блокер фонового запуска (2026-11-17)

## Цель
Автономно открыть **Claude Desktop**, его режим Code и затем выбрать Fable 5.2 / Medium, не используя Claude CLI, не трогая браузер другого агента и не перехватывая физический фокус.

## Факты, проверенные на машине владельца
- Установлен пакет `Claude_5.11492.5.0_x64__pzs8sxrjxfjjc`.
- Manifest: `Application Id=Claude`, `Executable=app\Claude.exe`, `EntryPoint=Windows.FullTrustApplication`.
- Зарегистрированный обработчик `claude://` запускает пакетный `app\Claude.exe -- "%1"`.
- На момент проверки `Claude.exe` не работал. Действующие экземпляры Bridge и Chrome не останавливались.
- Live Bridge v3 `computer_use.hidden_start` запускает приватный Win32 desktop, однако `hidden_request.launch_app app=claude` возвращает `HIDDEN_APP_UNSUPPORTED`.
- Отдельная изолированная проба с Windows `CreateDesktopW` и `CreateProcessW`, явным `STARTUPINFO.lpDesktop=winsta0\FFBridge-Agent-...`, `CREATE_SUSPENDED` и запуском установленного EXE вернула Win32 `ERROR_ACCESS_DENIED (5)` **до создания дочернего процесса**. Рабочий стол теста был закрыт. Это не доказывает, что все способы MSIX-активации невозможны.
- После пробы `Claude.exe` отсутствует в Win32_Process; запуск не оставил GUI-окна.
- Нельзя запускать `explorer.exe shell:AppsFolder` / `IApplicationActivationManager` наугад: контракт этих средств не гарантирует, что окно окажется на приватном рабочем столе. Возможно вмешательство в пользовательский foreground.

## Официальный поддерживаемый путь подготовки Code-сессии
Документация Anthropic https://support.claude.com/en/articles/14729294-open-claude-desktop-with-a-link

`claude://code/new?q=<percent-encoded-text>` открывает Claude Desktop в режиме Code и предзаполняет prompt (до ~14k символов). `folder=<encoded-absolute-path>` требует обязательного подтверждения каталога. Параметров `model` и `effort` в этом контракте нет. URI не отправляет prompt самостоятельно.

## Архитектурный следующий шаг
Нужен **выделенный MSIX full-trust adapter**: исследовать официальный AUMID-брокер/процесс запуска и независимо доказать принадлежность нового HWND приватному desktop (не только PID) без активации `winsta0\default`. Сначала испытать на безопасном packaged тестовом приложении, с наблюдением foreground и fail-closed при любом нарушении, затем на Claude. Не отключать ACL, не копировать пакетный EXE и не подменять Desktop CLI. После доказанного фонового запуска подключить UIA/WebView/Electron маршруты для Code, выбора модели и effort, ввода/отправки с проверкой результата. Кандидат держать за выключенным feature flag. При невозможности такого запуска честно возвращать `HIDDEN_MSIX_LAUNCH_UNPROVEN`, а не переключаться на видимый GUI.

## Статус
**NOT READY** для автоматической отправки в Claude Desktop. Проверены наличие официального deep link и конкретная неудача direct hidden MSIX CreateProcess. Ни Fable, ни модельный режим не выбирались и запрос не отправлялся. Боевой runtime не менялся.


## 17 ноября: проверенный маршрут в feature-ветке

Прямая попытка CreateProcessW для WindowsApps/.../Claude.exe возвращала
ERROR_ACCESS_DENIED (5). Штатный AppExecutionAlias claude-desktop.exe,
напротив, успешно создаёт пакетный процесс и окно Chrome_WidgetWin_1
на приватном desktop с STARTUPINFO.lpDesktop до исполнения, без ShellExecute.
Это не произвольный MSIX-launcher: доступен только app=claude и только
при отсутствии любого ранее запущенного Claude.exe.

Первый сквозной тест обнаружил реальную утечку: упакованный процесс оставался
после прекращения hidden worker. Исправлено: теперь MSIX alias создаётся в
состоянии CREATE_SUSPENDED, до запуска прикрепляется к dedicated JobObject
(KILL_ON_JOB_CLOSE), и лишь затем возобновляется. Повторный live-тест
подтвердил исчезновение собственного PID после остановки worker.

Флаг --force-renderer-accessibility=complete дал доступ к Electron UIA.
После загрузки UIA нашёл Code (RadioButton, selected:true) и кнопку
Модель: Fable 5.2 Средний. Проверено отсутствие переключения
пользовательского foreground при запуске и наблюдении. Основной Chrome
не использовался. Отправка промпта НЕ выполнялась.

Проверки: tests/integration/claude_desktop_private_smoke.py --run --observe
и tests/integration/claude_desktop_code_smoke.py --run. Тесты запускают
только свой скрытый экземпляр и не отправляют сообщения. Для релиза
требуется полный набор регрессий и проверка release parity. Боевой Bridge
остаётся без изменений.


## Проверка Code deep-link и устранение MSAA сбоя

В подготовленной feature-ветке разрешён только URI вида
claude://code/new?q=<encoded-prompt>&folder=<absolute-existing-directory>
без произвольных URI схем и дополнительных параметров. Это запуск именно
пакетного Claude Desktop через AppExecutionAlias, а не Claude Code CLI.
Штатный диалог доверия к рабочей папке не отключается. Его подтверждают
UI Automation только после независимого чтения точного пути.

В реальном тесте диалог показывал
каталог рабочего checkout этой ветки.
Ранее UIA Invoke завершался ошибкой NO_FOCUS_raw-msaa: MSAA traversal limit
до вызова кнопки. Изменён cua_native_uia3_sidecar.cs: при ограниченном
MSAA обходе без отправки действия допускается выбор непосредственного
UIA InvokePattern после повторной проверки пути/runtime ID с выключенным
AutoSetFocus. Ограничения обхода не повышены.

После устранения ошибки действие вернуло STALE_TARGET в фазе проверки:
диалог исчез, и исходный элемент больше не существует. Это НЕ является
безусловным успехом RPC, однако независимое повторное UIA-наблюдение
показало точный каталог, предварительно заполненный тестовый промпт,
кнопку «Отправить» и модель «Fable 5.2 Средний». Таким образом,
переход в композер подтверждён без отправки сообщения и без повторного
нажатия кнопки доверия. Фокус пользователя не изменился.

Для настоящего запуска Fable требуется долговременный приватный worker.
Завершение тестового worker приводит к остановке принадлежащей ему
MSIX-сессии; отправлять запрос из одноразового smoke бессмысленно.
