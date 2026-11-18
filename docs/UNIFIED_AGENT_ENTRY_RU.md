# Единый вход для агентов

Кандидат Hub предоставляет один контракт `ff-agent-entry-v1` через локальный HTTP, MCP stdio и CLI. Запросы всех трёх клиентов используют одну сессию задачи, один набор ресурсов и один журнал Hub. Настраивать провайдера в ядре для нового MCP или HTTP клиента не требуется.

## Выдача доступа

Запустите отдельный private runtime по [инструкции установки](PRIVATE_DESKTOP_DAILY_RU.md). Владелец локально выдаёт один ограниченный по времени bearer для `client_id`, `agent_id` и `task_id`. Секрет записывается только в указанный новый файл. Храните этот файл в каталоге с доступом только владельца и уполномоченного клиента.

```powershell
python tools/agent_entry.py issue --state-dir <hub-state> --credential-file <grant-file> --client local-mcp --agent work-agent --task demo-01 --ttl 3600 --scope private_browser --scope artifacts --scope locks
python runtime/bridge-v3/ff_hub.py --state-dir <hub-state> grant add --classes app_launch --agents work-agent --apps chrome.exe --ttl 1h
```

Для фонового GUI можно добавить `--scope private_app --app charmap` и локально разрешить `charmap.exe` тому же агенту в политике Hub. Доступная группа приложений указана в `issue --help`. В CLI полномочия отзываются командой `revoke --state-dir <hub-state> --grant-id <id>`. После отзыва либо истечения TTL сервер отклоняет следующий запрос. Уже допущенная операция может завершиться. Периодическая очистка после завершения активных операций закрывает ресурсы этой задачи.

## Подключение клиента

- HTTP. Отправляйте JSON через `POST http://127.0.0.1:<port>/agent/v1` с `Content-Type: application/json` и заголовком `Authorization: Bearer <grant>`. Начните с `{"op":"capabilities"}`. Endpoint слушает loopback, отвергает браузерный `Origin` и требует loopback `Host`. Для облачного клиента нужен отдельный доверенный транспорт до этого адреса.
- MCP stdio. Настройте запуск `python tools/agent_entry.py mcp --endpoint-file <hub-state>/endpoint.json --credential-file <grant-file>`. Инструмент `ff_agent_call` принимает поля запроса HTTP. Также можно передать фиксированный `--port`.
- CLI. Используйте `python tools/agent_entry.py call --endpoint-file <hub-state>/endpoint.json --credential-file <grant-file> --op capabilities`. Для аргументов используйте `--args-file request.json`, для сессии `--session-id`, для мутации `--key`.

1. `capabilities` возвращает реально выданные операции. `route_plan` с аргументом `surface: "browser"` или `surface: "app"` показывает допустимый маршрут и причины отказов.
2. `session_open` без аргументов возвращает `session_id`. Повторное открытие с тем же bearer восстанавливает тот же ID, в том числе после потери первого ответа. Для новой работы после завершения нужна новая задача.
3. Для private Chrome вызовите `private_browser` с `args: {"command":"open"}`, а затем `tabs`, `navigate`, `observe` и `read` с выданными `browser_id` и `tab_id`. Для файлов задачи доступны `task_file` с командами `put`, `read`, `list`. `put` принимает `name` и `content_base64`, максимум 1 MiB на файл и 4 MiB на задачу.
4. Для каждой мутации передайте постоянный `request_key` длиной 8–200 символов. При разрыве вызовите `request_status` с тем же ключом в `args`. Если состояние `unknown`, проверьте эффект отдельно. Клиент не повторяет операции автоматически.
5. В конце отправьте `task_cancel` со своим `session_id` и ключом. Проверьте `cleanup_verified`. Квитанция отмены доступна после закрытия задачи до истечения срока bearer.

## Доступность маршрутов

Для `private_browser` кандидат использует отдельный Chrome на приватном Windows Desktop и долговечное CDP-соединение. Windows Desktop разделяет пользователя и сеть с основным сеансом. Эта схема не изолирует сетевой трафик как VM. Вход выдавайте только доверенному клиенту с согласованным заданием.

Владелец управляет Chrome DevTools и нативными разрешениями штатными средствами. Существующий доверенный Hub RPC по-прежнему имеет отдельный маршрут Playwright Extension с проверкой совместимости. Scoped endpoint не открывает вкладки владельца и не передаёт CDP адрес. Установленное расширение или наличие программы ещё не подтверждает разрешённое подключение. FF Browser Companion имеет отдельный Native Messaging протокол для скачиваний.

Официальный API, CLI, COM и нативные инструменты агента могут работать автономно. Пока они не регистрируют ресурс и квитанцию в Hub, `route_plan` помечает их `UNMANAGED`. Persistent Playwright и owner extension для scoped endpoint помечены `UNAVAILABLE`. Скрытый UIA доступен только с выданным scope и местным разрешением на приложение. Видимый рабочий стол из этого интерфейса недоступен.

## Приёмка и поставка

```powershell
python -X utf8 -m unittest discover -s tests -p "test_agent_entry.py"
python -X utf8 tests/integration/agent_entry_smoke.py
```

Интеграционная проверка требует установленного Chrome и Python MCP SDK. Она создаёт отдельный Hub на случайном порту, проверяет реальный Chrome, Win32 UIA, изоляцию задач и завершение принадлежащих тесту процессов. Облачные A1/A4/A6, мобильные клиенты и нативная привязка к профилю владельца проверяются отдельными приёмками. Процедуру перехода действующих private задач см. в [инструкции скрытого runtime](PRIVATE_DESKTOP_DAILY_RU.md).
