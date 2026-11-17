# Подключение агентов к общему Hub

`ff_hub_mcp.py` — локальный MCP stdio-вход в существующий Hub. Один инструмент
`hub` даёт одинаковые операции Codex, Claude Code/Desktop, Antigravity/Gemini и
OpenCode. Адаптер не запускает модель, не включает feature-флаг и не выдаёт разрешения.
Работа идёт с правами текущего пользователя Windows, без новой VM или sandbox.

## Подключение

Перед изменением общей конфигурации сохраните её резервную копию. Добавьте сервер
`ff-universal-hub`, сохранив остальные записи. Для каждого клиента задайте своё
`--agent`: например, `codex`, `claude-code`, `claude-desktop`, `antigravity`,
`gemini-cli`, `opencode`.

```json
{
  "command": "<python executable>",
  "args": ["<runtime>/ff_hub_mcp.py", "--state-dir", "<Bridge root>/state/hub", "--agent", "claude-code"]
}
```

Codex использует `[mcp_servers.ff-universal-hub]` в пользовательском `config.toml`;
такую запись добавляет `codex mcp add`. Claude Code — `claude mcp add --scope user`,
Desktop — `mcpServers` в `claude_desktop_config.json`. Antigravity CLI читает
`mcpServers` в `~/.gemini/config/mcp_config.json`; Gemini CLI — в
`~/.gemini/settings.json`. OpenCode 1.x использует `mcp.<name>` с
`type:"local", command:[<python>, <adapter>, ...]`; в 2.x структура изменилась на
`mcp.servers.<name>`. Проверяйте установленную версию и её валидатор.

Официальные контракты:
[Codex MCP](https://developers.openai.com/codex/mcp/),
[Claude Code MCP](https://code.claude.com/docs/en/mcp),
[Antigravity MCP](https://antigravity.google/docs/mcp?tab=cli),
[Gemini CLI MCP](https://geminicli.com/docs/tools/mcp-server/),
[OpenCode MCP](https://opencode.ai/docs/mcp-servers).

`codex mcp list`, `claude mcp list`, `agy mcp list` и `opencode mcp list`
проверяют конфигурацию/соединение. Обнаружение инструмента не доказывает, что
модель авторизована или выполнила задачу. Уже открытый Desktop/IDE может потребовать
перезагрузки списка MCP либо нового чата; не прерывайте ради этого чужую работу.
Cursor Agent использует `~/.cursor/mcp.json`; `agent mcp list-tools ff-universal-hub`
проверяет реальное обнаружение `hub` без запуска модели. Наличие Pro/другой
подписки не доказывает остаток включённого usage или отсутствие платных overages.

Ранее настроенные серверы и встроенные shell/browser-инструменты клиента
сохраняются. Они могут выполнять действия напрямую, вне Hub; автоматической
подмены всех инструментов клиента нет. Для общей координации агент выбирает
`ff-universal-hub`. `hub_status` показывает зарегистрированные в Hub задачи,
а не каждый процесс или стороннюю задачу на компьютере.

## Одна задача

Вызовы инструмента `hub`:

1. `{op:"capabilities"}` — прочитать действующий контракт.
2. `{op:"session_open", task_id:"<unique task>"}` — открыть собственную сессию.
3. `{op:"browser", task_id, args:{command:"open", url}, request_key:"tab-open-0001"}`.
4. Сохранить `tab_id`; читать/изменять DOM через `read`, `snapshot`, `act`.
5. `files` и `terminal` использовать с той же задачей и стабильными ключами.
6. Закрыть свои вкладки/GUI, затем `{op:"session_close", task_id}`. Проверить
   `cleanup_verified`; ошибка закрытия не доказывает удаление ресурса.

Секреты сессии и resume token сохраняются в приватном `state/hub/clients`, а
модель получает только публичные поля. После перезапуска MCP `session_open`
проверяет и повторно использует сохранённую действующую сессию. Для смены
credentials нужен явный `session_resume`; старые credentials отзываются.
Отключение клиента не закрывает задачу. Потеря checkpoint при создании/resume
остаётся неопределённым результатом; новую личность автоматически не создаём.

Владелец может добавить в конфигурацию адаптера `--start-if-stopped`. Тогда
при пропаже процесса запускается именно Hub из установленного рядом runtime.
Для этого уже должен существовать локальный `state/universal-agent-runtime.json`
с `version:1, enabled:true`. Выключенный/повреждённый флаг даёт отказ без запуска;
сам адаптер флаг не создаёт. Потерянный запрос после старта не повторяется.

## Файлы и терминал

`files` поддерживает `read`, `stat`, `write`, абсолютный `path`, UTF-8 до 1 MiB.
Запись требует `text` и `expected_sha256`: `null` означает создание нового файла,
существующий файл меняется только при совпадении SHA. Запись атомарная. Канонический
путь получает исключительный lock до `resource_release` или окончания сессии.
Чужой lock даёт `RESOURCE_BUSY`. Эти locks кооперативные: внешние программы
могут менять файл напрямую, а SHA-проверка не является транзакцией с ними.

```json
{"op":"files","task_id":"example-task","request_key":"write-result-0001",
 "args":{"command":"write","path":"<absolute task file>","text":"result","expected_sha256":null}}
```

`terminal {command:"start", argv:[...], cwd, timeout_seconds}` возвращает
`terminal_id`. `shell=false`; для shell-команды явно указывается интерпретатор
в `argv`. Задание неинтерактивное, stdin закрыт; PTY и interactive stdin здесь
не реализованы. Supervisor живёт независимо от Hub и ограничивает время
(до 300 секунд) и вывод (1 MiB после остановки дерева). На Windows дерево
привязано к существующему механизму именованных Job Objects. Кратковременное
превышение лимита вывода до обнаружения возможно. Ответ `status` содержит
последние 64 KiB, код выхода, PID, время создания и подтверждение cleanup.

Проверяйте `terminal {command:"status",terminal_id}`. `cancel` отменяет только
собственное задание; `list` показывает собственные задания. Повтор `start` с
тем же ключом возвращает прежний ID без второго запуска. После аварии Hub
проверяйте точный ID, а не имя процесса. Если supervisor погиб сам, выполнение
не повторяется автоматически и требует проверки состояния.

Разрешение на интерпретатор и рабочий каталог **не ограничивает** доступ
команды этим каталогом. Это доверенные агенты одного пользователя, а не
изоляция от враждебного кода.

## Постоянные разрешения

Применяется существующая локальная policy Hub. RPC/MCP не изменяет её. Уже
данное владельцем разрешение на конкретную настройку позволяет оператору
сохранить соответствующие grants; отдельного нового подтверждения из-за
локального CLI не требуется.

```text
python ff_hub.py grant add --classes project_write --agents codex --paths <project>
python ff_hub.py grant add --classes terminal_execute --agents codex --paths <project> --apps <python executable>
python ff_hub.py grant list
python ff_hub.py grant revoke <grant-id>
```

Для `terminal_execute` обязательны и `paths`, и `apps`. Для `browser_script`
можно ограничить `agents` и `hosts`, для `app_launch` — `agents` и `apps`.
Все заданные ограничения действуют одновременно. `--ttl` ограничивает срок;
без TTL grant сохраняется до отзыва. Policy читается при каждом решении и
сохраняется после restart. `permission_check` объясняет отказ; `permission_describe`
показывает действующие классы. Повтор с прежним ключом после отказа допустим
только когда отказ явно произошёл до исполнения и policy уже изменена владельцем.

Разрешения Hub не отвечают на диалоги сторонних продуктов. Видимый ввод идёт
через прежний Bridge с chat-permission, сроком, точным окном, OWNER_ACTIVE,
notice и Stop. Постоянных разрешений на `external_send` и `financial` нет.

## Наблюдение и проверка

`python ff_hub.py status` / `hub {op:"hub_status"}` показывает сессии,
владельцев, ресурсы, PID supervisor и способ восстановления. `audit_read`
даёт причины отказов и события своей задачи. `request_status` принимает
исходный ключ; `unknown` запрещает автоматический повтор.

```text
python -m unittest discover -s tests -p "test_hub_clients_io.py"
python tests/integration/hub_mcp_clients_smoke.py
python tests/integration/hub_owner_chrome_rpc_smoke.py --run
python tests/integration/hub_owner_chrome_parent_crash_smoke.py --run
python tests/integration/hub_hidden_gui_smoke.py --run
```

Первый integration smoke — три отдельных MCP-процесса, а не три провайдера.
Проверка внешних моделей требует отдельных фактических запусков клиентов и
независимой проверки DOM/файлов; список моделей или готовый адаптер не дают PASS.
Платная/недоступная модель отмечается UNTESTED с причиной, без покупок и обхода лимитов.

При аварии Python Hub stdin менеджера Chrome закрывается. Такой EOF только
отключает relay: физические страницы, формы и точные target ID сохраняются.
Перед отключением локальные Page handles переводятся в `lost`, чтобы их
события `close` не стирали журнал живых физических вкладок. Замена менеджера
ожидает завершения прежнего; `BROWSER_MANAGER_RETIRING` означает безопасную
паузу до освобождения relay. Штатный shutdown RPC закрывает собственные вкладки
как прежде. Проверка parent-crash отдельно подтверждает две прежние физические
вкладки, сохранённый ввод/JS и dedupe эффекта после перезапуска.

Откат конфигурации восстанавливает только добавленную запись либо её точную
резервную копию при неизменном SHA. Не затирайте появившиеся чужие правки.
Исходники, установленный Hub и основной Bridge проверяются отдельно. Upgrade
Hub выполняется лишь после проверки сессий/вкладок, со снимком и проверенным
возвратом прежнего кода; перезапуск Bridge для MCP-адаптера не требуется.
