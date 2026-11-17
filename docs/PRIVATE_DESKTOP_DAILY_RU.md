# Скрытые приложения и Chrome: ежедневная работа

Продуктовый маршрут — локальный Hub API с собственными sessions/resources и durable receipts. GUI выполняется отдельным worker на private Windows Desktop. Chrome имеет новый профиль, а навигация, DOM, ввод, upload/download и submit идут через broker внутри worker и journal Hub. Физический ввод, visible focus и clipboard не нужны.

## Установка и запуск отдельного runtime

Нужны Windows 10/11 с интерактивной сессией, Python 3.13 и установленный Chrome. Word нужен только для Office-сценария. Runtime использует стандартную библиотеку; тесты дополнительно используют psutil и python-docx.

Из распакованного source release:

```powershell
python tools/private_desktop_runtime.py --home <новая-папка-runtime> install --source-zip <source.zip> --sha256 <SHA-256-из-поставки>
python tools/private_desktop_runtime.py --home <папка-runtime> start
python tools/private_desktop_runtime.py --home <папка-runtime> grant-apps --agent my-agent --apps chrome.exe,charmap.exe,winword.exe
python tools/private_desktop_runtime.py --home <папка-runtime> doctor
```

Установщик проверяет SHA/CRC и manifest, не принимает чужую непустую папку, создаёт immutable releases и переключает active.json. State, credentials и journal лежат отдельно в state/. Порт выбирается автоматически. Старый production Bridge/Hub и его state не заменяются.

`enable-autostart` добавляет только собственную уникальную HKCU Run entry через pythonw, без окна консоли. `disable-autostart` удаляет только ту же проверенную entry. Это автозапуск **после входа**; pre-login управление Windows не предоставляется. Регистрация и readback можно проверить без reboot. Реальный reboot/login gate отдельно отмечается NOT_RUN, пока не выполнен владельцем в безопасное время.

## Постоянный клиент

```powershell
python tools/private_desktop_client.py --state-dir <runtime>/state/hub --session-file <private-session.json> open --agent my-agent --task daily-work
```

Session file содержит credentials и resume token; держать локально, не включать в отчёты/репозиторий. При возобновлении использовать `resume`, а не угадывать старые HWND. Каждое имя agent/task независимо. Никаких токенов личного браузера не требуется.

В `request.json` сохранить `{"command":"open"}` и вызвать:

```powershell
python tools/private_desktop_client.py --state-dir <runtime>/state/hub --session-file <private-session.json> call --op private_browser --args-file request.json --key daily-chrome-open-001
```

Ответ содержит browser_id, PID/birth/HWND/Desktop и путь собственного профиля. Затем `private_browser` с `command:tabs` вернёт tab_id. Для навигации: `{"command":"navigate","browser_id":"...","tab_id":"...","url":"https://react.dev/learn"}` с новым постоянным request_key. `read` возвращает текст/URL/title; во время загрузки допустим пустой text, чтение можно повторить.

Для формы выполнить `observe`: получить snapshot и controls с ref/id/name. `act` принимает только наблюдённые snapshot/ref, operation `fill|click|select`, value и postcondition. Например: `{"command":"act","browser_id":"...","tab_id":"...","snapshot":"...","ref":"2","operation":"fill","value":"Widget","postcondition":{"type":"value_equals","selector":"#filter","value":"Widget"}}`. Для submit — click и проверяемая postcondition `text_includes` или `url_equals`. Ref расходуется перед действием; после изменения перечитать observe. В одном worker команды сериализованы, разные tasks работают независимо.

После пропавшего ответа:

```powershell
python tools/private_desktop_client.py --state-dir <runtime>/state/hub --session-file <private-session.json> receipt --key <исходный-request-key>
```

`completed` возвращает записанный результат; повтор того же ключа не даёт второй submit. `unknown` означает, что эффект мог произойти: проверить сайт/файл независимым чтением и не переигрывать автоматически. После restart только явно открывать новый браузер с новым намерением; старые receipts не являются живыми window handles.

## Файлы и GUI

- `upload`: snapshot/ref input[type=file], name и content_base64, максимум 1 MiB. Никаких произвольных путей к домашним файлам. Broker сохраняет bytes в собственном artifacts/uploads и передаёт Chrome через DOM.setFileInputFiles в том же CDP соединении, которому принадлежит objectId.
- `download_prepare`, затем наблюдённый click. `download_read` с безопасным name возвращает bytes/base64/SHA-256, максимум 4 MiB. Каталог закреплён в Preferences нового профиля и поддерживается живым CDP соединением. Файлы не направляются в пользовательский Downloads.
- `tab_open/tab_close/activate`, `screenshot`: только вкладки данного private browser. CDP screenshot показывает страницу; PrintWindow Chromium может быть белым и не является доказательством содержимого.
- `app_discover/app_open/app_windows/app_observe/app_find/app_act/app_capture/app_close`: generic UIA на private Desktop. Неподдержанный singleton/packaged app отклоняется с конкретной причиной; visible fallback не включается.
- Для Word/PPT/Excel документ задаётся один раз в app_open. `app_document` read/replace/save связан с тем же путём и HWND. Результат сохранения нужно независимо прочитать из файла. Замена простого текста не сохраняет сложное форматирование.
- `evaluate` — отдельный класс browser_script, по умолчанию требует owner-side grant; ordinary browser permission не даёт произвольный JavaScript.

Три независимых клиента используют разные session files и agent/task. `resource_claim` с kind/key даёт кооперативную блокировку между агентами; wait_seconds — ограниченную очередь. Это не запрет для внешних программ Windows того же пользователя. Чужие browser_id/app_id/HWND не принимаются.

## Отмена, обновление, диагностика

`client cancel` вызывает durable task_cancel: закрывает только ресурсы данной задачи. Receipt доступен даже после закрытия session. `cleanup_verified=false` и profile_cleanup[].removed=false сохраняют ошибку; такой исход не считать успешной уборкой.

`runtime stop` отказывается при активных sessions/hidden workers. `install` новой SHA-проверенной версии сначала готовит release, затем требует idle и сохраняет previous_release. `rollback` также требует idle и переключает previous_release. State/journal не удаляется. После start проверять doctor и фактический E2E. Не завершать чужие процессы ради обновления.

Hub/worker/browser crashes дают lost-resource/unknown receipts, а не автоматическую повторную отправку. Windows Job завершает owned descendants при смерти владельца; следующий запуск очищает profile только с подтверждённо умершим PID+creation identity. HTTP disconnect не отменяет уже начатый запрос: узнать outcome по тому же ключу. Audit и bounded журнал находятся в state/hub; credentials не печатаются.

## Граница production rollout

Legacy Bridge handover передаёт listener и terminal sessions, но не сохраняет active hidden sessions: новый процесс возвращает HIDDEN_SESSION_NOT_FOUND, старый может завершиться по linger вместе с worker. Пока нельзя доказать отсутствие/завершение всех таких задач, **production не переключать**. Отдельный runtime пригоден для новых задач параллельно старому; перенос существующих tasks не заявляется.

## Проверка

```powershell
python -X utf8 -m unittest discover -s tests -p "test_*.py"
python tests/integration/isolated_rpc_smoke.py
python tests/integration/private_product_acceptance.py --output <новый-каталог-evidence>
```

Gate выполняет реальные GUI Word/Character Map, SPA/form/files, три Hub clients, conflicts/queue/cancel, cookies, socket loss, timeout с поздним POST, browser/worker/Hub/Bridge crashes и restart без replay. Owner observer измеряет input Desktop/foreground/cursor; изменения человеческой активности допускаются, собственный foreground PID — отказ. Это проверка перечисленных сценариев, не универсальная поддержка всех Windows-приложений и сайтов.
