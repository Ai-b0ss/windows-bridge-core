# Скрытый Chrome на отдельном Windows Desktop

Этот маршрут запускает настоящий Chrome/Chromium с окном на отдельном неактивном Windows Desktop. Ввод и чтение страницы выполняются через CDP. Это два отдельных механизма: OS Desktop изолирует окна от обычного рабочего стола, CDP управляет содержимым браузера.

## Запуск и управление

1. Через `computer_use` выполнить `{"command":"hidden_start","worker_integrity":"medium"}`. Сохранить `session_id`, `desktop`, `worker_pid`.
2. Через `computer_use` выполнить `{"command":"hidden_request","session_id":"<id>","timeout_s":60,"request":{"command":"browser.launch"}}`. Запускать через `durable_call` с постоянным `request_key`.
3. Ответ содержит `pid`, `create_time`, `hwnd`, `profile_path`, `cdp_endpoint`, `browser_ws_endpoint`. Профиль создаёт только родительский Bridge. Путь, executable и параметры Chromium по RPC не принимаются. Разрешены стандартные установленные Chrome/Chromium; отсутствие браузера даёт `HIDDEN_CHROME_NOT_INSTALLED`.
4. Перед работой с CDP вызывать `browser.info` в той же hidden session. Он проверяет живой PID и время рождения, HWND на том же private Desktop, владельца профиля, listener с точным PID на loopback, DevToolsActivePort и ответ `/json/version`. После этого подключить CDP-клиент к возвращённому endpoint. При любой ошибке identity остановить действия. Существующий isolated/headless browser sidecar сохраняет свою прежнюю политику.
5. CDP позволяет навигацию, DOM, ввод в страницу, вкладки и снимок страницы. Не подключаться к браузерам/профилям владельца. Перед каждым изменением сохранить намерение; при потере ответа сначала проверить результат чтением, не повторять автоматически форму или клик.
6. Закрыть `hidden_close` через `durable_call`. Требовать `browser_profile_cleanup[].removed=true`, отсутствие профиля и точных owned процессов. Для отмены закрыть всю session. Отдельный browser.close не требуется.

Прямые CDP navigation/DOM/input выполняются внешним клиентом **вне durable journal Bridge**. Durable receipts покрывают Bridge RPC, включая запуск и закрытие; они не дают гарантии восстановления отдельной CDP mutation. В тесте CDP dispatch отдельно записывается в `rpc.jsonl`; потерянный ответ не переигрывается, результат сверяется независимым чтением. Единого brokered CDP API с durable recovery этот candidate не добавляет.

Пример payload `durable_call`:

```json
{"request_key":"my-task-chrome-launch-1","agent_id":"my-agent","task_id":"my-task","op":"computer_use","args":{"command":"hidden_request","session_id":"<id>","timeout_s":60,"request":{"command":"browser.launch"}}}
```

Повтор того же ключа возвращает сохранённый ответ и не запускает второй браузер. Старый сохранённый HWND/endpoint после перезапуска не является действующим ресурсом: требуется новая проверка. После `HIDDEN_ACTION_OUTCOME_UNKNOWN` worker/Job закрывается, слот освобождается; исходный запрос не переигрывается. После падения родительского Bridge Windows закрывает Job и его процессы; следующий запуск очищает только профиль с подтверждённо умершим владельцем. Ошибка уборки остаётся видимой в ответе.

## Ограничения

- Это изоляция ресурсов одного владельца Windows, а не защитная граница от другого кода того же пользователя. Loopback CDP доступен в рамках этой модели доверия. Личные cookies и авторизация не переносятся.
- Medium снижает integrity того же пользователя; это не проверка работы из отдельной стандартной учётной записи. Sandbox браузера, UAC, Defender и owner-activity guard не отключаются.
- Не вызываются `SwitchDesktop`, `SendInput`, visible focus или clipboard. Перед каждым worker request заново проверяется, что private Desktop не является input Desktop.
- `PrintWindow` у Chromium может вернуть пустое белое изображение. Такой снимок нельзя считать визуальным подтверждением страницы. Для содержимого используется CDP screenshot; принадлежность OS-окна проверяется отдельно. Native Notepad поддерживает реальное чтение/запись Win32 и проверенный PrintWindow.
- Поддержка этого маршрута не означает универсальную поддержку всех приложений Windows, UAC, CAPTCHA или произвольных Electron singleton.

## Воспроизводимая проверка candidate

Требуются Windows с интерактивной пользовательской сессией, Python 3.13, установленный Chrome/Chromium и `psutil` для независимой фиксации дочерних процессов тестом. Рабочий runtime использует стандартную библиотеку Python. Без платных API и установки браузера.

```powershell
python -m unittest discover -s tests -p "test_*.py"
python tests/integration/isolated_rpc_smoke.py
python tests/integration/hidden_chrome_smoke.py --output <новый-абсолютный-каталог-доказательств>
```

Каждый прогон требует новый каталог: durable journal предыдущего прогона сохраняет старые результаты. Gate поднимает отдельный Bridge на случайном loopback-порту и отдельный local HTTP server, проверяет Notepad, Chrome, форму с независимым серверным receipt, CDP screenshot, внешний сайт, вкладки, две одновременные формы/профили/cookies, запрет чужих HWND/параметров, kill worker, отмену, падение родительского Bridge и restart без replay. Отдельный read-only observer измеряет foreground/cursor/input Desktop/clipboard sequence каждые 10 ms. Такая выборка не исключает события короче интервала; человеческая активность допускается и не приписывается агенту автоматически.

## Деплой и откат

До production требуется обычное окно обслуживания и проверка отсутствия активных задач. Не заменять исполняемые файлы активного Bridge и не завершать его старые private peers. Candidate следует проверить отдельно, сохранить Git commit и SHA-256. После согласованного переключения применять канонический operator guide с backup, точными Git bytes, runtime parity, ping/capabilities/scope_report. Откат — восстановление прежнего полного runtime из backup и проверка тех же RPC. При действующих задачах оставить candidate без переключения production.
