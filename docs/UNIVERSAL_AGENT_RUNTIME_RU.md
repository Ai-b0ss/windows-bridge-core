# Общий Hub агентов: экспериментальный runtime

Кандидат в отдельной feature-ветке. Функция отключена по умолчанию. Исходники,
проверки в worktree, опубликованный архив и установленный процесс — отдельные
артефакты. Этот документ не подтверждает merge, публикацию или deploy.

## Что подключено

Bridge публикует `capabilities.features.universal_agent_runtime`, операцию `hub`
и подсказку в `agent_workflows`. Discovery читает только локальный feature-флаг;
не запускает Hub, Chrome или GUI. При выключенном либо повреждённом флаге
операция возвращает `HUB_FEATURE_DISABLED` до каких-либо действий.

Локальный файл относительно корня **выбранного экземпляра Bridge**:
`state/universal-agent-runtime.json`:

```json
{"version": 1, "enabled": true}
```

В этой работе флаг создаётся только в одноразовых тестовых каталогах.
Настройка владельца, `chat-permission.json` и установленный runtime не меняются.
Включение Hub не является разрешением на видимый ввод, платежи, рассылки или
использование платной модели.

Hub хранит SQLite-сессии, журнал запросов и кооперативное владение ресурсами
в `state/hub`. После первого вызова он может жить отдельно от Bridge. Несколько
Bridge с одним корнем используют один Hub. Клиент не выбирает через RPC другой
state-каталог, ключ, endpoint или способ запуска.

## Протокол агента

1. Проверить live capabilities; если функция выключена, продолжить существующими
   маршрутами, не включать и не перезапускать рабочий Bridge для эксперимента.
2. `hub {op:"capabilities",args:{}}` возвращает действующий контракт Hub.
3. `hub {op:"session_open",args:{agent_id,task_id}}` создаёт сессию. Сохранить
   `session_id`, `session_secret`, `resume_token` в приватном checkpoint.
4. Передавать `session_id` и `session_secret` на верхнем уровне **вложенного
   Hub-запроса**, а аргументы действия — в его `args`. Изменяющим запросам давать
   стабильный `request_key`. Не оборачивать их в ещё один Bridge `durable_call`.
5. После потери ответа запросить Hub `request_status` с прежним ключом. `unknown`
   означает необходимость независимой проверки состояния; повтор под новым
   ключом не разрешён автоматически.
6. Возобновление того же `agent_id/task_id` требует сохранённый `resume_token`,
   в том числе после устаревания сессии. Старые credentials после resume отзываются.
7. Завершить собственную сессию и проверить cleanup. Ошибка закрытия ресурса
   не является доказательством его удаления.

Пример тела операции Bridge `hub`:

```json
{
  "op": "resource_claim",
  "args": {"kind": "file", "key": "<absolute task-owned file>"},
  "session_id": "<saved session>",
  "session_secret": "<saved secret>",
  "request_key": "task-file-claim-0001"
}
```

## Границы доверия и ввода

`agent_id` — метка доверенного клиента, а не независимо подтверждённая личность.
Секрет сессии и resume token защищают существующую сессию от подмены другим
клиентом. Они не образуют sandbox между враждебными процессами того же Windows
пользователя. Первичное создание меток предполагает доверенный транспорт.
Файловые locks кооперативные: сторонняя программа может изменить файл напрямую.

Выдачи standing grants через Hub RPC нет. Без заранее настроенной policy классы
`app_launch`, `browser_script` и `secret_use` возвращают `PERMISSION_REQUIRED`.
Полный удалённый UX выдачи этих grants из чата ещё не реализован; локальный CLI
остаётся owner-side механизмом. Агент не запускает его, чтобы разрешить действие
самому себе. Отказ до начала исполнения можно повторить с прежним ключом после
решения владельца; неизвестный результат исполнения таким отказом не считается.

Hub **отказывает** в foreground-вводе, даже при старом локальном standing grant.
Видимый ввод проходит через существующий Bridge `set_desktop_mode` после слов
владельца в чате: локальное включение chat-permission, срок, точные окна с PID и
временем создания, OWNER_ACTIVE, notice, Stop и scope_report сохраняются.
Hub не удаляет `stop.flag` и не выдаёт desktop grants.

Standing grant на класс `external_send` запрещён: отправка другим людям требует
отдельного согласия на точный текст и адресата. DOM-действие не распознаёт смысл
всех кнопок сайта; соблюдение границы отправки остаётся обязанностью Skill и
агента. UAC, CAPTCHA, MFA и запросы разрешений Chrome не обходятся.

Policy перечитывается на каждом решении. Кэш только по timestamp удалён: реальная
регрессия показала сохранение старого `allow`, если отзыв разрешения сохранял
mtime и размер файла. Тест воспроизводит это до исправления и проверяет отказ
после него. Повреждённая или нечитаемая policy также отказывает; новые grants
через Hub RPC не выдаются.

DPAPI защищает vault на диске. Broker ограничивает разрешённые получатели и
команды; это не sandbox для разрешённого процесса или сервера. Не передавать
настоящие credentials непроверенным приложениям/сервисам. В публичных тестах
используются только искусственные значения.

## Chrome и GUI: доказанные ограничения

Chrome подключается через официальный Playwright extension к профилю владельца.
Cookie, пароли и копирование профиля для этого не нужны. Hub создаёт собственные
вкладки, проверяет владельца, ограничивает квоты и не присваивает чужие страницы.
После разрыва вкладка отмечается lost; restore **никогда не открывает URL повторно**:
он возвращает исходную физическую вкладку только при точном совпадении CDP target id.
Если её нельзя найти, результат — TAB_RECOVERY_UNAVAILABLE; повторная навигация
могла бы создать дубликат, потерять данные формы и нарушить владение.
Карта физических вкладок живёт в Node-процессе, но теперь дублируется на диск:
`state/hub/browser/tab-ledger.json` хранит для каждой вкладки агента её id,
владельца и **точный CDP target id** — случайный идентификатор, который браузер
выдаёт одной вкладке. Журнал пишется атомарно при открытии, навигации и закрытии.
После hard crash новый процесс менеджера загружает записи как `lost` +
`orphaned:true`. `restore` и `close` сначала ищут физическую страницу **только по
точному совпадению target id**. URL и заголовок доказательством не считаются.

- Совпадение найдено: та же вкладка возвращается владельцу
  (`reattached:true`, `evidence:"cdp_target_id"`, `page_state_preserved:true`) —
  JS-состояние и незавершённая форма сохраняются; `close` закрывает её с
  подтверждением.
- Совпадения нет: `restore` → `TAB_RECOVERY_UNAVAILABLE`, `close` →
  `TAB_CLEANUP_UNCONFIRMED`. Чужая страница с тем же адресом не присваивается,
  дубликат не открывается.
- Закрытие «по отсутствию» (`evidence:"target_absent_in_browser"`) принимается
  только на транспорте, который перечисляет все targets браузера. Relay
  расширения показывает лишь подключённые вкладки, поэтому там отсутствие
  ничего не доказывает и статус остаётся неподтверждённым.
- При разрыве relay без падения процесса restore пробует переподключить
  **только ту же физическую вкладку**. Если новый клиент расширения её не видит,
  возвращается TAB_RECOVERY_UNAVAILABLE; URL никогда не служит идентификатором.
- При завершении сессии неподтверждённые записи попадают в отчёт
  (`cleanup_verified:false`) и audit, после чего удаляются из журнала менеджера,
  чтобы недостижимая вкладка не занимала квоту бессрочно.
- Повреждённый журнал сохраняется рядом как `.unreadable`, вкладки из него не
  «придумываются»; `status.tab_ledger.error` сообщает об этом.

Остаточное окно: падение между созданием страницы и записью журнала оставляет
вкладку без записи; запрос при этом числится в журнале Hub как `unknown`.
Prerender/смена target id также дают fail-safe отказ, а не угадывание.

Что доказано и что нет. Механизм проверен на **реальном Chromium** с реальным
жёстким завершением менеджера (`browser_hub_reattach_smoke.mjs`, см. ниже), но
через прямой CDP к одноразовому изолированному браузеру. Сохраняет ли relay
официального расширения прежние вкладки видимыми новому подключению — **не
проверено**: Chrome владельца ниже порога, подключение не создавалось. Если relay
их не показывает, поведение остаётся прежним fail-safe. Потеря HTTP-ответа
менеджера по-прежнему записывается как `unknown`; прежний ключ запрещает replay.

Background-действия Hub используют DOM и синтетические события. Они не равны
trusted pointer/keyboard input: canvas, drag-and-drop, пользовательская активация,
скрытые animation frames и отдельные сайты могут не работать. Невыполненное
postcondition возвращает ошибку, а не успех. Общий поддерживаемый способ trusted
input в произвольной скрытой вкладке не доказан.

Официальный [Playwright MCP v0.0.85](https://github.com/microsoft/playwright-mcp/releases/tag/v0.0.85)
указывает extension не ниже 0.5.0; отсутствие вывода служебной страницы вперёд
также зависит от токена, уже работающего Chrome не ниже `158.0.8127.2`.
Проблема hidden click/Enter описана в [upstream issue 44096](https://github.com/microsoft/playwright/issues/44096).
Экспериментальный upstream patch не является доказательством исправления
установленной среды. Playwright в исходниках закреплён на 1.65.1; расширение и
Chrome владельца в этой работе не обновляются.

Read-only capability probe, без подключения, чтения токена или вывода profile path:

```text
node runtime/bridge-v3/ff_browser_hub.mjs --preflight
```

`available:false`, `reason:BACKGROUND_CONNECT_UNSAFE`, `fallback:null` означает
закрытый маршрут для текущего Chrome. Порог подтверждён upstream release notes;
для версии 157 безопасный fallback в рамках этих условий не доказан. Ответ также
содержит `remedy:"OWNER_CHROME_UPDATE_AND_RELAUNCH"`, `automatic:false`:
единственное поддерживаемое средство — обычное обновление и перезапуск Chrome
самим владельцем; Hub браузер не обновляет и не перезапускает. Проба также
проверяет расширение и установленный Playwright, если прошла проверка Chrome.
`available:true` подтверждает только предпосылки: `live_verified:false` и
`token_checked:false` сохраняются. Discovery приложения сообщает `expected` и
capability gate вместо безусловного `proven`. Ввод на видимом desktop автоматически
не выбирается. CDP или отдельный профиль не подменяют разрешённый профиль владельца.

Для альтернативного CDP-маршрута [Chrome с версии 136](https://developer.chrome.com/blog/remote-debugging-port)
не принимает debugging port/pipe для default profile: требуется другой
`user-data-dir`. Это не повторное использование текущего signed-in профиля.
Поддерживаемый [Chrome DevTools MCP autoConnect](https://github.com/ChromeDevTools/chrome-devtools-mcp/blob/main/docs/advanced-usage.md#automatically-connecting-to-a-running-chrome-instance)
требует заранее включённого remote debugging и диалога разрешения Chrome.
Эти настройки не включались, диалоги не обходились. Уже разрешённый отдельный
relay endpoint этого Hub не подтверждён; чужой session не присваивается.
Экспериментальный CDP focus emulation не доказывает trusted background input
для произвольного сайта. Это ограничения проверенных маршрутов, а не утверждение
о невозможности любой фоновой автоматизации.

GUI запускается на отдельном Windows desktop с собственным Job. Для окон
проверяется PID и время создания процесса. Generic launch не применяется к
известным single-instance Chromium/Electron приложениям: попытка запуска могла
бы передать команду уже открытой копии владельца. Для редакторов с изолированным
профилем существуют отдельные маршруты; их пригодность к конкретной задаче
проверяется отдельно. UWP/MSIX и частичное UIA-дерево не считаются поддержкой
произвольного GUI.
Для неизвестного Win32 singleton отдельный desktop также не доказывает изоляцию
от уже работающей копии: требуется проверка конкретного приложения и маршрута.

## Проверки и rollout

Обязательные локальные команды:

```text
python -m unittest discover -s tests -p "test_*.py"
python tests/integration/isolated_rpc_smoke.py
node --test tests/test_ff_browser_hub.mjs
python tests/integration/hub_bridge_rpc_smoke.py
python tests/integration/hub_singleton_smoke.py
python tests/integration/browser_hub_crash_smoke.py
```

Последний smoke поднимает реальные отдельные Bridge и Hub на случайных loopback
портах: три агента, отрицательные проверки чужих ресурсов, deduplication,
перезапуск Bridge с сохранением Hub и аварийное завершение собственного Hub
во время запроса. После рестарта журнал обязан показать `unknown` без replay.
Это проверка протокола и recovery, не live Chrome/GUI acceptance.

`browser_hub_crash_smoke.py` запускает настоящий отдельный Node HTTP-процесс с
**синтетическим page adapter**: после записи тестового эффекта процесс аварийно
завершается до ответа. Проверяются `unknown`, запрет replay, перезапуск менеджера,
отказ restore без создания дубликата, сохранение ресурса и неподтверждённый cleanup.
Chrome, credentials и профиль владельца в этом smoke не используются. Проверка
добавлена в CI; её локальный PASS не заменяет live Chrome acceptance.

`hub_hidden_gui_smoke.py` — отдельная ручная Windows-проверка только своего
private desktop. `browser_hub_owner_chrome_smoke.mjs` требует заранее разрешённого
расширения и проверки условий background. Такие испытания не включаются в
обычный CI и не подменяются mock-тестами. Совместное live испытание Chrome + GUI
+ файловый агент остаётся отдельным gate; отчёт должен различать PASS, FAIL,
NOT_RUN и неизвестный результат.

Локальная проверка этого кандидата: RPC/recovery smoke прошёл на реальных
одноразовых процессах. Chrome smoke — **NOT_RUN**: read-only preflight обнаружил
версию `157.0.8103.79`, ниже безопасного порога; токен не читался, подключение не
создавалось. В двух private desktop наблюдались toggle/set_value с postcondition,
независимое UIA-чтение, capture, отказы чужим HWND/creation time и cleanup.
Исторический повтор с guard остановился до app launch при изменении owner state.
Обновлённый harness разделяет `functional_status` и `noninterference_status`.
Перед pattern-действиями он проверяет, что private desktop не стал input desktop;
независимый observer thread через Win32 enumeration проверяет принадлежность HWND
именно private desktop. `SetThreadDesktop` привязывает только observer thread;
`SwitchDesktop` и физический ввод не используются. Движения владельца наблюдаются,
но не приписываются агенту и не обрывают изолированную функциональную проверку.
Production guards OWNER_ACTIVE/Stop/permissions этим изменением не затрагиваются.

Локальный повтор обновлённого harness: **functional PASS**, **noninterference
INCONCLUSIVE**. Два desktop, разные PID, native HWND identity, toggle/set_value,
независимое UIA-чтение, capture, отказы чужим окнам/creation time и cleanup прошли.
В 1022 замерах foreground менялся; cursor и clipboard sequence не изменились.
Общий результат остаётся **INCONCLUSIVE / OWNER_STATE_CHANGED_DURING_SMOKE**.
Начальные попытки новой native identity assertion завершались FAIL и cleanup;
после исправления observer проверка прошла. Общий gate не объявляется PASS.
Итог полного совместного live gate: **NOT READY**.

Финальная локальная регрессия: **606/606 Python unit tests**, **30/30 Node Hub
tests**, **8/8 iframe checks**, isolated Bridge RPC, Bridge/Hub recovery smoke и
concurrent startup smoke — **PASS**. Python compile, PowerShell parsing и
`diff --check` прошли. Все **250** bundled source files совпадают между рабочими
LF-байтами, индексом Git и SHA-256 manifest. GitHub checks в этом checkpoint —
**NOT_RUN**; portable ZIP не собирался, установленный runtime не развёртывался.

Оставшиеся blockers этого checkpoint:

| Gate | Статус | Что требуется для следующего доказательства |
| --- | --- | --- |
| Signed-in Chrome background | NOT_RUN | Уже работающая среда, проходящая capability probe; затем разрешённый live smoke. Версия Chrome в этой работе не меняется. |
| Физические вкладки после hard crash | NOT READY | Поддерживаемый устойчивый идентификатор и подтверждение владения/закрытия. До этого действует fail-safe без adoption и повторного открытия. |
| GUI отсутствие вмешательства | INCONCLUSIVE | Наблюдение без изменений owner state либо независимая атрибуция событий. Функциональный private desktop gate уже PASS. |
| Совместный Chrome + GUI + file gate | NOT_RUN | Сначала закрыть перечисленные live gates; протокольные и синтетические smoke их не заменяют. |

CI добавляет Node Hub tests и отдельный Bridge/Hub smoke без профиля владельца.
Manifest обновляется по точным LF-байтам source. Перед будущим rollout нужны
все обязательные GitHub checks, source/portable parity и отдельное решение
владельца о deploy по действующим operator guides.

Откат feature: локально выставить `enabled:false`; новые вызовы Hub будут
отказаны без перезапуска Bridge. Это само по себе не завершает уже начатый
запрос и не останавливает общий Hub. Сначала завершить свои задачи и сверить
состояние ресурсов. Для отката бинарного runtime применять существующий
проверенный cold rollback kit; не завершать общие keeper или чужие приложения.


## Checkpoint 17 ноября 2026: Chrome 157, восстановление вкладок, GUI

### Chrome 157 и официальное расширение (независимая проверка)

- Read-only preflight на этой машине: работающий Chrome `157.0.8103.79`,
  результат `BACKGROUND_CONNECT_UNSAFE`. Токен не читался, подключение не
  создавалось, Chrome не обновлялся и не перезапускался.
- [Release notes Playwright MCP v0.0.85](https://github.com/microsoft/playwright-mcp/releases/tag/v0.0.85)
  подтверждают: `--background` оставляет подключённую вкладку неактивной, а
  служебная connect-страница открывается в фоне только при заданном токене,
  **уже работающем** Chrome `158.0.8127.2+` и расширении `0.5.0+`. На 157
  подключение выводит страницу и окно браузера вперёд — это нарушает условие
  «не трогать фокус», поэтому маршрут закрыт, а не «работает с оговоркой».
- По данным [ChromiumDash](https://chromiumdash.appspot.com/releases?platform=Windows)
  на дату проверки стабильный канал Windows уже `158.0.8127.36/37`. В каталоге
  установки подготовленного обновления не найдено. Gate закроется обычным
  обновлением Chrome владельцем; программного обхода для 157 нет.
- Альтернативы для 157, проверенные по документации и отклонённые:
  remote debugging port/pipe (с Chrome 136 не работает с default profile —
  нужен другой `user-data-dir`, то есть не signed-in профиль); Chrome DevTools
  MCP `autoConnect` (требует включить remote debugging и ответить на диалог
  Chrome); копирование профиля/cookies (запрещено); собственное расширение с
  `chrome.debugger` (требует установки владельцем и показывает баннер отладки,
  отдельное решение владельца); Native Messaging companion в репозитории умеет
  только загрузки и не управляет вкладками.
- Trusted input: Hub по-прежнему сообщает `trusted_input:false`. CDP
  `Input.dispatch*` через debugger даёт trusted-события, но для скрытой вкладки
  upstream сам описывает отказ click/Enter
  ([issue 44096](https://github.com/microsoft/playwright/issues/44096)); в этом
  checkpoint такой режим не включался и не выдаётся за доказанный.

### Проверки этого checkpoint

| Проверка | Результат |
| --- | --- |
| `node --test tests/test_ff_browser_hub.mjs` | PASS, 36/36 (6 новых: журнал, target id, отказ adoption, remedy) |
| `node tests/integration/browser_hub_reattach_smoke.mjs --require` | PASS: реальный headless Chromium с временным профилем, жёсткое завершение менеджера, 2 вкладки возвращены по target id, JS-состояние и ввод сохранены, чужая страница с тем же URL не тронута, исчезнувшая вкладка не открыта повторно, закрытие подтверждено, журнал пуст |
| `python tests/integration/hub_hidden_gui_smoke.py --run` | PASS: functional PASS и noninterference PASS (1056 замеров; foreground, курсор и clipboard sequence владельца не менялись) |
| `python tests/integration/claude_desktop_private_smoke.py --run` | BLOCKED `CLAUDE_ALREADY_RUNNING` — ожидаемый fail-safe, ничего не запущено |
| Signed-in Chrome через расширение | NOT_RUN (Chrome 157) |

Reattach-smoke использует только встроенный тестовый Chromium из кэша Playwright
и никогда не выбирает установленный Chrome. Без Playwright runtime или тестового
браузера он честно возвращает `NOT_RUN`; в CI пока не включён, потому что там не
устанавливаются `playwright-core` и браузер.

GUI-harness исправлен: он сам может выполняться на приватном desktop (сессия
агента, запущенная скрытым маршрутом), где курсор и foreground владельца
недоступны. Наблюдатель теперь отдельным потоком привязывается к input desktop
только с правами чтения/перечисления; ничего не переключается и не активируется.

### Скрытый GUI: границы

- Эта самая Code-сессия Claude Desktop исполнялась на приватном desktop
  `FFBridge-Agent-*` (проверено `GetThreadDesktop`), то есть скрытый маршрут
  удерживает долгоживущую рабочую сессию. Это наблюдение одной сессии, а не
  автоматизированный acceptance отправки промпта.
- Пока работает любой `Claude.exe`, второй скрытый экземпляр не запускается
  (single-instance): и smoke, и production worker отказывают заранее.
- Порядок маршрутов прежний: официальный API/CLI/SDK → signed-in Chrome через
  расширение → UIA без фокуса → приватный desktop → видимый desktop после «да»
  владельца. Для Code-задач без GUI официальным программным путём остаются
  CLI/Agent SDK; deep link `claude://code/new` только предзаполняет prompt.
- Не доказано: произвольные Electron/UWP приложения, drag-and-drop, canvas,
  приложения с UAC/защищённым вводом, отправка промпта в Claude Desktop.

### Обновлённые gates

| Gate | Статус | Что требуется дальше |
| --- | --- | --- |
| Signed-in Chrome background | NOT_RUN | Владелец обновляет Chrome до 158.0.8127.2+ обычным способом; затем preflight и разрешённый live smoke. |
| Физические вкладки после hard crash | PASS на изолированном CDP-браузере; NOT_RUN через relay расширения | Тот же сценарий crash→reattach через расширение после открытия Chrome gate. |
| GUI отсутствие вмешательства | PASS (один прогон, 1056 замеров) | Повтор при активном владельце за ПК для статистики. |
| Совместный Chrome + GUI + file gate | NOT_RUN | Зависит от Chrome gate. |

Итог: **NOT READY** для включения по умолчанию; готов к следующему gate —
live acceptance на Chrome 158+ при выключенном по умолчанию feature flag.

## Claude Desktop: отдельный проверенный MSIX-алиас

В feature-ветке поддержан собственный скрытый Claude Desktop через
AppExecutionAlias, закреплённую за ним JobObject и точные PID/HWND guards.
Это не разрешение запускать произвольные UWP или Electron приложения.
Реальная вкладка Code и выбор Fable 5.2 Medium доступны для UIA-наблюдения.
Автоматическая отправка запроса и долгоживущий Code session ещё не проверены.
Описание: docs/CLAUDE_DESKTOP_BACKGROUND_RESEARCH_RU.md


## 17 ноября: первичная приёмка на настоящем Chrome 158

Независимо проверен основной Chrome 158.0.8127.36 (профиль Default,
расширение Playwright 0.5.0); Playwright 1.65.1 установлен в отдельной
приватной тестовой папке state владельца, без
обновления установленного Bridge. Ветка feat/universal-agent-runtime.

Owner Chrome smoke через защищённый DPAPI launcher: 20 PASS / 0 FAIL,
три параллельных агента, собственные скрытые вкладки, ввод/форма/скриншот,
запрещённый доступ к чужим вкладкам, физическая очистка 1/1/1,
ноль переключений foreground.

Критическое ограничение реального extension relay:
context.newCDPSession(page) существует, но вызывает
Target.attachToBrowserTarget: Not allowed. Следовательно,
durable_identity:false, target_id нет. При потере relay
вкладки других агентов могут стать lost с
TAB_CLEANUP_UNCONFIRMED. Первый owner-Chrome тест выявил
такой результат (23/24); повторная диагностика показала
closed:0,1,0, два lost и отсутствие права утверждать,
что вкладки физически удалены. Старый tabRestore при
таком сценарии открывал адрес заново и оставлял возможный дубликат.

Исправлено: tabRestore больше никогда не открывает URL
потерянной вкладки без доказательства отсутствия оригинала.
При отсутствии точной привязки возвращает
TAB_RECOVERY_UNAVAILABLE с no_address_fallback:true;
не воспроизводит действия, не теряет запись о lost.
Изолированный тест точной привязки по CDP ID сохраняется.
Owner-Chrome smoke больше не провоцирует обрыв relay,
если у вкладок нет CDP ID: выводит SKIP только для
восстановления и безопасно закрывает все три собственные вкладки.
Это сознательная граница готовности, не доказательство
полноценного восстановления авторизованных вкладок.

Тестовые вкладки с первых двух диагностических запусков
закрыты не подтверждённо. Их фактический статус неизвестен;
нельзя автоматически присваивать и удалять чужие вкладки по URL.
Производственное включение Hub не выполнялось. Следующий шаг —
поддерживаемый идентификатор вкладки в Playwright extension или
иная проверяемая идентификация, затем тест перезапуска relay.
До этого восстановление через основной Chrome блокировано.


## 17 ноября 2026: CDP target ID из Playwright Extension без глобальной отладки

На реальном Chrome 158.0.8127.36, Playwright Extension 0.5.0 и локальной
Playwright 1.65.1 выяснено: context.newCDPSession(page) в extension mode
вызывает Target.attachToBrowserTarget, который Chrome запрещает (Not allowed).
Само расширение, однако, успешно выполняет chrome.debugger.sendCommand
на собственной вкладке с Target.getTargetInfo. В in-process Playwright
page._connection.toImpl(page) возвращает соответствующий серверный Page
с delegate: CRPage, который **уже хранит** точный 32-символьный идентификатор
в delegate._targetId.

В ff_browser_hub.mjs реализовано чтение только для переданной собственной
страницы. Проверяются тождественность серверного Page, его BrowserContext,
тип делегата и формат targetId. Новая CDP-сессия не создаётся;
сторонние вкладки, cookies и расширения не обходятся. Поскольку
toImpl/CRPage — **непубличный API Playwright**, зафиксирована версия
1.65.1; любое несовпадение приводит к null и безопасному отказу.

**Подтверждённые испытания:**
- Node unit: **37/37 PASS**, включая отказ при чужом контексте
  и некорректном target ID.
- Реальный Chrome с профилем Default: **22/22 PASS**; три агента
  одновременно работали в скрытых вкладках, все три получили
  durable_identity:true; чужие операции изолированы;
  журнал на диске подтвердил три разных настоящих CDP target ID,
  связанные с конкретными владельцами; 1/1/1 вкладка физически закрыта;
  журнал после очистки пуст; смен foreground — 0.
- Отдельный изолированный Chromium/CDP: hard kill менеджера,
  возврат двух вкладок по CDP ID, сохранение JS-состояния,
  неприкосновенность чужой вкладки с тем же URL — PASS.

**Обновление gate:** ограничение повторного выбора устранено в следующем
изменении (см. секцию ниже). Это старое наблюдение не является текущим
блокером Chrome 158. Продолжает действовать fail-closed правило: отсутствие
строгого доказательства идентичности или владельца не разрешает управление.

Playwright 1.65.1 для испытаний установлен отдельно в приватном каталоге state
владельца; конкретный локальный путь не является частью публичной конфигурации.
Установленный боевой Bridge не перезапускался.


## 17 ноября 2026: реальное восстановление relay и hard-crash в Chrome 158 — PASS

### Архитектурный механизм

Официальное расширение 0.5.0 не предоставляет прямой RPC для повторного
выбора вкладки после аварии менеджера; новая token-сессия изначально видит
только собственный connect.html. Мы **не изменяли и не перепаковывали**
расширение, не включали remote-debugging всего Chrome и не копировали профиль.

Новая закрытая функция BrowserHub _bringBackExtensionTab действует
только из доверенной chrome-extension страницы официального расширения
в защищённом соединении. Она:

1. Берёт CDP target ID исключительно из журнала собственной агентской
   вкладки и отклоняет повторение того же ID у другого владельца.
2. Через уже существующую страницу расширения запрашивает
   chrome.debugger.getTargets() и отбирает **одно точное** совпадение по ID;
   URL и заголовок не являются идентификаторами.
3. Отказывает, если вкладка уже attached, числовой tab ID отсутствует,
   есть действующий владелец в getConnectionStatus, другая группа/окно
   небезопасны либо проверка происхождения страницы/группы не пройдена.
4. Только для подтверждённой *своей* свободной вкладки выполняет
   chrome.tabs.group() в группу нового защищённого relay.
   Штатный обработчик Playwright Extension прикрепляет вкладку по Chrome
   Debugger API и создаёт Page в новом соединении.
5. Повторно сверяет точный CDP target ID уже **прикреплённой** страницы.
   Состояние, формы и JavaScript остаются у прежней физической вкладки.
   Тайм-аут и любой недостаток доказательств — TAB_RECOVERY_UNAVAILABLE
   без открытия URL, без повторения пользовательского действия.

Инструмент не является универсальным доступом агента к
chrome.debugger/chrome.tabs: он существует только как внутренний
обработчик одной принадлежащей Hub вкладки.

### Подтверждённые live-испытания

| Испытание | Результат |
| --- | --- |
| Простой обрыв extension relay | PASS: та же вкладка, JS-состояние и ввод сохранены, физическое закрытие и очистка журнала |
| Жёсткий SIGKILL собственного процесса Hub и новый менеджер | **PASS, 3 независимых запуска**, каждый по две вкладки с точными ID, сохранённым JS и полями; журнал пуст |
| Второй Hub со старой копией журнала при живом владельце | PASS: TAB_RECOVERY_UNAVAILABLE; чужая вкладка и её группа не изменились |
| Невмешательство в пользовательский интерфейс | PASS: при трёх hard-crash-прогонах изменений foreground не зафиксировано |
| Node-unit отрицательные проверки | PASS: чужой extension origin и дубликат target ID не вызывают восстановление |

Запуск — только с защищённым token launcher, только при живом Chrome 158+:
- tests/integration/browser_hub_extension_recovery_smoke.mjs --run
- tests/integration/browser_hub_extension_crash_smoke.mjs --run
- tests/integration/browser_hub_extension_busy_owner_smoke.mjs --run

Два скрипта browser_hub_extension_crash_* разделяют жизненный цикл тестового
HTTP-сервера и двух дочерних Node-менеджеров; основной браузер не завершается.
Если аварийный сценарий не удаётся, очистка выполняется исключительно для
точных target ID теста с проверкой локального URL и уникального заголовка.

### Непроверенные границы

- Реальная полная авария **самого Chrome**, Windows logoff/reboot и восстановление
  вкладок после перезапуска браузера — не проверены и не обещаются.
- Приватные API Playwright toImpl / CRPage._targetId могут меняться при
  обновлении версии. Версия 1.65.1 закреплена, любые несовпадения fail-closed.
- Вкладки в другом окне, занятые другим client или не допускающие debugger
  attach не переносятся автоматически; требуется безопасный отказ, не захват.
- Это развитие feature-ветки, **не развёрнуто в установленном боевом Bridge**.
  Feature flag по умолчанию выключен. Для запуска через общий production RPC
  нужны отдельная релизная приёмка, проверка разрешений и окно внедрения без
  работающих чужих заданий.


### Проверка полного маршрута через Bridge RPC — PASS

Дополнительный live gate: tests/integration/hub_owner_chrome_rpc_smoke.py --run.
Запускает **только отдельные тестовые процессы** Bridge и Hub
на случайном loopback-порту и с отдельным временным state dir.
Основной Bridge (39073/39076) и Chrome не перезапускаются.

Три agent_id открыли три скрытые вкладки на тестовом localhost через
Bridge RPC -> Hub -> BrowserManager -> Playwright Extension -> Chrome 158.
Подтверждено: единственный браузерный менеджер, durable_identity:true,
персональные списки вкладок, отказ RESOURCE_NOT_OWNED при попытке
читать вкладку другого агента, реальное нажатие кнопки и чтение
изменённого DOM, физическое закрытие всех трёх вкладок и пустой журнал.
Вывод: FULL_RPC_PASS.

Тестовый browser manager завершён только по PID из **собственного
временного endpoint**, после доказанной очистки; установленные процессы
Bridge и Chrome сохранены. Тест намеренно не выдаёт эту приёмку за
production deployment: в рабочей установке feature flag остаётся
выключенным до безопасного окна обновления.


## Checkpoint 21 ноября 2026: пользовательское чтение сайта без прерывания (`site_read`), аудит манифестов и синтетическая проверка

### Аудит фактических манифестов (строго read-only, без изменения прав)

- **`FF Browser Companion` (`runtime/bridge-v3/browser_companion/manifest.json`, версия `0.1.1`):**
  декларирует только `permissions: ["downloads", "nativeMessaging"]` без `host_permissions`
  (в `service_worker.js` реализованы только `health`, `capabilities`, `download.*`).
  Не умеет открывать вкладки или читать страницы; во всех точках обнаружения
  (`inspect_companion_manifest`, `route_plan`, `site_read`, `agent_workflows`,
  `capabilities`, `cua_bridge_v3._companion_health`) явно публикуется с
  `browser_page_reader: false`, `page_read_supported: false` и исключается с кодом
  `COMPANION_DOWNLOADS_AND_NATIVE_MESSAGING_ONLY`.
- **`Playwright Extension` (проверено в read-only режиме по манифесту установленного профиля: `0.6.0`, требование Hub `>= 0.5.0` и Chrome `>= 158.0.8127.2`):**
  декларирует `permissions: ["activeTab", "debugger", "storage", "tabGroups", "tabs"]` и
  `host_permissions: ["<all_urls>"]`. Поддерживается через `ff_browser_hub.mjs`
  (`owner_chrome_extension`) только для обычного запроса фоновой вкладки
  (`visibility: "background_tab"`, `visible_tab_strip: true`, `hidden_secondary_window_supported: false`).
  В `ff_browser_hub.mjs` добавлена проверка прав манифеста (`BACKGROUND_EXTENSION_PERMISSIONS_INSUFFICIENT`
  при отсутствии `tabs` или `debugger`/`scripting`) и явная декларация `activates_tab: !background`,
  `read_supported: true`, `ownership_supported: true`.
- **Сторонние расширения ИИ-ассистентов в Chrome:** не управляются брокером Hub,
  не дают доказуемого владения, неактивации и очистки; исключаются с кодом
  `PROVIDER_UNMANAGED_NO_BROKER_OWNERSHIP` и никогда не перехватываются.
- **Изолированные профили (`managed_browser` / `private_browser`):** не наследуют
  авторизованные сессии Chrome владельца и никогда не подставляются молча
  (`ISOLATED_PROFILE_SUBSTITUTION_FORBIDDEN`).

### Реализация в исходниках

- `runtime/bridge-v3/cua_owner_chrome_secondary.py`: параметр `allow_new_ws: bool = True`
  в `preflight` (при `allow_new_ws=False` не открывается новый WebSocket и не вызывается
  диалог Chrome; возвращается `OWNER_CHROME_CDP_APPROVAL_REQUIRED` или
  `OWNER_CHROME_CDP_NOT_CONNECTED`).
- `runtime/bridge-v3/ff_browser_routes.py`: `inspect_companion_manifest`,
  `validate_site_read_url`, `normalize_visibility_mode`, `evaluate_no_interruption_site_read`
  и поддержка `capability="background_tab_read"` в `route_plan`.
  Строго различает `visibility="background_tab"` и `visibility="strict_invisible"` /
  `strict_invisibility=true` (при строгой невидимости `owner_chrome_extension` всегда
  отклоняется с `VISIBLE_TAB_SUBSTITUTION_FORBIDDEN`). При отсутствии готового провайдера
  возвращает **один** структурированный результат возможностей
  (`NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER`, `ui_triggered: false`,
  `prompts_triggered: false`, `pending_request_created: false`) до любого UI или pending-запроса.
- `runtime/bridge-v3/ff_hub.py`, `ff_hub_store.py`, `ff_hub_mcp.py`, `ff_agent_entry.py`,
  `cua_agent_workflows.py`, `cua_bridge_v3.py`: операция `site_read` (только чтение,
  allowlist/blocklist аргументов, запрет мутаций/stealth/извлечения cookies/авто-одобрения,
  проверка хоста после редиректа `REDIRECT_HOST_NOT_GRANTED` с сокрытием тела ответа,
  обязательный teardown в `finally` с fail-closed удержанием неподтверждённого закрытия),
  пользовательский CLI `ff_hub.py site-read` (выход `2` без открытия сессии при отсутствии
  провайдера, выход `0` после verified teardown), схема MCP `hub` и `/agent/v1` scope
  `owner_chrome_hidden`.

### Результаты синтетических и регрессионных испытаний

| Проверка | Результат | Подтверждённые факты |
| --- | --- | --- |
| `tests/test_no_interruption_site_read.py` (5 тестов) | **PASS (5/5)** | Аудит фактического `manifest.json` Companion 0.1.1; отказ подмены видимой вкладки при `strict_invisibility=true`; проверка всех 5 критериев провайдера (`authorized`, `connected`, `background_open_without_activation`, `read_access`, `ownership`); 1 результат `NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER` с `0` UI, `0` WS, `0` pending-запросов; блокировка запрещённых аргументов; **2 последовательные задачи + verified teardown** на синтетических loopback HTML-страницах через реальный Node `ff_browser_hub.mjs` (`bring_to_front_calls=0`, пустой `tab-ledger.json`, чужая вкладка владельца не тронута, блокировка cross-host редиректа, fail-closed удержание при обрыве во время закрытия) и через синтетический Chrome 158 HTTP-404 loopback CDP (`1` переиспользованный WS, `0` утекших targets, мгновенный отзыв grant); проверка MCP Adapter, `/agent/v1` scoped entry и пользовательского CLI `ff_hub.py site-read` |
| `python -X utf8 -m unittest discover -s tests -p "test_*.py"` | **PASS (787/787, skipped=4)** | Включая `test_manifest_matches_git.py` (**313** bundled source files, точное совпадение LF SHA-256 с Git index), `test_skill_contract.py`, `test_agent_workflows.py`, `test_browser_routes.py`, `test_owner_chrome_permission_ux.py` |
| `python -X utf8 tests/integration/isolated_rpc_smoke.py` | **PASS (22/22)** | `all_passed: true`, изолированный агент на случайном порту, `no_user_desktop: true` |
| `node --test tests/test_ff_browser_hub.mjs tests/test_p0_browser_hub_mjs.mjs tests/test_browser_companion.mjs` | **PASS (54/54, skipped=1)** | Включая новый тест отказа downloads-only манифеста в `backgroundExtensionPreflight` и флагов неактивации в `extensionConnector.describe()`; 1 skip — ожидаемый пропуск локального `pw165` root |
| `node tests/test_cua_browser_iframe_verify.mjs` | **PASS (8/8)** | Верификация main/child frame URL и fail-closed отказов |

### Оставшиеся ограничения доступности и границы checkpoint

- **Нет развёртывания и изменений на живом контуре:** все правки внесены и проверены
  исключительно в исходниках на синтетических страницах; установленный runtime Bridge/Hub,
  политики `state/hub/policy.json`, настройки Chrome и права живых расширений **не изменялись**.
- **Ожидание предварительного подключения провайдера:** без уже открытого и одобренного
  соединения (активного loopback CDP WebSocket для `owner_chrome_profile1_hidden_secondary`
  либо уже подключённого в фоне `ff_browser_hub.mjs` для `owner_chrome_extension`) маршрут
  `site_read` намеренно отказывает без UI и без авто-подключения, возвращая один
  информативный отчёт возможностей.
- **Видимая полоса вкладок у `owner_chrome_extension`:** даже при неактивной фоновой
  вкладке расширение добавляет вкладку в полосу вкладок Chrome (`visible_tab_strip: true`),
  поэтому никогда не удовлетворяет требованиям `strict_invisible`.
- **Двойной рубеж согласия Chrome 158+:** в режиме `chrome://inspect/#remote-debugging`
  (HTTP 404 `/json/version`) локальный grant Hub не отключает нативный диалог Chrome при
  первичном открытии WebSocket; для полностью невидимой работы без диалогов требуется
  заранее установленное владельцем соединение и единый ожидаемый профиль
  (`OWNER_CHROME_PROFILE_CONTEXT_MISMATCH` при несовпадении профиля).
- **Отсутствие live acceptance в этом checkpoint:** живое испытание с настоящей
  авторизованной страницей в Chrome владельца не выполнялось (намеренно, без вмешательства
  в живой профиль и расширения).


## Checkpoint 21 ноября 2026 (продолжение): фоновые операции с формами в собственных вкладках и `form-regression-fixture`

### Реализованные фоновые операции с формами (поверх staged `site_read`, без изменения политики доступа и без foreground-ввода)

- **`runtime/bridge-v3/ff_browser_hub.mjs` (`owner_chrome_extension` / Hub `browser`):**
  - Чисто DOM-реализация `domSelect` для `<select>` (одиночный и множественный выбор по `value` или тексту опции с отказом `OPTION_NOT_FOUND` до изменения DOM и событиями `input`/`change`) вместо нативного Playwright `locator.selectOption()`, который мог ждать `requestAnimationFrame` в фоновой вкладке.
  - Усилена обработка `check`/`uncheck` (валидация чекбоксов/radio/ARIA-переключателей до клика, запрет `uncheck` для `radio` с `TARGET_NOT_EDITABLE`), `domPress` (`Enter` в `<textarea>` не отправляет форму; на полях/кнопках вызывается единичный `form.requestSubmit()`), `read` для полей `<input>`/`<textarea>`/`<select>` (возврат актуального `.value` и `checked`).
  - Добавлена операция `reload` с проверкой владения вкладкой, проверкой живого хоста `expected_host` (`TAB_HOST_CHANGED` до перезагрузки), обновлением URL/title в `tab-ledger.json` и нулевыми вызовами `bringToFront()`.
  - `extensionConnector.describe()` публикует `form_operations_supported: true`.
- **`runtime/bridge-v3/cua_owner_chrome_secondary.py` (`owner_chrome_profile1_hidden_secondary` / Hub `owner_chrome_hidden`):**
  - Добавлена проверка живого хоста `_check_expected_host` (`TAB_HOST_CHANGED` при клиентском редиректе на неавторизованный хост) перед `act`, `evaluate`, `reload` и `wait_for`, а также атомарная проверка хоста внутри JS-выражения `act`.
  - Добавлены операции `reload` (CDP `Page.reload` с уникальным sentinel `window.__ffhsec_reload` для доказательства реального коммита перезагрузки) и `wait_for` (`WAIT_TIMEOUT`, поддержка `checked_equals` и совместимого формата `{target: {selector}, value, checked, state}`).
  - Расширен `act`: полный набор фоновых DOM-операций `fill`, `click`, `select`, `check`, `uncheck`, `press` (с поддержкой `selector`, `snapshot`+`ref`, `target: {selector|ref|id|name|label}`, отказом `TARGET_NOT_EDITABLE` на `readOnly`/нередактируемых полях, `TARGET_DISABLED`, `OPTION_NOT_FOUND`, `KEY_REQUIRED`, `FOREGROUND_ROUTE_REQUIRED`, `trusted_input: false`, `physical_input_used: false`).
  - Расширены `observe` (`checked`, `readonly`, `selected_text`, `contenteditable`) и `read` (чтение `.value`/`checked`/`selected` у элементов формы).
- **`runtime/bridge-v3/ff_browser_routes.py`, `ff_hub.py`, `ff_hub_mcp.py`, `ff_agent_entry.py`, `cua_agent_workflows.py`:**
  - Планировщик `route_plan(surface="browser", capability="background_tab_form", url=..., visibility="background_tab"|"strict_invisible")` (`schema: "ff-no-interruption-background-form-v1"`): проверяет только уже авторизованные и подключённые провайдеры без UI, без pending-запросов, без изменения `policy.json` и без подмены видимой вкладки при `strict_invisibility=true`; FF Browser Companion `0.1.1` исключается (`COMPANION_DOWNLOADS_AND_NATIVE_MESSAGING_ONLY`).
  - В `ff_hub.py` операция `reload` подключена к журналированию `request_key` (идемпотентность без дублирования) в обоих маршрутах (`browser` и `owner_chrome_hidden`), `wait_for` добавлена в `owner_chrome_hidden`, обновлены `capabilities`, MCP-схема `ff_hub_mcp.py`, `/agent/v1` (`OWNER_CHROME_HIDDEN_COMMANDS`) и `cua_agent_workflows.py`. Операция `site_read` сохранена строго read-only (`SITE_READ_ARG_FORBIDDEN`).

### Зафиксированные тесты и доказательства (`form-regression-fixture`)

| Проверка | Результат | Подтверждённые факты и доказательства |
| --- | --- | --- |
| `python -X utf8 -m unittest tests/test_background_form_operations.py -v` (4 теста) | **PASS (4/4)** | 1) `route_plan(capability="background_tab_form")`: строгая изоляция `strict_invisible`, исключение Companion `0.1.1`, `0` pending-запросов, неизменный SHA-256 `policy.json`, `site_read` остаётся строго read-only. 2) Изоляция владения (`RESOURCE_NOT_OWNED`), запрет `foreground=true` (`FOREGROUND_ROUTE_REQUIRED`), обязательный `request_key` на `act`/`reload`, валидация контролов (`TARGET_NOT_EDITABLE`, `TARGET_DISABLED`, `OPTION_NOT_FOUND`, `KEY_REQUIRED`), отказ при смене хоста (`TAB_HOST_CHANGED`). 3) **Два последовательных сценария fill/edit/save + reload** против синтетической локальной loopback-формы через реальный Node `ff_browser_hub.mjs` (`browser` через `Hub.dispatch` и MCP `Adapter`): WF1 (fill/select/check/click save + повтор того же `request_key` -> `deduplicated: true` + `request_status` + `REQUEST_KEY_REUSED` + `reload` + чтение `rev=1`) и WF2 (чтение данных WF1, edit/select/uncheck/radio/Enter в textarea без отправки/Enter в input save + dedupe + `reload` + чтение `rev=2`); подтверждены ровно **2** отправки на сервере (`0` дублей), `bring_to_front_calls=0`, `native_input_calls=0`, чужая вкладка владельца не закрыта и `blur_count=0`, пустой `tab-ledger.json`, неизменный SHA-256 `policy.json`. 4) **Два последовательных сценария fill/edit/save + reload** через **реальный изолированный Chrome 158** на отдельном Win32 private desktop (`CreateDesktopW`, временный `user_data_dir`, HTTP-404 `DevToolsActivePort` WS-прокси, без доступа к живым аккаунтам и настройкам) через `owner_chrome_hidden` (`Hub.dispatch`, MCP `Adapter`, `/agent/v1`): реальный Chromium DOM/JS/`fetch`/`Page.reload`, `snapshot`+`ref`, ровно **2** отправки на сервере (`0` дублей при повторе ключа и при `reload`), live `TAB_HOST_CHANGED` при клиентском асинхронном редиректе на `localhost`, реальный Win32 мониторинг (`GetForegroundWindow()` без изменений, `new_hwnds=[]`, `any_visible=false`, `any_taskbar=false`), фокус основной вкладки владельца `/owner-active` сохранён (`activeId="owner-draft"`, `blur_count=0`, `visibility_change_count=0`, черновик не тронут), чистый `session_close` (`cleanup_verified=true`, `resources_retained=0`, `0` утекших target в Chrome), неизменный SHA-256 `policy.json` |
| `node --test tests/test_ff_browser_hub.mjs tests/test_p0_browser_hub_mjs.mjs tests/test_browser_companion.mjs` | **PASS (55/55, skipped=1)** | Включая новый тест чистого DOM `domSelect`/`domFill`/`domPress`/`check`/`uncheck` и host-guarded `reload` без `bringToFront` и с `nativeInputCalls=0`; 1 skip — ожидаемый пропуск локального `pw165` root |
| `node tests/test_cua_browser_iframe_verify.mjs` | **PASS (8/8)** | Верификация main/child frame URL и fail-closed отказов |
| `python -X utf8 tests/integration/isolated_rpc_smoke.py` | **PASS (22/22)** | `all_passed: true`, изолированный агент на случайном порту, `no_user_desktop: true` |
| `python -X utf8 -m unittest discover -s tests -p "test_*.py"` | **PASS (791/791, skipped=4)** | Включая `test_manifest_matches_git.py` (**314** bundled source files, точное совпадение LF SHA-256 с Git index), `test_background_form_operations.py` (4/4), `test_no_interruption_site_read.py` (5/5), `test_cdp_discovery_repair.py`, `test_owner_chrome_permission_ux.py`, `test_browser_routes.py`, `test_agent_workflows.py`, `test_skill_contract.py` |

### Ограничения доступности (honest limits)

- **Без доступа к живым аккаунтам, без изменения прав браузера и без деплоя:** все испытания проведены исключительно в исходниках против локальной синтетической loopback-формы (`127.0.0.1`) с временными изолированными профилями/state; живой Chrome владельца, живые пользовательские аккаунты, `state/hub/policy.json`, права расширений и установленный боевой runtime **не затрагивались и не разворачивались**.
- **Предварительно авторизованная и подключённая среда:** операции с формами работают только на собственных вкладках уже авторизованных и подключённых маршрутов Hub (`owner_chrome_hidden` с действующим grant `owner_chrome_hidden_secondary` и одобренным loopback CDP WebSocket либо `browser` с запущенным `ff_browser_hub.mjs` и `browser_own_tabs`); при отсутствии готового провайдера `route_plan(capability="background_tab_form")` отказывает без UI, без pending-запросов и без изменения policy.
- **Границы DOM-ввода (`trusted_input: false`):** фоновые операции отправляют DOM-события без физического ввода; формы, требующие аппаратного `isTrusted: true` ввода, нативных диалогов выбора файлов ОС, drag-and-drop, canvas-виджетов, CAPTCHA, MFA или UAC, не поддерживаются фоновым режимом.
- **Ограничения видимости и рендеринга:** `owner_chrome_extension` добавляет неактивную вкладку в полосу вкладок (`visible_tab_strip: true`) и никогда не удовлетворяет `strict_invisible`; `owner_chrome_profile1_hidden_secondary` работает без OS-окна (`windowless: true`), но не поддерживает `screenshot` (`HIDDEN_TARGET_SCREENSHOT_UNSUPPORTED`); Chrome ограничивает таймеры и `requestAnimationFrame` в фоновых вкладках (`background_tab_timers`).
- **Разделение ответственности при `reload`:** при перезагрузке обычной страницы (`GET` / `fetch`-форма / PRG) `reload` не повторяет POST; если же сторонний сайт использует классическую HTML-форму POST без PRG (Post-Redirect-Get), браузерная перезагрузка самого POST-документа зависит от семантики сервера сайта, поэтому клиент должен проверять URL/состояние до повторной перезагрузки.
- **Отсутствие локального `pw165` root в этой ветке:** 1 Node-тест изолированного Playwright 1.65.1 пропущен (`pw165 root not available`); живой Playwright Extension relay с настоящим профилем владельца намеренно не запускался в этом checkpoint.
