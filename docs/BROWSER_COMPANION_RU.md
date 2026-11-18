# FF Browser Companion

Companion связывает загрузки Chrome с локальным Windows Bridge через Native Messaging. Расширение использует разрешения `downloads` и `nativeMessaging`. Для работы со страницей, DOM и вкладками используются соответствующие маршруты Bridge.

## Диагностика соединения

- `browser_companion` в диагностике Bridge показывает, ответил ли локальный host, совместим ли протокол и доступен ли Chrome Downloads API. Ответ `native_connection.state=CONNECTED` подтверждает обмен с worker расширения. Наличие файлов установки или записи Native Messaging в реестре само по себе подтверждает только конфигурацию host.
- Для локальной диагностики в согласованном профиле откройте инспектор service worker на странице `chrome://extensions` и выполните `globalThis.ffCompanionDiagnostics()`. Ответ содержит состояние, короткий код разрыва и число попыток. В Chrome for Testing проверяется `HOST_NOT_FOUND` при отсутствующем host. После регистрации worker восстанавливает соединение с увеличивающимся интервалом между попытками.
- `HOST_FORBIDDEN` указывает на отказ Chrome в допуске к host. Проверьте `allowed_origins` и ID расширения. При `HOST_PIPE_BUSY` другой экземпляр host уже обслуживает этот runtime. Для проверки используйте отдельный runtime и тестовый профиль. При `HOST_EXITED` ищите короткий код host в stderr, например `BRIDGE_SECRET_MISSING`, и проверьте файлы регистрации через штатный установщик.
- Host проверяет origin расширения, Windows SID на pipe и секрет соседнего runtime. Для нестандартных каталогов канал именуется по каталогу. Подключение к bridge не устанавливает связь между конкретной вкладкой Playwright и профилем Companion. Chrome сообщает URL и метаданные события загрузки, а результат сверяется с каталогом `FF-CUA/<operation_id>/`. При неоднозначности или недоказанном пути удаление отклоняется.

## Проверка кандидата на Windows

Из корня репозитория запустите тесты с путём к заранее установленному Chrome for Testing. Скрипт собирает host в новом каталоге, запускает отдельный headless Chrome с чистым профилем, регистрирует временное уникальное имя host и удаляет только свою запись. Проверяются ошибка отсутствующей регистрации, последующий handshake, отказ для неверного секрета, завершение idle host после закрытия stdin, SHA-256 файлов и cleanup. Для штатного Chrome назначение расширения и разрешения проверяются в профиле отдельно.

```powershell
node --test tests/test_browser_companion.mjs
python -X utf8 tests/integration/browser_companion_native_smoke.py --chrome-for-testing <chrome-for-testing.exe> --downloads 35
```

Сборка host отдельно без изменения регистрации Chrome доступна через `cua_browser_companion_install.ps1 -BridgeRoot <новая-папка> -SkipChromeRegistration`. В рабочем runtime установка обновляет конкретные файлы расширения и host. После обновления проверьте handshake версии `0.1.1` в диагностике.
