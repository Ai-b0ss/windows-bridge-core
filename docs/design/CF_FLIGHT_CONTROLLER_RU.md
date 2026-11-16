# FlightController + ContextShield v0.5.2 (Cloudflare MCP транспорт)

Универсальный транспортный модуль `tools/cf-flight-controller/flight-controller.mjs` для всех MCP-клиентов (`Gemini 4 Carbon`, `GPT-6 Sol`, `Claude` и др.), работающих поверх WebSocket-туннеля Cloudflare Durable Object (жёсткое окно кадра 20 000 мс).

## Ключевые механизмы (`v0.5.2-flight-controller-shield`)

1. **Бесшовный перевод долгих вызовов в асинхронный поллинг (`12.5s` soft window)**:
   - Быстрые вызовы завершаются синхронно со 100% обратной совместимостью схемы `ff-win-v3-result-v1`.
   - Вызовы дольше `12.5s` возвращают самодокументируемый билет `ff-win-v3-flight-ticket-v1` (`next_action: __flight_poll`) и продолжают выполнение в фоне.
2. **Защита от повторного выполнения при обрыве ответа (`OUTCOME_UNKNOWN` + сверка `request_status`)**:
   - Если ошибка возникла **до** отправки HTTP-запроса (`beforeDispatch === true`), ключ освобождается безопасно.
   - Если соединение с локальным Bridge оборвалось **после** отправки запроса (`socket.destroy()`, `ECONNRESET`, рестарт агента), рейс переходит в состояние `OUTCOME_UNKNOWN` и сохраняет привязку `dedupe_key -> flight_id` (включая `request_id` и точный `backend_url`) в `flights-journal.json`.
   - На стороне `ff_win_v3_main.py` вызовы с `dedupe_key` регистрируются в SQLite `RequestJournal` (`dk-<sha256>`). При повторном вызове с тем же `__dedupe_key` `FlightController` сначала запрашивает `request_status(op, dedupe_key)` **именно у того backend-порта, куда ушёл исходный запрос**:
     - если действие зафиксировано (`state: "completed"`), клиенту возвращается сохранённый ответ (`reconciled: true`, `deduped_replay: true`) без повторного выполнения;
     - если журнал подтверждает отсутствие записи на том же экземпляре (`state: "not_found", dedupe_journal_v1: true`), разрешается повтор с сохранением исходного `request_id`;
     - если исход не определён или первичный порт недоступен (при переключении `selectBackend` на резервный порт с отдельным журналом), выбрасывается `FlightOutcomeUnknownError` (`retry_safe: false`) с тем же `request_id` и **строго нулём повторных запусков**.
3. **ContextShield (построчный + символьный бюджет)**:
   - Сворачивает как многострочные простыни терминала, так и однострочные минифицированные JSON-ответы свыше 20 000 символов в компактный дайджест с извлечением строк ошибок из середины и записью полного оригинала в ротируемый `spillover/`.
