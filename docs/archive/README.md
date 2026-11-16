# Архив исторических спецификаций и служебных реестров

В этом каталоге хранятся ранние проектные черновики и одноразовые реестры сопровождения, замещённые действующими промышленными механизмами ядра Windows Bridge v3.

| Архивный файл | Статус | Действующая замена |
| :--- | :--- | :--- |
| `SEAMLESS_UPDATE.md` | Замещён (старая схема `SO_REUSEADDR` вызывала `WinError 10054` под нагрузкой) | [`../design/WINDOWS_SOCKET_HANDOVER_RU.md`](../design/WINDOWS_SOCKET_HANDOVER_RU.md) — бесшовная передача слушающего сокета WinSock (`socket.share` / `adopt_listener`) |
| `TEMPORARY_SKILL_PILOT.md` | Выведен из штатного контура (`enabled: false` по умолчанию) | [`../design/SKILL_FIRST_PERMISSION.md`](../design/SKILL_FIRST_PERMISSION.md) и [`../design/PER_WINDOW_GRANTS.md`](../design/PER_WINDOW_GRANTS.md) |
| `WB02_CHAT_CONSENT_PROTOCOL.md` | Исторический challenge-черновик (опциональный строгий режим) | [`../design/SKILL_FIRST_PERMISSION.md`](../design/SKILL_FIRST_PERMISSION.md) (`owner_chat_permission` + защёлка `cua_owner_stop.py`) |
| `P0_DURABLE_RECOVERY.md` | Ранний черновик журнала идемпотентности | [`../design/P0_DURABLE_TASK_RECOVERY.md`](../design/P0_DURABLE_TASK_RECOVERY.md) |
| `merged-branches-2026-11-14.json` | Исторический реестр SHA-хешей 62 слитых веток от 14.11.2026 | [`../REPOSITORY_MAINTENANCE_RU.md`](../REPOSITORY_MAINTENANCE_RU.md) |
