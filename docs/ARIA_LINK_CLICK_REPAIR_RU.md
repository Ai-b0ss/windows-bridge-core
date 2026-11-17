# Семантический клик по ARIA link

Наблюдение DOM, поиск по тексту и поиск по ARIA-роли исключали `div[role=link]`
из списка элементов с действием `click`. Поэтому BrowserSidecar отклонял действие
до вызова Playwright, хотя `locator.click()` поддерживает такой элемент.

Изменены только три одинаковых селектора определения действий: добавлен
`[role="link"]`. Проверки владения вкладкой, поколения, fingerprint, точного
разрешения элемента и неоднозначности сохранены. События DOM вручную не
генерируются; применяется обычный `locator.click()` с проверками Playwright.

`tests/browser_aria_link.test.mjs` запускает настоящий временный headless Chromium
на синтетическом документе: все три способа обнаружения, настоящий browser click,
native links/buttons, неприменимость к note, stale ref, неоднозначность и чужая
вкладка. Проверены также отказ исполнения click для note и отказ act на чужой
вкладке. Это проверка адаптера, а не доказательство входа в Google.

Запуск из корня клона (установленный pinned runtime либо module URI через
`FF_TEST_PLAYWRIGHT_MODULE`; `FF_TEST_CHROME` задаёт установленный Chrome):

```powershell
node --test tests/browser_aria_link.test.mjs
python -X utf8 -m unittest discover -s tests -p 'test_*.py'
python -X utf8 tests/integration/isolated_rpc_smoke.py
```

Во время чужих задач патч не устанавливать и общий runtime не перезапускать.
Применять через обычный процесс обновления после освобождения Bridge, с резервной
копией, проверкой Git bytes/hashes и откатом. В этом изменении установка,
перезапуск, изменение Chrome и разрешений не выполняются.

При переносе на актуальный main заново сформировать manifest штатным builder:
`python tools/build_portable_release.py --repo . --refresh-source-manifest`.
На Windows сохранить результат с LF перед `git add`, затем проверить
`python -m unittest discover -s tests -p test_manifest_matches_git.py`.
Checked-in manifest служит шаблоном: актуальную identity поставки формируют
release builder и транзакционный deployer из точного commit.

Передача слушающего сокета сохраняет транспорт и старые терминальные сессии,
но сама по себе не заменяет уже импортированный ESM-модуль браузерного sidecar.
Без отдельно доказанного сохранения browser surfaces общий runtime не обновлять.
Изменение `.mjs` также исключает режим холодного восстановления с сохранением
живого резервного порта, разрешающий только Python-файлы и manifest.

Проверенный обход для текущего запуска — самостоятельный выбор владельцем своего
разрешённого аккаунта в открытом chooser. `role=link` сам по себе не реализует
клавиатурное поведение; успех Enter нельзя считать гарантированным.
