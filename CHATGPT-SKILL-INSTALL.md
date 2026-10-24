# Windows Bridge skill — source packaging and actual host installation

The ChatGPT skill source lives at [skills/windows-bridge/SKILL.md](skills/windows-bridge/SKILL.md). The public `tools/build_skill_plugin.py` builder produces two **skills-only**, no-credential artifacts:

- `Windows-Bridge-ChatGPT-Skill.zip` — `SKILL.md` plus `references/`, for ChatGPT's **Create > Upload from your computer** Skills UI where available.
- `Windows-Bridge-ChatGPT-Plugin.zip` — portable Agent Plugins format with root `plugin.json`, `skills/windows-bridge/` and an onboarding skill. This is a package for plugin installation/testing; it does **not** register an MCP server or publish the plugin itself.

The archives carry no API keys, credentials, Windows hostnames, GitHub token, user private files or pre-authorized grants. **Creating or uploading one of these files does not automatically connect Windows Bridge to a computer.**

## Installation acceptance (not yet proven)

1. Check whether your ChatGPT account/workspace exposes **Plugins > Skills > Create** or a personal plugin upload feature. Availability varies by plan, workspace and region; do not assume it.
2. Install the skill ZIP or plugin ZIP using the supported ChatGPT interface. This installation is a user-controlled action; a GitHub commit or this chat cannot silently install it.
3. In a **new chat**, ask: "Подключись к Cursor через Windows Bridge и сначала проверь программные пути, не используй мой экран." Confirm that the skill was *actually selected*, device identification is correct and the agent performs a no-effect preflight before any modification.
4. Test a harmless authorized read-only Bridge call; verify route and evidence. For foreground-only tests, the trusted ChatGPT host must supply an authenticated owner-grant; the skill may not fabricate it.
5. Record observed install ID and activation evidence **privately**. Only after this trial mark new-chat skill acceptance PASS.

The connected Windows Bridge MCP plugin is separate from this skills-only package. A skills-only plugin can guide existing connected MCP tools, but does not grant app connection or device scope.

Official references: https://help.openai.com/en/articles/20001066-skills-in-chatgpt and https://developers.openai.com/plugins/build/plugins .

## Build / verify

```powershell
python tools/build_skill_plugin.py --mode skill --output dist/Windows-Bridge-ChatGPT-Skill.zip
python tools/build_skill_plugin.py --mode plugin --output dist/Windows-Bridge-ChatGPT-Plugin.zip
python -m unittest discover -s tests -v
```

This is P0 preparation, not proof of app-level task automation, installed skill activation, or secure chat-to-Bridge Permission Broker.
