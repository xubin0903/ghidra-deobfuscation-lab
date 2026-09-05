# docs/

| Path | What |
|---|---|
| [install.md](install.md) | Fetch / extract / JDK 21 / launch |
| [using-scripts.md](using-scripts.md) | Script Manager, headers, other projects |
| [headless.md](headless.md) | `analyzeHeadless` wrapper |
| [scripts/](scripts/README.md) | One page per script |
| [cookbook/](cookbook/README.md) | Obfuscation playbooks |
| [emulator-migration.md](emulator-migration.md) | `EmulatorHelper` → `PcodeEmulator` evaluation for the CFF engine (12.1.3 API mapping, plan) |

When you add a script, add `docs/scripts/<Name>.md` in the **same change**. When you hit a new obfuscation family, add a cookbook page even if the script does not exist yet.
