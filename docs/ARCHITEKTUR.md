# Architektur tofu-agent-gate

Generisches Gate um OpenTofu für Änderungen, die Agenten vorschlagen. Nichts hier ist UniFi-spezifisch. Python 3.13, nur Standardbibliothek und PyYAML.

## Module

| Modul | Aufgabe |
|---|---|
| `config.py` | `gate.yaml` laden. Pfad aus `GATE_CONFIG`, Default `/etc/tofu-agent-gate/gate.yaml` |
| `plan.py` | Plan-JSON (`tofu show -json`) lesen: Änderungen, Aktionen, sensible Werte maskieren, Zusammenfassung |
| `policy.py` | Policy-Engine: `auto`, `review`, `approval` oder `reject` je Plan |
| `delegate.py` | Beauftragter Prüfer für die Stufe `review` (Befehl mit JSON auf stdin und stdout) |
| `redact.py` | Generische Redaction für alles, was nach außen geht (Telegram, Logs, Ergebnisdateien) |
| `telegram.py` | Dünner Client für die Bot-API, Transport austauschbar (Tests ohne Netz) |
| `approve.py` | Freigabe per Inline-Buttons, gebunden an Plan-Hash, einmalig, mit Ablauf |
| `tofu.py` | Aufrufe von `tofu` als Subprozess, austauschbar für Tests |
| `gitops.py` | Branches holen, Pfad-Prüfung, Merge, Push, Branch löschen |
| `hooks.py` | Externe Prüf-Hooks ausführen (Invarianten, Health-Checks, Snapshot) |
| `deadman.py` | Rollback-Timer per `systemd-run` einplanen und abbrechen |
| `runner.py` | Ablauf je Branch, Lock, STOP, Rollback |
| `cli.py` | `python -m tofu_agent_gate <befehl>` |

## Sicherheitsmodell

1. **Agenten liefern Daten, keine HCL** (Default). Erlaubte Pfade im Branch stehen in `gate.yaml` (`repo.allowed_paths`, Glob). Berührt der Branch andere Dateien als die Merge-Basis, wird er abgelehnt, bevor `tofu` läuft. Grund: Beliebige HCL kann beim `plan` Code ausführen oder den API-Key abgreifen (fremde Provider, Provisioner, Backend, `api_url`).
2. **Provider-Allowlist:** `tofu` läuft mit einer CLI-Konfiguration des Runners (`TF_CLI_CONFIG_FILE`) mit `filesystem_mirror` und ohne `direct`. Andere Provider lassen sich nicht installieren.
3. **Backend kommt vom Runner:** aus der Override-Datei `zz_gate_override.tf`, die der Runner vor jedem `init` schreibt. Die State-Verschlüsselung steht in der HCL aus `main` (`enforced = true`), die Passphrase kommt als `TF_VAR_...` aus der Env-Datei des Runners.
4. **Variablen-Allowlist:** `repo.allowed_variables` begrenzt die obersten Schlüssel in `*.tfvars.json`. Sonst könnte ein Agent per `*.auto.tfvars.json` (Vorrang vor `TF_VAR_*`) z. B. die Passphrase überschreiben.
5. **Plan-Identität:** SHA-256 von `plan.bin`. Freigabe und Apply beziehen sich auf genau diesen Hash. Vor dem Apply wird er erneut berechnet.
6. **Policy und Hooks liegen außerhalb des Repos** (root-owned), der Gate-Code kommt aus einem Release-Tag.
7. **Ausgaben nach außen** gehen immer durch `redact.py` und optional durch eine weitere Redaction-Funktion (`redaction.extra`, Importpfad `modul:funktion`).

## gate.yaml

```yaml
state_dir: /var/lib/tofu-agent-gate        # Läufe, Freigaben, Offsets, Backups
stop_file: /etc/tofu-agent-gate/STOP
lock_file: /run/tofu-agent-gate.lock
keep_work_dirs: 10                         # Arbeitsordner (Pläne, Snapshots) abgeschlossener Läufe
min_free_percent: 10                       # sonst wartet der Branch (Platz und Inodes im state_dir), 0 = aus
max_branches_per_run: 0                    # >0: höchstens so viele Branches je run-once, dann Lock frei
drain_minutes: 0                           # >0: Rest gleich abarbeiten, solange der Lauf jünger ist
drain_pause_seconds: 15                    #     dazwischen Lock so lange frei (andere Dienste)
discard_pending_on_stop: true              # nach fehlgeschlagenem Rollback wartende Branches verwerfen

repo:
  url: ssh://git@git.example/infra/config.git
  workdir: /var/lib/tofu-agent-gate/repo
  main: main
  branch_prefix: desired/
  allowed_paths: ["tofu/*.auto.tfvars.json"]
  allowed_variables: [dns_records]          # None = keine Prüfung
  ssh_key: /etc/tofu-agent-gate/deploy_key  # optional, Push auf main nötig
  commit_url: "https://git.example/infra/config/commit/{sha}"   # optional, für Telegram
  author: {name: tofu-agent-gate, email: gate@localhost}

tofu:
  binary: /usr/local/bin/tofu
  dir: tofu                        # Unterordner im Repo
  env_file: /etc/tofu-agent-gate/tofu.env      # Provider-Credentials, TF_ENCRYPTION
  cli_config: /etc/tofu-agent-gate/tofu.tfrc
  state_path: /var/lib/tofu-agent-gate/tofu/terraform.tfstate
  state_backups: 30

policy: /etc/tofu-agent-gate/policy.yaml

approval:
  telegram_env: /etc/tofu-agent-gate/telegram.env
  timeout_minutes: 30
  delegate_command: []             # Stufe review: argv des Prüfers, leer = review wie approval

deadman:
  minutes: 10
  unit_prefix: tofu-agent-gate-rollback

hooks:                             # argv-Listen, leer = aus
  env_file: /etc/tofu-agent-gate/hooks.env   # Secrets nur für die Hooks
  timeout: 300
  snapshot: []                     # schreibt einen Snapshot nach $GATE_SNAPSHOT_OUT
  pre_apply: []                    # Invarianten auf dem geplanten Zustand
  post_apply: []                   # Health-Checks und Invarianten auf frischem Export
  post_rollback: []                # nach dem Rollback: frischer Export gleich Snapshot vorher?
  recover: []                      # nach STOP (Befehl recover): darf das Gate von selbst weiterlaufen?

redaction:
  extra: null                      # z. B. "unifi_snapshot.normalize:redact_text"
```

## Hook-Schnittstelle

Ein Hook ist eine argv-Liste. Das Gate setzt diese Umgebungsvariablen:

| Variable | Inhalt |
|---|---|
| `GATE_RUN_ID` | ID des Laufs |
| `GATE_PHASE` | `snapshot`, `pre_apply`, `post_apply`, `post_rollback` oder `recover` |
| `GATE_PLAN_JSON` | Pfad zum Plan-JSON. Bei `post_rollback` ein leerer Plan, erwartet ist keine Änderung |
| `GATE_REPO_DIR` | Checkout, der geplant wurde |
| `GATE_SNAPSHOT_OUT` | nur `snapshot`: Zielordner |
| `GATE_SNAPSHOT_BEFORE` | Snapshot vor dem Apply (falls Snapshot-Hook gesetzt) |
| `GATE_SNAPSHOT_AFTER` | `post_apply`: frischer Snapshot nach dem Apply, `post_rollback`: nach dem Rollback |
| `GATE_APPROVED_WARNINGS` | nur `post_apply`, nur nach Freigabe mit Warnung: JSON-Datei mit den freigegebenen Verstößen aus `pre_apply` |

Ausgabe auf stdout als JSON:

```json
{"ok": false, "violations": [{"id": "tor-no-external", "message": "..."}]}
```

Exitcode 0 = ok, 1 = Verstöße, alles andere = Fehler. Fehler zählen wie Verstöße.

Freigebbare Verstöße: Meldet `pre_apply` mit Exitcode 0 und `"ok": true` Verstöße mit
`"severity": "approve"` (optional `"title"` als kurzer Text), wendet das Gate nie automatisch an.
Es holt eine Freigabe, die jede Warnung zeigt, auch wenn die Policy `auto` ergeben hätte.
Nach der Freigabe bekommt `post_apply` die Verstöße per `GATE_APPROVED_WARNINGS`, damit der
Hook sie z. B. als dauerhafte Ausnahme speichern kann. Mit Exitcode 1 zählt `severity` nicht. Timeout pro Hook 300 s.

## Policy (policy.yaml)

```yaml
version: 1
vars:                               # Platzhalter für Regeln, z. B. Zonen-IDs
  zone_iot: "<zone-id>"
  zone_lab: "<zone-id>"
  zone_mgmt: "<zone-id>"
limits:
  max_changes: 10
  allow_delete: [unifi_dns_record]
  allow_replace: []
forbidden:                          # gilt auch für Rollbacks
  - type: unifi_setting
  - type: unifi_port_forward
  - references: ["$zone_mgmt"]       # Wert irgendwo in before oder after
  - address: "unifi_firewall_policy.iac_*"
rules:                              # erste passende Regel gewinnt
  - level: auto
    type: unifi_dns_record
  - level: auto
    type: unifi_firewall_policy
    actions: [create, update]
    where:
      source.zone_id: {in: ["$zone_iot", "$zone_lab"]}
      destination.zone_id: {in: ["$zone_iot", "$zone_lab"]}
default: approval
```

- Geprüft wird jede Ressource aus `resource_changes` mit Aktion ungleich `no-op` (`read` zählt nicht).
- **Gesamtergebnis:** das strengste Einzelergebnis, mit der Reihenfolge `auto` < `review` < `approval` < `reject`.
- **`review`:** Ein beauftragter Prüfer (`approval.delegate_command`) entscheidet zuerst. `approve` wendet an, `deny` lehnt ab (Begründung landet im Lauf und in der Meldung), `escalate`, Exit ungleich 0, ungültige Ausgabe oder Zeitüberschreitung fragen per Telegram wie bei `approval`, mit dem Hinweis des Prüfers. Ohne Prüfer ist `review` gleich `approval`. Freigebbare Verstöße aus `pre_apply` heben jeden Plan auf `approval`, der Prüfer sieht sie nie.
- **Wann `reject`:** bei `forbidden`, bei überschrittenem Limit, bei `delete` oder `replace` ohne Erlaubnis, bei unbekannter `mode`, sowie bei einem Plan mit Fehlern oder `errored: true`.
- **`where`:** Pfad mit Punkten in `before` und `after`. Beide Seiten müssen passen, sonst könnte ein Update aus einer erlaubten Zone in eine verbotene wandern.
- **Rollback-Modus:** Es gilt nur `forbidden`. Limits und Freigabe entfallen.

## Freigabe (approve.py)

```python
api = TelegramApi(token, transport=None)          # transport(method, params) -> dict, für Tests
approver = Approver(api, owner_user_id, owner_chat_id, store_dir, redact=fn, clock=time.time)
result = approver.request(plan_hash=..., summary=..., agent_reason=..., link=..., timeout_s=1800)
# ApprovalResult(approved: bool, reason: str, request_id: str, note: str)
result = approver.request(..., delegate=True)      # Stufe review: erst delegate(request) -> Verdict
approver.notify(text)
```

- **Nachricht:** `sendMessage` ohne `parse_mode`, mit Inline-Buttons Accept und Decline.
  - `callback_data` hat die Form `<request_id>:a` oder `<request_id>:d`. `request_id` sind 16 Hex-Zeichen aus `secrets`.
  - Die Anfrage wird in `store_dir` gespeichert (offen/erledigt, `message_id`, Plan-Hash, Ablauf). Dadurch greifen Replay-Schutz und Ablauf auch über Neustarts.
- **Ein Klick zählt nur, wenn alles zutrifft:**
  - `from.id` ist der Owner und `message.chat.id` ist der Owner-Chat.
  - `message.message_id` ist die gespeicherte ID.
  - Die Anfrage ist offen und nicht abgelaufen.
  - Der gespeicherte Plan-Hash ist der angefragte.
- **Andere Klicks:** `answerCallbackQuery` mit Hinweis, sonst nichts.
- **Danach:** `answerCallbackQuery` und `editMessageText` mit dem Ergebnis, ohne Buttons. Timeout zählt als Decline.
- **Text:** höchstens 4096 Zeichen, sonst kürzen und den Link anhängen. Die Begründung des Agenten steht getrennt unter "Begründung des Agenten (ungeprüft):" und wird auf 800 Zeichen gekürzt.
- **Prüfer (`delegate=True`):** `delegate.CommandDelegate(argv)` bekommt `{request_id, plan_hash, summary, agent_reason, link, timeout_s}` (redigiert) auf stdin und liefert in der letzten JSON-Zeile `{decision: approve|deny|escalate, by, note}`. approve und deny gehen ohne Telegram (`reason` `delegated` bzw. `delegate_denied`, `decided_by` `delegate:<by>` im Store), alles andere fällt auf die Telegram-Freigabe zurück.
- **Long Polling:** `getUpdates` mit `allowed_updates=["callback_query"]`. Der Offset wird in `store_dir` gespeichert.

## Ablauf je Branch (runner.py)

1. **Vorbedingungen:** STOP-Datei vorhanden: nichts tun. Lock holen (`flock`).
2. **Branches holen:** `git fetch --prune`, alle `origin/<prefix>*` mit neuem Kopf-Commit. Ein Branch, dessen letzter Kopf schon ein Ergebnis hat, wird übersprungen.
3. **Arbeitsstand:** `origin/main` plus Branch in einem temporären Merge.
   - Pfad-Prüfung auf `git diff --name-only <merge-base> <branch>`.
   - Ein Konflikt führt zur Ablehnung.
4. **Plan:** Override-Datei schreiben, `tofu init`, `tofu plan -out=plan.bin`, `tofu show -json`, Hash berechnen.
5. **Prüfungen:** Policy, dann `pre_apply`-Hooks. Ein Verstoß führt zu `reject`.
6. **Freigabe:** bei `approval` per Telegram.
7. **Apply vorbereiten:**
   - `last-good` ist der Commit von `origin/main`.
   - State-Backup anlegen und Snapshot vorher ziehen.
   - Dead-Man einplanen.
8. **Apply:** Plan-Hash erneut prüfen, dann `tofu apply plan.bin`.
9. **Health-Checks:**
   - Der Plan auf demselben Stand muss leer sein (`-detailed-exitcode` = 0).
   - Snapshot nachher ziehen, dann die `post_apply`-Hooks ausführen.
10. **Ergebnis:**
    - Erfolg: Dead-Man abbrechen, Merge-Commit nach `main` pushen, Branch löschen, keine Meldung (Erfolg ist der Normalfall).
    - Fehler: Rollback sofort, Ergebnisdatei, Meldung, Branch bleibt.

Ergebnisdateien liegen unter `state_dir/runs/<run_id>.json` und werden nicht ins Repo geschrieben, damit Agenten keinen Push auf `main` brauchen.

## Rollback

`python -m tofu_agent_gate rollback <run_id>` läuft sofort im Fehlerfall oder über den Dead-Man-Timer:

1. **Hängenden Lauf beenden:** Lebt der Lauf noch (PID in der Laufdatei), wird seine Prozessgruppe beendet, erst mit TERM, nach 20 s mit KILL.
2. **Lock und Ziel:** Lock holen und `last-good` auschecken.
3. **Planen und prüfen:** `plan`, dann Policy im Rollback-Modus (nur `forbidden`).
4. **Anwenden und prüfen:** `apply`, danach muss ein erneuter Plan leer sein.
5. **Mit dem Stand vor dem Apply vergleichen** (nur mit `post_rollback`-Hook):
   - Ein leerer Plan reicht nicht. Behandelt der Provider null als "nicht anfassen", bleibt ein gerade gesetztes Feld stehen.
   - Frischen Snapshot nach `state_dir/work/<run_id>/snapshot-after-rollback` ziehen, dann `post_rollback` mit `snapshot-before` und einem leeren Plan ausführen.
   - Fehlt der Snapshot vorher oder meldet der Hook einen Verstoß, gilt der Rollback als fehlgeschlagen.
6. **Melden:** Erfolg oder Fehlschlag per Telegram. Bei Fehlschlag setzt der Rollback die STOP-Datei, damit nichts weiterläuft, bis ein Mensch draufschaut.
7. **Warteschlange verwerfen** (bei Fehlschlag, `discard_pending_on_stop`, Standard an): Alle noch nicht gelaufenen Branches bekommen einen Lauf mit Status `discarded` und gelten als gesehen. Sie wurden gegen einen Stand geschrieben, der nicht mehr gilt, und liefen sonst nach dem Aufheben von STOP ungeprüft durch. Die Telegram-Meldung nennt sie. Neuer Versuch = neuer Commit.

### Wiederanlauf nach STOP (`recover`)

`python -m tofu_agent_gate recover` läuft per Timer (z. B. alle 10 min) und hebt einen STOP nach `rollback_failed` selbst auf, wenn der Stand wieder stimmt. Von Hand oder vom Deploy gesetzte STOP-Dateien bleiben unberührt: Erkannt wird nur die erste Zeile `Rollback <run_id> fehlgeschlagen` zu einem Lauf mit Status `rollback_failed`.

1. **Je STOP einmal prüfen** (Lock): main frisch planen, Policy im Rollback-Modus. Ist der Plan leer, frischen Snapshot nach `work/<run_id>/snapshot-recover` ziehen und den `recover`-Hook mit `snapshot-before` des Laufs ausführen. Bestandener Hook mit Meldungen = nur Hinweise.
   Ist der Plan von main nicht leer, der des gescheiterten Laufs (`merge_commit`) aber schon, war der Apply durch und erst die Prüfung danach scheiterte (z. B. Platte voll). Dann ist der schon freigegebene Branch-Stand das Ziel: Hook mit dem Plan des Laufs, bei Grün den Branch nach main übernehmen wie nach einem gelungenen Lauf (Status `applied`).
2. **Grün** (Plan leer, Hook ohne Verstoß): STOP nach `state_dir/STOP-<datum>-<run_id>.txt` kopieren und entfernen, Meldung "Gate läuft wieder" mit den Hinweisen.
3. **Sonst eine Freigabe:** Accept wendet main erneut an, falls der Plan nicht leer war (nur wenn ein frischer Plan noch dieselben Änderungen zeigt), und hebt den STOP auf. Decline lässt ihn stehen, das Gate fragt zu diesem STOP nicht mehr. Ohne Antwort fragt es frühestens nach `recover_reask_hours` (Standard 6) erneut.
4. Stand in `state_dir/recover.json` (Schlüssel = Hash der STOP-Datei). Ein neuer Inhalt der STOP-Datei gilt als neuer STOP.

Ohne `recover`-Hook hebt das Gate einen STOP nie von selbst auf, es fragt immer.
