# migrations/

One directory per breaking upgrade, named `vFROM-to-vTO/`, each containing:

- **`MIGRATION.md`** — what changed, why, and before→after for every breaking change, plus an
  agent-applicable find→replace rule list.
- **`migrate-check.sh`** — a read-only checker: point it at your repo
  (`./migrate-check.sh /path/to/your/service`) and it prints every call site you must change, with
  the fix, and exits non-zero if any remain (gate CI on it). It never edits your code.

Upgrading across several versions? Run each version's checker in order.
