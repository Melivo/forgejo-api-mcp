# Gebündelter API-Vertrag

**Status:** Verifiziert
**Entscheidung:** Der Forgejo-Swagger-Snapshot wird mit dem Python-Paket
ausgeliefert und beim Start lokal normalisiert.

## Kontext

Der Server muss hunderte Forgejo-Operationen konsistent entdecken, validieren und
serialisieren. Ein Laufzeitabruf würde Start und Verhalten von Netzwerkzustand,
Serverrechten und einem veränderlichen Upstream-Vertrag abhängig machen.

## Betrachtete Optionen

1. Einen geprüften Snapshot bündeln und Änderungen bewusst übernehmen.
2. Die Spezifikation bei jedem Start von Forgejo laden.

## Begründung

Option 1 macht Start, Tests und Paketinstallation reproduzierbar. Der Katalog kann
lokale Referenzen auflösen, Operationen unveränderlich indexieren und dieselben
Verträge in Discovery und Invocation verwenden.

## Konsequenzen

- Snapshot und Adapter können hinter dem Forgejo-Server zurückliegen.
- Jede Snapshot-Aktualisierung braucht das Verfahren aus
  [../maintenance.md](../maintenance.md).
- Die vollständige Konformitätsprüfung muss weiterhin jede katalogisierte
  Operation abdecken.
- Laufzeitcode darf keinen automatischen Spezifikationsabruf ergänzen.
