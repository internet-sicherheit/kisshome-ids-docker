# KISSHome-IDS-Watchdog

Das Skript install-kisshome-ids-watchdog.sh biete die Möglichkeit einen Zeitgesteuerten systemd Service zu installieren der das KISSHome IDS überwacht und bei Fehlerzuständen neustartet.

Gleichzeitig überwacht der kisshome-ids-watchdog Service die aktuelle IDS Version und aktuallisiert das Docker Image bei Bedarf.

Der kisshome-ids-watchdog kann bei installiertem Docker auch direkt genutzt werden um einen KISSHome-IDS Container zu starten.

**Achtung:** Wenn Sie das KISSHome-IDS bereits in einem Container betreiben, beenden sie diesen Container bevor Sie das KISSHome-IDS-Watchdog Skript installieren. Der Container wird spätestens 2 Minuten nach der Installation neu gestartet.

## Voraussetzungen

* bash
* Docker
* curl
* jq **oder** python3

## Installieren des kisshome-ids-watchdog

Laden Sie sich das Skript install-kisshome-ids-watchdog.sh herunter **entweder** mit

```
curl -L -o install-kisshome-ids-watchdog.sh \
https://raw.githubusercontent.com/internet-sicherheit/kisshome-ids-docker/main/KISSHome-IDS-Watchdog/install-kisshome-ids-watchdog.sh
```
**oder**
```
wget -O install-kisshome-ids-watchdog.sh \
https://raw.githubusercontent.com/internet-sicherheit/kisshome-ids-docker/main/KISSHome-IDS-Watchdog/install-kisshome-ids-watchdog.sh
```

und führen Sie es mit 

```
sudo bash install-kisshome-ids-watchdog.sh --shared-path /home/username/kisshome-ids --port 5000
```

aus. Beachten Sie das die Angabe eines Pfades zum speichern von persistenten Dateien **Notwendig** ist. Die Angabe einer Port-Nummer abweichend von 5000 ist optional.

Bei der Installation wird das KISSHome-IDS-Watchdog Skript nach /usr/local/bin/kisshome-ids-watchdog.sh installiert. Außerdem wird ein systemd Service 'kisshome-ids-watchdog.service' und ein systemd Timer 'kisshome-ids-watchdog.timer' angelegt und gestartet.


## Deinstallieren des kisshome-ids-watchdog

Mit
```
sudo bash install-kisshome-ids-watchdog.sh --uninstall
```
wird das zuvor installierte Skript sowie der systemd Timer und der systemd Service gestoppt und entfernt.

**Achtung** Der IDS Container selbst wird hier durch **weder gestoppt, noch entfernt**.
