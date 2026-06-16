# Logging & Linux Deployment

This document explains how application logs are saved to local files and how to
deploy the backend on a Linux server. The same build works on Windows (dev) and
Linux (prod) with no code changes.

---

## 1. Logging

Logging is configured in [`src/main/resources/logback-spring.xml`](../src/main/resources/logback-spring.xml).

### Log files produced

| File                        | Contents                              |
|-----------------------------|---------------------------------------|
| `payment-app.log`           | All logs (INFO and above by default)  |
| `payment-app-error.log`     | ERROR-level logs only                 |
| `payment-app.json`          | Structured JSON logs (only in `json` profile) |

Files roll over **daily or at 10 MB**, are gzipped, kept for **30 days**, and the
total size is capped (1 GB for the main log) so they never fill the disk.

### Where logs are written

The directory is resolved in this order (first match wins):

1. `LOG_PATH` environment variable — e.g. `export LOG_PATH=/var/log/payment-app`
2. `log.path` property — e.g. `--log.path=/var/log/payment-app`
3. Default `logs/` folder next to the running app

### Plain text vs JSON

- **Default** (no profile): human-readable console + plain-text files.
- **JSON** (for ELK / Grafana Loki): activate the `json` Spring profile.

```bash
# Plain text (default)
java -jar app.jar --log.path=/var/log/payment-app

# Structured JSON
java -jar app.jar --log.path=/var/log/payment-app --spring.profiles.active=json
# or
SPRING_PROFILES_ACTIVE=json LOG_PATH=/var/log/payment-app java -jar app.jar
```

> Tests use `src/test/resources/logback-test.xml`, which logs to console only and
> never creates files.

---

## 2. Deploy on Linux with systemd

Files live in the [`deploy/`](.) folder:

| File                       | Purpose                                  |
|----------------------------|------------------------------------------|
| `payment-app.service`      | systemd unit (auto-start, auto-restart)  |
| `install.sh`               | One-shot install/upgrade script          |
| `payment-app.env.example`  | Template for secrets & overrides         |

### Quick start

```bash
# 1. Build the jar
mvn clean package -DskipTests

# 2. Install + start as a service (creates user, dirs, copies jar & unit)
sudo bash deploy/install.sh
```

### Manage the service

```bash
sudo systemctl status payment-app      # current status
sudo systemctl restart payment-app     # restart
sudo journalctl -u payment-app -f      # live stdout/stderr (via journald)
tail -f /var/log/payment-app/payment-app.log   # live application log file
```

### Configure secrets (recommended)

```bash
sudo mkdir -p /etc/payment-app
sudo cp deploy/payment-app.env.example /etc/payment-app/payment-app.env
sudo chmod 600 /etc/payment-app/payment-app.env
# edit the file, then uncomment EnvironmentFile=... in payment-app.service
sudo systemctl daemon-reload && sudo systemctl restart payment-app
```

The service runs as a dedicated unprivileged `payment` user and is hardened
(`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`), writing only to
`/var/log/payment-app`.

