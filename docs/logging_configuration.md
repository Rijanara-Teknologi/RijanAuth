# Logging Configuration

RijanAuth uses a Laravel-style logging system configured in `apps/config.py`.

## Configuration Options

The `LOGGING` dictionary in `config.py` controls behavior:

| Key | Description | Default |
|-----|-------------|---------|
| `level` | Minimum log level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `path` | Directory to store logs | `storage/logs` |
| `max_files` | Days to keep logs | `7` |
| `max_size` | Max size per file (bytes) | 100MB |
| `sensitive_fields` | Fields to mask in context | `['password', 'token', ...]` |

## Environment Variables

You can override defaults using `.env` or system variables:

- `LOG_LEVEL`: Set to `DEBUG` for verbose output.
- `LOG_PATH`: Custom path for logs (e.g. `/var/log/rijanauth`).

## Security

Logs automatically mask sensitive data.
- **Passwords**: Masked as `****`
- **Tokens**: Masked as `****`
- **PII**: Configurable via `sensitive_fields`

## Log Format

Logs are stored in JSON-enriched format:
```
[2026-01-25 10:00:00] production.INFO: Message {"user_id": "...", "ip": "..."}
```

Files are rotated daily: `rija-auth-YYYY-MM-DD.log`.
