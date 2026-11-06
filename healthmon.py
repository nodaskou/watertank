"""Monitor-process health rules. No Flask and no network.

Disk figures are for the filesystem that holds this app's data, not a recorder disk.
A powered-off machine cannot run these checks. That limit is documented with the watchdog.
"""


def disk_level(free_bytes, total_bytes, warn_pct, crit_pct):
    """ok, warning, critical, or off when both thresholds are 0.

    Percent free is the only signal. Missing sizes are unknown, not a failure.
    """
    try:
        warn = int(warn_pct or 0)
        crit = int(crit_pct or 0)
    except (TypeError, ValueError):
        return "unknown"
    if warn <= 0 and crit <= 0:
        return "off"
    if not total_bytes or free_bytes is None:
        return "unknown"
    pct = 100.0 * float(free_bytes) / float(total_bytes)
    if crit > 0 and pct <= crit:
        return "critical"
    if warn > 0 and pct <= warn:
        return "warning"
    return "ok"


def backup_status(last_ok_ts, now, every_sec, grace_sec, enabled=True):
    """ok, stale, unknown, or off.

    No successful copy yet is unknown until one full interval plus the grace has
    passed, then stale. A disabled job is off and is not a failure.
    """
    if not enabled:
        return "off"
    try:
        every = int(every_sec)
        grace = int(grace_sec)
    except (TypeError, ValueError):
        return "unknown"
    if every <= 0:
        return "off"
    limit = every + max(0, grace)
    if not last_ok_ts:
        return "unknown"
    if float(now) - float(last_ok_ts) > limit:
        return "stale"
    return "ok"


def heartbeat_view(age_sec, limit_sec, service_active):
    """What an independent watchdog can see.

    service_active is True, False, or None when systemd is not available.
    A missing heartbeat (age None) is unknown until the service is inactive.
    Hung means the unit is still active but the beat is old. Stopped means the
    unit is inactive. This cannot see a powered-off host.
    """
    try:
        limit = max(30, int(limit_sec or 180))
    except (TypeError, ValueError):
        limit = 180
    if service_active is False:
        return "stopped"
    if age_sec is None:
        return "unknown"
    if float(age_sec) > limit:
        return "hung" if service_active else "stale"
    return "ok"
