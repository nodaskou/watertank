"""MikroTik text export and optional binary backup.

The API (librouteros, RouterOS 7) is tried first. SSH (paramiko) is the fallback
and is also how the binary .backup file is fetched. Credentials are supplied by
the caller; this module does not store them.
"""
import difflib
import hashlib
import os
import ssl
import time


def strip_export_header(text):
    """Drop the leading comment lines so a new timestamp is not a config change."""
    lines = (text or "").replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines) and (not lines[i].strip() or lines[i].lstrip().startswith("#")):
        i += 1
    return "\n".join(lines[i:]).strip() + "\n"


def compare_exports(previous, current, limit=150):
    """Return (changed, unified diff). Header comments are ignored."""
    old, new = strip_export_header(previous), strip_export_header(current)
    if not previous:
        return False, ""
    if old == new:
        return False, ""
    diff = list(difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=2,
                                     fromfile="previous", tofile="current"))
    return True, "\n".join(diff[:limit])


def sha256_text(text):
    return hashlib.sha256(strip_export_header(text).encode("utf-8")).hexdigest()


def ids_to_prune(rows, keep):
    """Keep `keep` successful backups (newest first). Failures do not use a weekly slot.

    There is no separate yearly archive: the default keep of 52 is one backup a week
    for a year. Older failures than the oldest kept success are dropped too, except
    the 10 newest failures, so a bad week stays visible.
    """
    keep = max(1, int(keep))
    rows = sorted(rows, key=lambda r: (r.get("ts") or 0, r.get("id") or 0), reverse=True)
    successes = [r for r in rows if r.get("ok")]
    drop = {r["id"] for r in successes[keep:]}
    kept_success = successes[:keep]
    oldest = min((r.get("ts") or 0) for r in kept_success) if kept_success else None
    failures = [r for r in rows if not r.get("ok")]
    for i, row in enumerate(failures):
        if i >= 10 and (oldest is None or (row.get("ts") or 0) < oldest):
            drop.add(row["id"])
    return drop


def _probe_hint(text):
    low = (text or "").lower()
    if "timed out" in low or "timeout" in low:
        return "The router did not answer within 15 seconds. Check the IP and that this machine can reach the API or SSH port."
    if "refused" in low or "errno 111" in low:
        return "Nothing is listening. API is port 8728, or 8729 when API-SSL is ticked. SSH is usually port 22."
    if "invalid user" in low or "bad" in low and "auth" in low or "authentication" in low or "login" in low:
        return "The username or password was rejected. Use a user that can log in to the API and to SSH."
    return "The login failed. The user needs the api and ssh policies, and read access. A binary backup also needs ftp."


def probe(host, user, password, api_port=8728, use_ssl=False, ssh_port=22, timeout=15):
    """Log in and read the identity. Does not export the config."""
    errors = []
    try:
        return {"ok": True, "via": "API", "detail": _identity_api(host, user, password, api_port, use_ssl, timeout),
                "error": "", "hint": ""}
    except Exception as e:
        errors.append(f"API: {e}")
    try:
        return {"ok": True, "via": "SSH", "detail": _identity_ssh(host, user, password, ssh_port, timeout),
                "error": "", "hint": ""}
    except Exception as e:
        errors.append(f"SSH: {e}")
    text = "; ".join(errors)
    return {"ok": False, "via": "", "detail": "", "error": text[:500], "hint": _probe_hint(text)}


def _identity_api(host, user, password, port, use_ssl, timeout):
    from librouteros import connect
    kwargs = dict(username=user, password=password, host=host, port=int(port or (8729 if use_ssl else 8728)),
                  timeout=timeout)
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ADH:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        kwargs["ssl_wrapper"] = ctx.wrap_socket
    api = connect(**kwargs)
    try:
        rows = list(api.path("system", "identity"))
        name = ""
        if rows:
            name = rows[0].get("name") or ""
        return name or "logged in"
    finally:
        try:
            api.close()
        except Exception:
            pass


def _identity_ssh(host, user, password, port, timeout):
    client = _ssh_client(host, user, password, port, timeout)
    try:
        _stdin, stdout, stderr = client.exec_command(":put [/system identity get name]", timeout=timeout)
        text = stdout.read().decode("utf-8", "replace").strip()
        err = stderr.read().decode("utf-8", "replace").strip()
        if not text and err:
            raise RuntimeError(err)
        return text or "logged in"
    finally:
        client.close()


def export_text(host, user, password, api_port=8728, use_ssl=False, ssh_port=22, sensitive=False, timeout=40):
    """Return (text, via). Tries the API, then SSH."""
    errors = []
    try:
        return _export_api(host, user, password, api_port, use_ssl, sensitive, timeout), "api"
    except Exception as e:
        errors.append(f"API: {e}")
    try:
        return _export_ssh(host, user, password, ssh_port, sensitive, timeout), "ssh"
    except Exception as e:
        errors.append(f"SSH: {e}")
    raise RuntimeError("; ".join(errors))


def _export_api(host, user, password, port, use_ssl, sensitive, timeout):
    from librouteros import connect
    kwargs = dict(username=user, password=password, host=host, port=int(port or (8729 if use_ssl else 8728)),
                  timeout=timeout)
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ADH:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        kwargs["ssl_wrapper"] = ctx.wrap_socket
    api = connect(**kwargs)
    try:
        cfg = api.config() if callable(getattr(api, "config", None)) else api.config
        text = cfg.export(show_sensitive=bool(sensitive))
        if not text or not str(text).strip():
            raise RuntimeError("API export was empty")
        return str(text)
    finally:
        try:
            api.close()
        except Exception:
            pass


def _ssh_client(host, user, password, port, timeout):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=int(port or 22), username=user, password=password,
                   timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                   look_for_keys=False, allow_agent=False)
    return client


def _export_ssh(host, user, password, port, sensitive, timeout):
    cmd = "/export show-sensitive" if sensitive else "/export"
    client = _ssh_client(host, user, password, port, timeout)
    try:
        _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        text = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace").strip()
        if not text.strip():
            raise RuntimeError(err or "SSH export was empty")
        return text
    finally:
        client.close()


def fetch_binary(host, user, password, ssh_port=22, timeout=60):
    """Create a temporary unencrypted .backup on the router and download it. Returns bytes."""
    name = "pm-auto"
    client = _ssh_client(host, user, password, ssh_port, timeout)
    try:
        _stdin, stdout, stderr = client.exec_command(
            f"/system backup save name={name} dont-encrypt=yes", timeout=timeout)
        stdout.channel.recv_exit_status()
        err = stderr.read().decode("utf-8", "replace").strip()
        time.sleep(1)
        sftp = client.open_sftp()
        try:
            remote = name + ".backup"
            with sftp.open(remote, "rb") as fh:
                data = fh.read()
            try:
                sftp.remove(remote)
            except OSError:
                pass
        finally:
            sftp.close()
        if not data:
            raise RuntimeError(err or "binary backup was empty")
        return data
    finally:
        client.close()


def save_pair(directory, stamp, text, binary=None):
    os.makedirs(directory, mode=0o750, exist_ok=True)
    path = os.path.join(directory, stamp + ".rsc")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, 0o640)
    bin_path = ""
    if binary:
        bin_path = os.path.join(directory, stamp + ".backup")
        with open(bin_path, "wb") as fh:
            fh.write(binary)
        os.chmod(bin_path, 0o640)
    return path, bin_path


def safe_under(root, path):
    root_real = os.path.realpath(root)
    path_real = os.path.realpath(path)
    return path_real == root_real or path_real.startswith(root_real + os.sep)
