"""Start, stop, and inspect the local transform server process."""

from __future__ import annotations

import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path

import httpx

from transformatron.config import TransformatronConfig
from transformatron.envfile import load_env_file

STARTUP_TIMEOUT = 45.0
SHUTDOWN_TIMEOUT = 10.0
HEALTH_POLL_INTERVAL = 0.4


class ServerLifecycleError(RuntimeError):
    """Raised when the server cannot be started or stopped."""


@dataclass
class ServerStatus:
    """Observed state of the managed server process.

    Attributes:
        running: Whether the recorded PID belongs to a live process.
        pid: The recorded process id, if any.
        healthy: Whether the server answered a health probe.
        detail: Human-readable explanation of the current state.
    """

    running: bool
    pid: int | None
    healthy: bool
    detail: str


# Popen handles for servers this process started. A child that has exited but
# not been waited on stays a zombie, and os.kill(pid, 0) still succeeds for it,
# so liveness checks must reap through the handle rather than trust the signal.
_OWNED: dict[int, subprocess.Popen] = {}


def _pid_is_alive(pid: int) -> bool:
    """Return whether a process with this pid is running (not an unreaped zombie)."""
    owned = _OWNED.get(pid)
    if owned is not None:
        if owned.poll() is not None:
            del _OWNED[pid]
            return False
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _is_our_server(config: TransformatronConfig, pid: int) -> bool:
    """Return whether ``pid`` is a transform server launched from ``config.entrypoint``.

    A pid file outlives its process, and the kernel recycles pids, so after a crash or a
    reboot the recorded pid can name an unrelated process. Signalling it would kill
    something the user never asked us to touch, so a live pid is only trusted once its
    command line has the exact shape ``start`` launches: a Python interpreter running the
    entrypoint as its script. Merely mentioning the file is not enough — ``vim project.py``
    must not be stopped. ``ps`` is consulted rather than ``/proc`` because it answers the
    same way on macOS and Linux. If ``ps`` cannot be run the process is treated as foreign:
    refusing to act is recoverable, a wrong kill is not.
    """
    if pid in _OWNED:
        return True
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    # Split on the last space only: the interpreter path may itself contain spaces.
    interpreter, _, script = result.stdout.strip().rpartition(" ")
    return script == config.entrypoint.name and Path(interpreter).name.lower().startswith("python")


def read_pid(config: TransformatronConfig) -> int | None:
    """Return the recorded pid if it names our live server process, else ``None``.

    Clears a stale pid file so a crashed server does not block a restart. A pid that is
    not positive is corrupt, not merely stale: ``os.kill`` treats 0 and negative values
    as process groups, so passing one on would signal far more than one process.
    """
    if not config.pid_file.exists():
        return None
    try:
        pid = int(config.pid_file.read_text().strip())
    except ValueError:
        config.pid_file.unlink(missing_ok=True)
        return None
    if pid <= 0 or not _pid_is_alive(pid) or not _is_our_server(config, pid):
        config.pid_file.unlink(missing_ok=True)
        return None
    return pid


def read_scheme(config: TransformatronConfig) -> str:
    """Return the scheme the running server was started with.

    The scheme is runtime state: ``project.py`` defaults to ``https``, but
    :func:`build_server_env` overrides it per start, so a server may be serving
    either scheme. Probing the wrong one makes a healthy server look
    unreachable, so the scheme is recorded at startup.
    """
    if not config.scheme_file.exists():
        return config.scheme
    scheme = config.scheme_file.read_text().strip()
    return scheme if scheme in ("http", "https") else config.scheme


def resolve_config(config: TransformatronConfig) -> TransformatronConfig:
    """Return ``config`` addressing the running server's actual scheme."""
    return config.with_scheme(read_scheme(config))


# Prefix of the Problem Details ``type`` the SDK returns when auth rejects a request,
# including a status probe (maltego/auth/problem.py, AUTH_PROBLEM_TYPE_PREFIX).
SDK_PROBLEM_TYPE_PREFIX = "urn:maltego-transforms:problem:"


def _is_maltego_response(response: httpx.Response) -> bool:
    """Return whether ``response`` came from a Maltego SDK transform server.

    Any web server on the port answers *something*, so a bare status code would let an
    unrelated service pass for ours. The SDK's status handler always sets a
    ``maltego-protocol-version`` header (maltego/server/v3/__init__.py get_status, via
    maltego/server/util.py set_protocol_version_header). When auth is enforced, the
    request is rejected before that handler runs, so the SDK's auth Problem Details body
    is accepted as proof instead.
    """
    if "maltego-protocol-version" in response.headers:
        return True
    if response.status_code not in (401, 403):
        return False
    try:
        problem = response.json()
    except ValueError:
        return False
    return isinstance(problem, dict) and str(problem.get("type", "")).startswith(
        SDK_PROBLEM_TYPE_PREFIX
    )


def probe_health(config: TransformatronConfig, timeout: float = 3.0) -> bool:
    """Return whether a Maltego transform server answers on its status endpoint."""
    resolved = resolve_config(config)
    try:
        response = httpx.get(f"{resolved.api_url}/status", timeout=timeout, verify=False)
    except httpx.HTTPError:
        return False
    return _is_maltego_response(response)


def _port_in_use(config: TransformatronConfig, timeout: float = 1.0) -> bool:
    """Return whether anything accepts TCP connections on the configured host and port.

    Deliberately protocol-agnostic: any listener, Maltego or not, stops the server from
    binding, and the SDK would then exit with a bind error buried in the log.
    """
    try:
        with socket.create_connection((config.host, config.port), timeout=timeout):
            return True
    except OSError:
        return False


def tail_log(config: TransformatronConfig, lines: int = 50) -> str:
    """Return the last ``lines`` lines of the server log."""
    if not config.log_file.exists():
        return "(no log file yet — the server has not been started)"
    with config.log_file.open("r", errors="replace") as handle:
        return "".join(deque(handle, maxlen=lines)) or "(log is empty)"


def status(config: TransformatronConfig) -> ServerStatus:
    """Report whether the server process is running and answering requests."""
    resolved = resolve_config(config)
    pid = read_pid(config)
    if pid is None:
        healthy = probe_health(config)
        if healthy:
            return ServerStatus(
                running=False,
                pid=None,
                healthy=True,
                detail=(
                    f"Something is already serving {resolved.base_url}, but it was not "
                    "started by this tool, so it cannot be stopped here."
                ),
            )
        if _port_in_use(config):
            # Not a transform server, but it holds the port, so start would refuse. Saying
            # "not running" here would send the caller into that refusal blind.
            return ServerStatus(
                running=False,
                pid=None,
                healthy=False,
                detail=(
                    f"Something else is listening on {config.host}:{config.port}; it is not a "
                    "transform server started by this tool. Stop it, or change [server].port "
                    "in transformatron.toml."
                ),
            )
        return ServerStatus(False, None, False, "Server is not running.")
    healthy = probe_health(config)
    detail = (
        f"Server is running (pid {pid}) and answering at {resolved.base_url}."
        if healthy
        else f"Process {pid} is alive but not answering yet at {resolved.base_url}."
    )
    return ServerStatus(True, pid, healthy, detail)


def build_server_env(config: TransformatronConfig, ssl: bool = False) -> dict[str, str]:
    """Build the environment that pins the server to our host, port, and scheme.

    The generated ``project.py`` hardcodes its ``ServerHTTPSettings`` and parses no
    command-line arguments. Those settings are a pydantic ``BaseSettings`` whose
    ``MALTEGO_SERVER_`` environment variables take precedence over the values
    passed in code, so the environment is the only way to steer the server
    without editing the user's project file.

    API keys in ``.env`` at the repository root are merged in so transforms can read
    them through their environment fallback. An exported variable wins over the file, so
    a one-off ``KEY=value`` on the command line still overrides what is written down.

    Raises:
        ServerLifecycleError: If HTTPS is requested but certificates are missing.
    """
    env = dict(load_env_file(config.env_file))
    env.update(os.environ)
    env["MALTEGO_SERVER_HTTP_ADDR"] = config.host
    env["MALTEGO_SERVER_HTTP_PORT"] = str(config.port)
    env["MALTEGO_SERVER_PROTOCOL"] = "https" if ssl else "http"
    # Identity travels the same way as host and port, so transformatron.toml steers the
    # server without anyone editing project.py. Set unconditionally rather than only when
    # it differs from the default: an inherited MALTEGO_SERVER_NS in the ambient
    # environment would otherwise silently outrank the file the author actually wrote.
    env["MALTEGO_SERVER_SERVER_NAME"] = config.server_name
    env["MALTEGO_SERVER_NS"] = config.namespace
    env["MALTEGO_SERVER_AUTHOR"] = config.author
    env["PYTHONUNBUFFERED"] = "1"

    if ssl:
        if not (config.cert_file.exists() and config.key_file.exists()):
            raise ServerLifecycleError(
                "HTTPS was requested but no certificates exist. Run generate_certs first."
            )
        env["MALTEGO_SERVER_CERT_FILE"] = str(config.cert_file)
        env["MALTEGO_SERVER_CERT_KEY"] = str(config.key_file)
    return env


def start(config: TransformatronConfig, ssl: bool = False) -> ServerStatus:
    """Launch the transform server and wait until it answers a health probe.

    Args:
        config: Server locations and connection details.
        ssl: Serve over HTTPS using the generated certificate pair.

    Returns:
        The status observed once the server is healthy.

    Raises:
        ServerLifecycleError: If the server is already running, something else holds
            the port, the entrypoint is missing, certificates are absent, or startup
            fails or times out.
    """
    existing = read_pid(config)
    if existing is not None:
        raise ServerLifecycleError(
            f"Server is already running (pid {existing}). Use server_restart to reload it."
        )
    if not config.entrypoint.exists():
        raise ServerLifecycleError(
            f"No server entrypoint at {config.entrypoint}. "
            "Generate one with: maltego-transforms start server --with-skills"
        )
    # Validate certificates before recording anything, so a refused HTTPS start leaves no
    # scheme file behind to make later probes address a server that never existed.
    env = build_server_env(config, ssl=ssl)
    # Without this check a foreign listener answers the health probe, and start would
    # report success for a server that is not ours while ours dies on a bind error.
    if _port_in_use(config):
        raise ServerLifecycleError(
            f"Something is already serving {config.host}:{config.port} and it was not "
            "started by this tool. Stop it, or change [server].port in transformatron.toml."
        )

    config.state_dir.mkdir(parents=True, exist_ok=True)
    log_handle = config.log_file.open("ab")
    try:
        process = subprocess.Popen(
            [sys.executable, config.entrypoint.name],
            cwd=config.project_dir,
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    finally:
        log_handle.close()

    _OWNED[process.pid] = process
    config.pid_file.write_text(str(process.pid))
    config.scheme_file.write_text("https" if ssl else "http")
    return _await_healthy(config, process)


def _clear_state(config: TransformatronConfig) -> None:
    """Forget the recorded server so nothing describes a process that is gone."""
    config.pid_file.unlink(missing_ok=True)
    config.scheme_file.unlink(missing_ok=True)


def _await_healthy(config: TransformatronConfig, process: subprocess.Popen) -> ServerStatus:
    """Wait for the server to answer, failing fast if the process dies.

    A failed start leaves no process and no pid file, so the next start is not refused by
    a server that cannot be reached. The scheme file is kept: it records the scheme the
    caller asked for, and the usual reason for a failed start is a transform that did not
    import. Dropping it would bring the fixed server back on plain HTTP at the next
    ``restart``, which the Maltego desktop client rejects without a trace in the log.
    """
    base_url = resolve_config(config).base_url
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _OWNED.pop(process.pid, None)
            config.pid_file.unlink(missing_ok=True)
            raise ServerLifecycleError(
                f"Server exited immediately with code {process.returncode}. "
                f"Recent log output:\n{tail_log(config, 30)}"
            )
        # The child must still be alive after the probe answers: if it died meanwhile,
        # whatever answered is not ours, and the next iteration reports the exit.
        if probe_health(config) and process.poll() is None:
            return ServerStatus(
                running=True,
                pid=process.pid,
                healthy=True,
                detail=f"Server started (pid {process.pid}) at {base_url}.",
            )
        time.sleep(HEALTH_POLL_INTERVAL)

    _terminate(process.pid)
    config.pid_file.unlink(missing_ok=True)
    raise ServerLifecycleError(
        f"Server did not answer at {base_url} within {STARTUP_TIMEOUT:g}s and was "
        f"stopped. Recent log output:\n{tail_log(config, 30)}"
    )


def _terminate(pid: int) -> bool:
    """Send SIGTERM, escalating to SIGKILL after ``SHUTDOWN_TIMEOUT``.

    Returns:
        Whether the process had to be killed.
    """
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        _OWNED.pop(pid, None)
        return False
    deadline = time.monotonic() + SHUTDOWN_TIMEOUT
    while time.monotonic() < deadline:
        if not _pid_is_alive(pid):
            _OWNED.pop(pid, None)
            return False
        time.sleep(HEALTH_POLL_INTERVAL)

    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    owned = _OWNED.pop(pid, None)
    if owned is not None:
        owned.wait(timeout=SHUTDOWN_TIMEOUT)
    return True


# uvicorn logs these in order while it shuts down (uvicorn/server.py Server.shutdown and
# uvicorn/lifespan/on.py; unchanged from 0.35 to 0.54). The furthest one reached names
# the stage that was still waiting when the server had to be killed.
_SHUTDOWN_STARTED = "Shutting down"
_WAITING_FOR_CONNECTIONS = "Waiting for connections to close"
_WAITING_FOR_APPLICATION = "Waiting for application shutdown."
_APPLICATION_SHUTDOWN_COMPLETE = "Application shutdown complete."


def _log_size(config: TransformatronConfig) -> int:
    """Return the current size of the server log, so later reads see only new lines."""
    try:
        return config.log_file.stat().st_size
    except OSError:
        return 0


def _read_log_from(config: TransformatronConfig, offset: int) -> str:
    """Return what the server logged after byte ``offset`` of its log."""
    try:
        with config.log_file.open("rb") as handle:
            handle.seek(offset)
            return handle.read().decode(errors="replace")
    except OSError:
        return ""


def _shutdown_stall_cause(logged: str, https: bool) -> str:
    """Name what held up a shutdown, from the lines logged after SIGTERM.

    A bare "was killed" reads like a crash and invites hunting for lost work. Each
    known cause leaves its own trace in the log, so the message can say which one it
    was and what, if anything, to change.
    """
    if _APPLICATION_SHUTDOWN_COMPLETE in logged:
        return (
            "The application shut down but the process did not exit; check server.log for "
            "what was still running."
        )
    # Checked before the connection wait: the lifespan only starts once connections are
    # done, so reaching it means the connections were not what blocked.
    if _WAITING_FOR_APPLICATION in logged:
        return (
            "A transform was blocking the runner thread, and the SDK waits for it without a "
            "limit; check server.log for the run in progress, and use async I/O in transforms "
            "(never requests, sync httpx or time.sleep)."
        )
    if _WAITING_FOR_CONNECTIONS in logged:
        return (
            "Open client connections held it up; an HTTPS keep-alive client such as Maltego "
            "Desktop can hold shutdown for up to 30s while TLS closes."
        )
    if _SHUTDOWN_STARTED in logged and https:
        # uvicorn tracks a connection only once its TLS handshake is done, so one stuck
        # mid-handshake leaves no log line, yet asyncio waits up to 60s for it.
        return (
            "A client connection that never finished its TLS handshake held it up; the "
            "server waits up to 60s for one and logs nothing about it."
        )
    if _SHUTDOWN_STARTED in logged:
        return "Shutdown stalled with no further log line; check server.log."
    return "The server logged nothing after SIGTERM; check server.log."


def stop(config: TransformatronConfig) -> str:
    """Terminate the server, escalating to SIGKILL if it does not exit.

    Only a pid that :func:`read_pid` confirms is our server is ever signalled. When the
    server has to be killed, the message names the cause found in the log lines written
    since SIGTERM; earlier lines belong to previous runs and would mislead.
    """
    return _stop(config)[0]


def _stop(config: TransformatronConfig) -> tuple[str, bool]:
    """Stop the server and return the message and whether it had to be killed."""
    pid = read_pid(config)
    if pid is None:
        return "Server is not running.", False

    https = read_scheme(config) == "https"
    log_offset = _log_size(config)
    killed = _terminate(pid)
    _clear_state(config)
    if killed:
        cause = _shutdown_stall_cause(_read_log_from(config, log_offset), https)
        # The SDK's shutdown only stops runner threads and closes its auth client, and
        # middleware.py has no flush hooks, so a kill skips nothing worth keeping.
        message = (
            f"Server did not exit within {SHUTDOWN_TIMEOUT:g}s and was killed (pid {pid}). "
            f"{cause} Nothing was lost: the server keeps no state that a clean shutdown "
            "would have saved."
        )
        return message, True
    return f"Server stopped (pid {pid}).", False


def restart(config: TransformatronConfig, ssl: bool | None = None) -> ServerStatus:
    """Stop the server if running, then start it again.

    This is the reload path after adding or editing a transform module, so a stop that
    had to kill the server is reported with its cause ahead of the start: otherwise a
    transform blocking its runner thread shows up only as an unexplained 10s pause.

    Args:
        ssl: Serve over HTTPS. When ``None`` the scheme the server is currently
            running under is preserved. Restarting an HTTPS server onto HTTP
            would break the Maltego desktop client, which rejects plain HTTP
            client-side and leaves no trace in the server log.

    Returns:
        The status observed once the server is healthy.
    """
    if ssl is None:
        ssl = read_scheme(config) == "https"
    stopped, killed = _stop(config)
    status = start(config, ssl=ssl)
    if killed:
        return replace(status, detail=f"{stopped}\n{status.detail}")
    return status
