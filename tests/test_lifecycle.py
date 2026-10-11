"""Tests for server process management."""

from __future__ import annotations

import dataclasses
import os
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator

import httpx
import pytest

from transformatron import certs, lifecycle
from transformatron.config import TransformatronConfig


@pytest.fixture
def config(tmp_path) -> TransformatronConfig:
    project = tmp_path / "server"
    project.mkdir()
    (project / "project.py").write_text("")
    return TransformatronConfig(project_dir=project, state_dir=tmp_path / "state")


@pytest.fixture
def server_child(config: TransformatronConfig) -> Iterator[subprocess.Popen]:
    """A real process running the entrypoint, launched outside ``lifecycle``.

    It is not in ``lifecycle._OWNED``, so ownership has to be proven from its command
    line, exactly as for a server started by an earlier CLI invocation.
    """
    config.entrypoint.write_text("import time\ntime.sleep(60)\n")
    process = subprocess.Popen([sys.executable, config.entrypoint.name], cwd=config.project_dir)
    yield process
    process.kill()
    process.wait()


def _free_port() -> int:
    """Return a loopback port nothing is listening on."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _on_free_port(config: TransformatronConfig) -> TransformatronConfig:
    """Point ``config`` at an unused loopback port, so a real start is not refused."""
    return dataclasses.replace(config, host="127.0.0.1", port=_free_port())


def test_read_pid_clears_a_stale_pid_file(config: TransformatronConfig) -> None:
    """A crashed server must not block the next start."""
    config.state_dir.mkdir(parents=True)
    # PID 2**31-1 is above the kernel maximum, so it cannot name a live process.
    config.pid_file.write_text("2147483647")

    assert lifecycle.read_pid(config) is None
    assert not config.pid_file.exists()


def test_read_pid_clears_a_corrupt_pid_file(config: TransformatronConfig) -> None:
    config.state_dir.mkdir(parents=True)
    config.pid_file.write_text("not-a-pid")

    assert lifecycle.read_pid(config) is None
    assert not config.pid_file.exists()


def test_read_pid_returns_our_live_server(
    config: TransformatronConfig, server_child: subprocess.Popen
) -> None:
    config.state_dir.mkdir(parents=True)
    config.pid_file.write_text(str(server_child.pid))

    assert lifecycle.read_pid(config) == server_child.pid


def test_read_pid_does_not_trust_a_foreign_process(config: TransformatronConfig) -> None:
    """A recycled pid naming some other live process is stale, not our server."""
    config.state_dir.mkdir(parents=True)
    config.pid_file.write_text(str(os.getpid()))

    assert lifecycle.read_pid(config) is None
    assert not config.pid_file.exists()


def test_read_pid_does_not_trust_a_process_that_merely_opens_the_entrypoint(
    config: TransformatronConfig,
) -> None:
    """An editor or pager holding project.py open is not the server and must not be stopped."""
    config.entrypoint.write_text("")
    viewer = subprocess.Popen(["tail", "-f", config.entrypoint.name], cwd=config.project_dir)
    try:
        config.state_dir.mkdir(parents=True)
        config.pid_file.write_text(str(viewer.pid))

        assert lifecycle.read_pid(config) is None
    finally:
        viewer.kill()
        viewer.wait()


@pytest.mark.parametrize("recorded", ["0", "-1"])
def test_read_pid_rejects_non_positive_pids(config: TransformatronConfig, recorded: str) -> None:
    """os.kill treats 0 and negative pids as process groups, so they must never pass."""
    config.state_dir.mkdir(parents=True)
    config.pid_file.write_text(recorded)

    assert lifecycle.read_pid(config) is None
    assert not config.pid_file.exists()


def test_exited_child_is_not_reported_alive(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exited child we started is a zombie until reaped, and os.kill(pid, 0)
    still succeeds for it. Liveness must come from the Popen handle instead, or
    every stop falls through to SIGKILL."""
    pid = 424242

    class ExitedChild:
        returncode = 0

        def poll(self) -> int:
            return 0

    monkeypatch.setitem(lifecycle._OWNED, pid, ExitedChild())
    # Simulate the kernel still answering for the unreaped pid.
    monkeypatch.setattr(lifecycle.os, "kill", lambda *a: None)

    assert not lifecycle._pid_is_alive(pid)
    assert pid not in lifecycle._OWNED, "a reaped child must be forgotten"


def test_live_owned_child_is_reported_alive(monkeypatch: pytest.MonkeyPatch) -> None:
    pid = 424243

    class RunningChild:
        def poll(self) -> None:
            return None

    monkeypatch.setitem(lifecycle._OWNED, pid, RunningChild())

    assert lifecycle._pid_is_alive(pid)


def test_start_refuses_when_already_running(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = 424244

    class RunningChild:
        def poll(self) -> None:
            return None

    monkeypatch.setitem(lifecycle._OWNED, pid, RunningChild())
    config.state_dir.mkdir(parents=True)
    config.pid_file.write_text(str(pid))

    with pytest.raises(lifecycle.ServerLifecycleError, match="already running"):
        lifecycle.start(config)


def test_start_reports_a_missing_entrypoint(tmp_path) -> None:
    config = TransformatronConfig(project_dir=tmp_path / "absent", state_dir=tmp_path / "state")

    with pytest.raises(lifecycle.ServerLifecycleError, match="maltego-transforms start"):
        lifecycle.start(config)


def test_stop_is_safe_when_not_running(config: TransformatronConfig) -> None:
    assert lifecycle.stop(config) == "Server is not running."


def test_stop_never_signals_a_foreign_process(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pid file naming someone else's process must not get that process killed."""
    config.state_dir.mkdir(parents=True)
    config.pid_file.write_text(str(os.getpid()))
    sent: list[int] = []
    real_kill = os.kill

    def recording_kill(pid: int, sig: int) -> None:
        if sig != 0:
            sent.append(sig)
        real_kill(pid, sig)

    monkeypatch.setattr(lifecycle.os, "kill", recording_kill)

    assert lifecycle.stop(config) == "Server is not running."
    assert sent == []


@pytest.fixture
def stalling_server(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[list[str]], subprocess.Popen]]:
    """Start recorded servers that log given lines when asked to stop, then hang.

    Each writes to server.log as the real server does, so ``stop`` has to find the cause
    in what was appended after its SIGTERM. Any child a failed test leaves running is
    killed at teardown, since it ignores SIGTERM by design.
    """
    started: list[subprocess.Popen] = []
    monkeypatch.setattr(lifecycle, "SHUTDOWN_TIMEOUT", 0.5)

    def start(on_sigterm: list[str]) -> subprocess.Popen:
        config.entrypoint.write_text(
            "import signal, time\n"
            f"LINES = {on_sigterm!r}\n"
            "def on_term(*_):\n"
            "    for line in LINES:\n"
            "        print(f'INFO     | uvicorn | {line}', flush=True)\n"
            "signal.signal(signal.SIGTERM, on_term)\n"
            "print('ready', flush=True)\n"
            "while True:\n"
            "    time.sleep(1)\n"
        )
        config.state_dir.mkdir(parents=True, exist_ok=True)
        offset = config.log_file.stat().st_size if config.log_file.exists() else 0
        with config.log_file.open("ab") as log:
            process = subprocess.Popen(
                [sys.executable, config.entrypoint.name],
                cwd=config.project_dir,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        started.append(process)
        # The handler must be installed before stop signals, or SIGTERM just ends the child.
        deadline = time.monotonic() + 10
        while b"ready" not in config.log_file.read_bytes()[offset:]:
            assert process.poll() is None, "the stalling server exited before it was ready"
            assert time.monotonic() < deadline, "the stalling server never became ready"
            time.sleep(0.02)
        monkeypatch.setitem(lifecycle._OWNED, process.pid, process)
        config.pid_file.write_text(str(process.pid))
        return process

    yield start
    for process in started:
        process.kill()
        process.wait()


@pytest.mark.parametrize(
    ("scheme", "on_sigterm", "cause"),
    [
        (
            "https",
            ["Shutting down", "Waiting for connections to close. (CTRL+C to force quit)"],
            "Open client connections held it up",
        ),
        ("https", ["Shutting down"], "never finished its TLS handshake"),
        (
            "http",
            ["Shutting down", "Waiting for application shutdown."],
            "blocking the runner thread",
        ),
        # Connections drained, then the lifespan stalled: the runner thread is to blame.
        (
            "https",
            [
                "Shutting down",
                "Waiting for connections to close. (CTRL+C to force quit)",
                "Waiting for application shutdown.",
            ],
            "blocking the runner thread",
        ),
        # The lifespan finished, so neither connections nor a transform are to blame.
        (
            "https",
            [
                "Shutting down",
                "Waiting for connections to close. (CTRL+C to force quit)",
                "Waiting for application shutdown.",
                "Application shutdown complete.",
            ],
            "shut down but the process did not exit",
        ),
        # Plain-HTTP sockets close at once, so a silent stall there is not a handshake.
        ("http", ["Shutting down"], "Shutdown stalled with no further log line"),
    ],
)
def test_killed_stop_names_the_cause_from_the_log(
    config: TransformatronConfig,
    stalling_server: Callable[[list[str]], subprocess.Popen],
    scheme: str,
    on_sigterm: list[str],
    cause: str,
) -> None:
    """A kill must say what held shutdown up, not read like a crash that lost work."""
    process = stalling_server(on_sigterm)
    config.scheme_file.write_text(scheme)

    message = lifecycle.stop(config)

    assert process.poll() is not None, "the stalled server must still be killed"
    assert message.startswith(f"Server did not exit within 0.5s and was killed (pid {process.pid})")
    assert cause in message
    assert "Nothing was lost" in message
    assert "\n" not in message
    assert not config.pid_file.exists()


def test_killed_stop_ignores_log_lines_from_earlier_runs(
    config: TransformatronConfig, stalling_server: Callable[[list[str]], subprocess.Popen]
) -> None:
    """An old run's shutdown lines must not be blamed for this one's stall."""
    config.state_dir.mkdir(parents=True)
    config.log_file.write_text(
        "INFO     | uvicorn | Shutting down\n"
        "INFO     | uvicorn | Waiting for application shutdown.\n"
    )
    process = stalling_server([])

    message = lifecycle.stop(config)

    assert process.poll() is not None
    assert "logged nothing after SIGTERM" in message
    assert "runner thread" not in message


def test_restart_reports_why_the_old_server_had_to_be_killed(
    config: TransformatronConfig,
    stalling_server: Callable[[list[str]], subprocess.Popen],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """restart is the reload path agents use most; a kill there must not pass unexplained."""
    process = stalling_server(["Shutting down", "Waiting for application shutdown."])
    config.scheme_file.write_text("http")
    _record_restart_scheme(config, monkeypatch)

    status = lifecycle.restart(config)

    assert process.poll() is not None
    assert "blocking the runner thread" in status.detail
    assert status.detail.endswith("started")


def test_build_server_env_pins_host_port_and_scheme(config: TransformatronConfig) -> None:
    env = lifecycle.build_server_env(config)

    assert env["MALTEGO_SERVER_HTTP_ADDR"] == config.host
    assert env["MALTEGO_SERVER_HTTP_PORT"] == str(config.port)
    assert env["MALTEGO_SERVER_PROTOCOL"] == "http"


def test_build_server_env_carries_identity(config: TransformatronConfig) -> None:
    """Identity reaches the server the same way host and port do, via MALTEGO_SERVER_*."""
    named = dataclasses.replace(
        config, server_name="Acme Intel", namespace="acme.intel", author="Acme"
    )

    env = lifecycle.build_server_env(named)

    assert env["MALTEGO_SERVER_SERVER_NAME"] == "Acme Intel"
    assert env["MALTEGO_SERVER_NS"] == "acme.intel"
    assert env["MALTEGO_SERVER_AUTHOR"] == "Acme"


def test_configured_identity_outranks_the_ambient_environment(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale MALTEGO_SERVER_NS in the shell must not override transformatron.toml.

    build_server_env copies os.environ in before setting its own keys, so an inherited
    value would win if identity were merged in the other order — and the server would
    register transform ids under a namespace nobody configured.
    """
    monkeypatch.setenv("MALTEGO_SERVER_NS", "stale.from.shell")
    named = dataclasses.replace(config, namespace="acme.intel")

    assert lifecycle.build_server_env(named)["MALTEGO_SERVER_NS"] == "acme.intel"


def test_read_scheme_defaults_to_http(config: TransformatronConfig) -> None:
    assert lifecycle.read_scheme(config) == "http"


def test_read_scheme_reports_recorded_https(config: TransformatronConfig) -> None:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.scheme_file.write_text("https")

    assert lifecycle.read_scheme(config) == "https"
    assert lifecycle.resolve_config(config).base_url.startswith("https://")


def test_read_scheme_ignores_junk(config: TransformatronConfig) -> None:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.scheme_file.write_text("gopher")

    assert lifecycle.read_scheme(config) == "http"


def test_probe_health_uses_recorded_scheme(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server started with ssl=True must be probed over https, not http."""
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.scheme_file.write_text("https")
    probed: list[str] = []

    def fake_get(url: str, **kwargs: object) -> httpx.Response:
        probed.append(url)
        return httpx.Response(
            200,
            headers={"maltego-protocol-version": "3.1"},
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(lifecycle.httpx, "get", fake_get)

    assert lifecycle.probe_health(config) is True
    assert probed[0].startswith("https://")


@pytest.mark.parametrize(
    ("response", "healthy"),
    [
        pytest.param(
            httpx.Response(200, headers={"maltego-protocol-version": "3.1"}),
            True,
            id="sdk-status",
        ),
        pytest.param(
            httpx.Response(
                401,
                json={"type": "urn:maltego-transforms:problem:auth:credentials-missing"},
            ),
            True,
            id="sdk-auth-rejection",
        ),
        pytest.param(httpx.Response(200, text="<html>hello</html>"), False, id="foreign-200"),
        pytest.param(httpx.Response(404, text="Not Found"), False, id="foreign-404"),
        pytest.param(httpx.Response(401, json={"error": "nope"}), False, id="foreign-401"),
    ],
)
def test_probe_health_only_accepts_a_maltego_server(
    config: TransformatronConfig,
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
    healthy: bool,
) -> None:
    """Any web server on the port answers something; only the SDK counts as healthy.

    An auth-enforcing SDK server rejects the unauthenticated probe, but with its own
    Problem Details body, so it still counts as up rather than timing startup out.
    """
    monkeypatch.setattr(lifecycle.httpx, "get", lambda *a, **k: response)

    assert lifecycle.probe_health(config) is healthy


def test_build_server_env_requires_certs_for_ssl(config: TransformatronConfig) -> None:
    with pytest.raises(lifecycle.ServerLifecycleError, match="generate_certs"):
        lifecycle.build_server_env(config, ssl=True)


def test_build_server_env_points_at_certs_when_present(config: TransformatronConfig) -> None:
    config.cert_file.parent.mkdir(parents=True)
    config.cert_file.write_text("cert")
    config.key_file.write_text("key")

    env = lifecycle.build_server_env(config, ssl=True)

    assert env["MALTEGO_SERVER_PROTOCOL"] == "https"
    assert env["MALTEGO_SERVER_CERT_FILE"] == str(config.cert_file)
    assert env["MALTEGO_SERVER_CERT_KEY"] == str(config.key_file)


def _record_restart_scheme(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> list[bool]:
    """Capture the ``ssl`` value ``restart`` hands to ``start``.

    ``stop`` is left real so the test also covers it deleting the scheme file
    before ``start`` would read it.
    """
    started: list[bool] = []

    def fake_start(_config: TransformatronConfig, ssl: bool = False) -> lifecycle.ServerStatus:
        started.append(ssl)
        return lifecycle.ServerStatus(running=True, pid=1, healthy=True, detail="started")

    monkeypatch.setattr(lifecycle, "start", fake_start)
    return started


def test_restart_preserves_a_running_https_server(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reloading an HTTPS server must not drop it to HTTP.

    The Maltego desktop client rejects plain HTTP client-side, so a silent
    downgrade fails with an empty server log — the hardest failure to diagnose.
    """
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.scheme_file.write_text("https")
    started = _record_restart_scheme(config, monkeypatch)

    lifecycle.restart(config)

    assert started == [True]


def test_restart_preserves_a_running_http_server(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.scheme_file.write_text("http")
    started = _record_restart_scheme(config, monkeypatch)

    lifecycle.restart(config)

    assert started == [False]


def test_restart_honours_an_explicit_ssl_request(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.scheme_file.write_text("http")
    started = _record_restart_scheme(config, monkeypatch)

    lifecycle.restart(config, ssl=True)

    assert started == [True]


def test_restart_honours_an_explicit_downgrade(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--no-ssl`` is the deliberate way back to HTTP."""
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.scheme_file.write_text("https")
    started = _record_restart_scheme(config, monkeypatch)

    lifecycle.restart(config, ssl=False)

    assert started == [False]


def test_tail_log_explains_an_absent_log(config: TransformatronConfig) -> None:
    assert "not been started" in lifecycle.tail_log(config)


def test_tail_log_returns_trailing_lines(config: TransformatronConfig) -> None:
    config.state_dir.mkdir(parents=True)
    config.log_file.write_text("".join(f"line{i}\n" for i in range(100)))

    tail = lifecycle.tail_log(config, lines=3)

    assert tail.splitlines() == ["line97", "line98", "line99"]


def test_status_flags_a_foreign_server_it_cannot_stop(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Something else on the port must not be reported as ours."""
    monkeypatch.setattr(lifecycle, "probe_health", lambda *a, **k: True)

    status = lifecycle.status(config)

    assert not status.running
    assert status.healthy
    assert "not started by this tool" in status.detail


def test_start_refuses_a_port_something_else_holds(config: TransformatronConfig) -> None:
    """A foreign listener would otherwise answer the probe and pass for our server."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        busy = dataclasses.replace(config, host="127.0.0.1", port=listener.getsockname()[1])

        with pytest.raises(lifecycle.ServerLifecycleError, match="already serving"):
            lifecycle.start(busy)

    assert not busy.pid_file.exists()
    assert not busy.scheme_file.exists()


def test_status_names_a_foreign_listener_that_start_would_refuse(
    config: TransformatronConfig,
) -> None:
    """`status` must not report a free port when `start` is about to refuse it."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        busy = dataclasses.replace(config, host="127.0.0.1", port=listener.getsockname()[1])

        reported = lifecycle.status(busy)

    assert not reported.running
    assert "Something else is listening" in reported.detail


def test_refused_https_start_records_no_scheme(config: TransformatronConfig) -> None:
    """A stale scheme file would make later probes address a server that never ran."""
    with pytest.raises(lifecycle.ServerLifecycleError, match="generate_certs"):
        lifecycle.start(config, ssl=True)

    assert not config.scheme_file.exists()
    assert not config.pid_file.exists()


def test_crashed_start_clears_its_pid(config: TransformatronConfig) -> None:
    config.entrypoint.write_text("raise SystemExit(3)\n")
    local = _on_free_port(config)

    with pytest.raises(lifecycle.ServerLifecycleError, match="exited immediately with code 3"):
        lifecycle.start(local, ssl=False)

    assert not local.pid_file.exists()


def test_crashed_https_start_keeps_https_for_the_next_restart(
    config: TransformatronConfig,
) -> None:
    """A transform that fails to import must not turn the fixed server into an HTTP one.

    The Maltego desktop client rejects plain HTTP without a trace in the server log, so a
    restart after fixing the import has to come back on the scheme that was asked for.
    """
    local = _on_free_port(config)
    certs.generate(local)
    local.entrypoint.write_text("raise SystemExit(3)\n")

    with pytest.raises(lifecycle.ServerLifecycleError, match="exited immediately"):
        lifecycle.start(local, ssl=True)

    assert lifecycle.read_scheme(local) == "https"


def test_start_timeout_leaves_nothing_running_or_recorded(
    config: TransformatronConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server that never answers is stopped, not left orphaned behind a failed start."""
    child_pid_file = config.project_dir / "child.pid"
    config.entrypoint.write_text(
        "import os, pathlib, time\n"
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    local = _on_free_port(config)
    monkeypatch.setattr(lifecycle, "STARTUP_TIMEOUT", 1.5)

    with pytest.raises(lifecycle.ServerLifecycleError, match="did not answer"):
        lifecycle.start(local)

    child_pid = int(child_pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)
    assert child_pid not in lifecycle._OWNED
    assert not local.pid_file.exists()
    # The requested scheme outlives the failure on purpose; see the crashed-HTTPS test.
