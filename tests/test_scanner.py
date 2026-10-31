import socket
import threading

import pytest

from hawkscan import parse_ports, scan_host


def test_parse_ports_mixed():
    assert parse_ports("80,22,20-22") == [20, 21, 22, 80]


@pytest.mark.parametrize("spec", ["", "abc", "0", "70000", "100-10"])
def test_parse_ports_invalid(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_detects_open_and_closed_ports():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    open_port = server.getsockname()[1]
    closed_port = _free_port()

    def serve():
        try:
            conn, _ = server.accept()
            conn.sendall(b"SSH-2.0-TestServer\r\n")
            conn.close()
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()

    report = scan_host("127.0.0.1", [open_port, closed_port], timeout=1.0)
    states = {r.port: r for r in report.results}
    server.close()

    assert states[open_port].state == "open"
    assert "SSH-2.0" in states[open_port].banner
    assert states[closed_port].state == "closed"


def test_unresolvable_host():
    with pytest.raises(ValueError):
        scan_host("no-such-host.invalid", [80], timeout=0.5)
