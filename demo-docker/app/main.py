# main.py
import logging
import os
import time
import socket
import sys
from flask import Flask, Response, request

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# Logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("flask-demo")

# =========================
# CrashLoop simulation
# =========================
if os.getenv("CRASH_ON_START", "0") == "1":
    log.error('{"event":"startup","error_type":"crashloop","msg":"CRASH_ON_START=1, exiting now"}')
    sys.exit(42)

# =========================
# Prometheus metrics
# =========================
REQ_COUNT = Counter("http_requests_total", "Total HTTP requests", ["path", "method", "status"])
ERR_COUNT = Counter("app_errors_total", "Total app errors", ["error_type"])
REQ_LAT = Histogram("http_request_duration_seconds", "Request latency", ["path"])


def _observe(path: str, status: str, start: float):
    REQ_LAT.labels(path=path).observe(time.time() - start)
    REQ_COUNT.labels(path=path, method="GET", status=status).inc()


# =========================
# Routes
# =========================

@app.get("/")
def hello():
    start = time.time()
    _observe("/", "200", start)
    return "ok\n", 200


# 1) Dependency failure simulation (TCP connect)
@app.get("/dep")
def dep():
    start = time.time()
    host = request.args.get("host", "10.0.0.1")
    port = int(request.args.get("port", "5432"))
    timeout = float(request.args.get("timeout", "0.3"))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        _observe("/dep", "200", start)
        return "dep ok\n", 200
    except Exception as e:
        ERR_COUNT.labels(error_type="dependency").inc()
        log.error(
            f'{{"event":"request","path":"/dep","error_type":"dependency",'
            f'"host":"{host}","port":{port},"msg":"connect failed","err":"{e}"}}'
        )
        _observe("/dep", "500", start)
        return "dependency failure\n", 500


# 2) Config error simulation
@app.get("/config")
def config():
    start = time.time()
    required = os.getenv("REQUIRED_TOKEN")
    if not required:
        ERR_COUNT.labels(error_type="config").inc()
        log.error(
            '{"event":"request","path":"/config","error_type":"config","msg":"Missing REQUIRED_TOKEN env var"}'
        )
        _observe("/config", "500", start)
        return "missing config\n", 500
    _observe("/config", "200", start)
    return "config ok\n", 200


# 3) Resource pressure simulations

@app.get("/cpu")
def cpu():
    start = time.time()
    seconds = float(request.args.get("seconds", "0.6"))
    end = time.time() + seconds
    while time.time() < end:
        pass
    _observe("/cpu", "200", start)
    return f"cpu burn {seconds}s\n", 200


@app.get("/mem")
def mem():
    start = time.time()
    mb = int(request.args.get("mb", "200"))
    try:
        _ = bytearray(mb * 1024 * 1024)
        ERR_COUNT.labels(error_type="memory").inc()
        log.error(
            f'{{"event":"request","path":"/mem","error_type":"memory","msg":"allocated memory","mb":{mb}}}'
        )
        _observe("/mem", "200", start)
        return f"allocated {mb}MB\n", 200
    except Exception as e:
        ERR_COUNT.labels(error_type="memory").inc()
        log.error(
            f'{{"event":"request","path":"/mem","error_type":"memory","msg":"allocation failed","err":"{e}"}}'
        )
        _observe("/mem", "500", start)
        return "mem allocation failed\n", 500


@app.get("/slow")
def slow():
    start = time.time()
    time.sleep(0.8)
    _observe("/slow", "200", start)
    return "slow\n", 200


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@app.get("/unknown")
def unknown():
    start = time.time()
    samples = [
        "ERROR flask-demo unknown error",
        "ERROR flask-demo request failed",
        "ERROR flask-demo unexpected exception",
        "ERROR flask-demo handler failed",
        "ERROR flask-demo internal error",
    ]
    msg = samples[int(time.time()) % len(samples)]
    log.error(msg)
    _observe("/unknown", "500", start)
    return "unknown error\n", 500


# =========================
# Entry point (for docker)
# =========================
if __name__ == "__main__":
    # For local dev only; in Docker we will use gunicorn
    app.run(host="0.0.0.0", port=8080)
