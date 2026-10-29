#!/usr/bin/env python3
"""Serve the tablet probe on loopback; save sanitized metrics in a new local directory.

python3 -B qa/serve_probe.py --output /private/tmp/ai-development/OWNED_TASK/tablet-results
The parent owns USB forwarding and Chrome consent. No access/body logs are kept.
"""
import argparse
import json
import math
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


HTML = Path(__file__).with_name("tablet-probe.html")
MAX_BODY = 32 * 1024
STATUSES = {"untested", "requesting", "ok", "stopped", "ended", "denied", "unavailable",
            "busy", "unsupported", "unconfirmed", "error", "lost"}
STATUS_FIELDS = {name: STATUSES for name in (
    "media_status", "camera_status", "mic_status", "front_camera", "back_camera",
    "device_enumeration", "canvas2d_status", "webgl_status")}
STATUS_FIELDS.update({
    "frame_count_status": {"untested", "ok", "fallback", "unsupported"},
    "audio_context": {"untested", "running", "suspended", "closed", "interrupted", "error", "unknown"},
    "facing_mode": {"user", "environment", "left", "right", "unknown"},
    "preview_orientation": {"portrait", "landscape", "square", "unknown"},
    "screen_orientation": {"portrait-primary", "portrait-secondary", "landscape-primary", "landscape-secondary", "unknown"},
    "webgl_renderer": {"adreno", "mali", "swiftshader", "angle", "other", "unknown"},
    "pointer_type": {"pen", "touch", "mouse", "unknown"},
})
COUNTERS = set(("elapsed_ms video_inputs audio_inputs video_frames video_width video_height "
                "audio_sample_rate mic_samples canvas2d_frames webgl_frames webgl_errors pointer_events "
                "pointer_down pointer_move pointer_up pointer_cancel hover_events pen_hover_events "
                "pen_events touch_events mouse_events drawing_segments buttons buttons_seen "
                "document_width document_height viewport_width viewport_height").split())
RANGES = {
    **{name: (0, 1) for name in ("rms_current", "rms_min", "rms_max", "rms_mean",
                                "pressure", "pressure_min", "pressure_max")},
    **{name: (-90, 90) for name in ("tilt_x", "tilt_y", "tilt_x_min", "tilt_x_max", "tilt_y_min", "tilt_y_max")},
    **{name: (-10000000, 10000000) for name in ("client_x", "client_y", "page_x", "page_y", "canvas_x", "canvas_y")},
    **{name: (0, 10000000) for name in ("preview_width", "preview_height", "visible_width", "visible_height", "canvas_width", "canvas_height")},
    "orientation_angle": (-360, 360), "button": (-1, 31),
}
BOOLEANS = {"preview_visible", "hover"}


def validate_metrics(value):
    if not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("Invalid metrics schema")
    for name, metric in value.items():
        if name == "schema":
            continue
        if name in STATUS_FIELDS:
            valid = isinstance(metric, str) and metric in STATUS_FIELDS[name]
        elif name in COUNTERS:
            valid = type(metric) is int and 0 <= metric <= 2**53 - 1
        elif name in RANGES:
            low, high = RANGES[name]
            valid = type(metric) in (int, float) and low <= metric <= high and math.isfinite(metric)
        elif name in BOOLEANS:
            valid = type(metric) is bool
        else:
            valid = False
        if not valid:
            raise ValueError("Unknown or malformed metric")
    return dict(value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate metric")
        result[key] = value
    return result


def output_directory(path):
    path = path.expanduser().resolve()
    home = Path.home().resolve()
    roots = [home / name for name in ("Documents", "Desktop", "Library/Mobile Documents",
                                      "Library/CloudStorage", "Dropbox", "OneDrive", "Google Drive")]
    roots += list(home.glob("Dropbox*")) + list(home.glob("OneDrive*")) + list(home.glob("Google Drive*"))
    if any(path.is_relative_to(root.resolve()) for root in roots):
        raise ValueError("Output must be outside cloud-sync roots")
    if path.is_relative_to(Path(__file__).resolve().parent.parent) or any(
            (parent / ".git").exists() for parent in (path, *path.parents)):
        raise ValueError("Output must be outside source repositories")
    if path.exists() and (not path.is_dir() or path.stat().st_uid != os.getuid() or any(path.iterdir())):
        raise ValueError("Output must be a new or empty directory owned by the current user")
    return path


def save_metrics(directory, metrics):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory,
                                         prefix=".results-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(metrics, stream, separators=(",", ":"), sort_keys=True, allow_nan=False)
            stream.write("\n")
        temporary.replace(directory / "results.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class ProbeHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, _format, *args):
        pass

    def reply(self, status, body, content_type="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(self), microphone=(self), geolocation=(), display-capture=()")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; "
                         "style-src 'unsafe-inline'; connect-src 'self'; media-src 'self' blob:; "
                         "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def local_request(self, post=False):
        port = self.server.server_port
        host = self.headers.get("Host", "").lower()
        if host not in {f"127.0.0.1:{port}", f"localhost:{port}"}:
            self.reply(403, b'{"error":"loopback host required"}')
            return False
        if post and (self.headers.get("Origin") != "http://" + host
                     or self.headers.get("Sec-Fetch-Site") == "cross-site"):
            self.reply(403, b'{"error":"same origin required"}')
            return False
        return True

    def do_GET(self):
        if not self.local_request():
            return
        if self.path not in {"/", "/tablet-probe.html"}:
            self.reply(404, b'{"error":"not found"}')
            return
        try:
            body = HTML.read_bytes()
        except OSError:
            self.reply(500, b'{"error":"probe unavailable"}')
            return
        self.reply(200, body, "text/html; charset=utf-8")

    def do_POST(self):
        if not self.local_request(post=True):
            return
        if self.path != "/results":
            self.reply(404, b'{"error":"not found"}')
            return
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
            self.reply(400, b'{"error":"one numeric content length required"}')
            return
        if len(lengths[0]) > 10:
            self.reply(413, b'{"error":"metrics exceed 32 KiB"}')
            return
        length = int(lengths[0])
        if length > MAX_BODY:
            self.reply(413, b'{"error":"metrics exceed 32 KiB"}')
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json" or self.headers.get("Content-Encoding"):
            self.reply(415, b'{"error":"UTF-8 JSON required"}')
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete body")
            metrics = validate_metrics(json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object))
        except (ValueError, UnicodeError, RecursionError):
            self.reply(400, b'{"error":"invalid metrics"}')
            return
        except (TimeoutError, OSError):
            self.reply(408, b'{"error":"body timed out"}')
            return
        try:
            with self.server.results_lock:
                save_metrics(self.server.output, metrics)
        except OSError:
            self.reply(500, b'{"error":"could not save metrics"}')
            return
        self.reply(200, b'{"saved":true}')


def make_server(output, port=18767):
    output = output_directory(output)
    server = ThreadingHTTPServer(("127.0.0.1", port), ProbeHandler)
    try:
        output.mkdir(parents=True, mode=0o700, exist_ok=True)
        output.chmod(0o700)
    except OSError:
        server.server_close()
        raise
    server.output = output
    server.results_lock = threading.Lock()
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18767)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    try:
        with make_server(args.output, args.port) as server:
            print(f"Probe: http://127.0.0.1:{server.server_port}/", flush=True)
            print(f"Metrics: {server.output / 'results.json'}", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    except (OSError, ValueError) as error:
        parser.exit(2, f"serve_probe: {error}\n")


if __name__ == "__main__":
    main()
