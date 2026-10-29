import http.client
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from qa import serve_probe as probe


class ProbeServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name) / "results"
        self.server = probe.make_server(self.output, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01})
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())
        self.temporary.cleanup()

    def request(self, method, path, body=None, headers=None):
        port = self.server.server_port
        values = {"Origin": f"http://127.0.0.1:{port}", "Content-Type": "application/json"}
        values.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request(method, path, body=body, headers=values)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_loopback_only_and_exact_static_whitelist(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        for path in ("/", "/tablet-probe.html"):
            status, headers, body = self.request("GET", path)
            self.assertEqual(status, 200)
            self.assertEqual(body, probe.HTML.read_bytes())
            self.assertIn("connect-src 'self'", headers["Content-Security-Policy"])
        for path in ("/../serve_probe.py", "/%2e%2e/serve_probe.py", "/tablet-probe.html/../serve_probe.py",
                     "/serve_probe.py", "/results.json", "/?path=../serve_probe.py"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path)[0], 404)
        self.assertEqual(self.request("GET", "/", headers={"Host": "foreign.example"})[0], 403)

    def test_only_whitelisted_metrics_are_saved_privately(self):
        metrics = {"schema": 1, "front_camera": "ok", "back_camera": "unavailable", "rms_max": 0.125,
                   "pointer_type": "pen", "pressure": 0.5, "tilt_x": -42, "pen_hover_events": 5,
                   "page_x": 128.5, "page_y": 720, "preview_visible": True, "webgl_renderer": "adreno"}
        self.assertEqual(self.request("POST", "/results", json.dumps(metrics))[0], 200)
        saved = self.output / "results.json"
        self.assertEqual(json.loads(saved.read_text()), metrics)
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual([path.name for path in self.output.iterdir()], ["results.json"])
        self.assertEqual(self.request("POST", "/results", '{"schema":1,"pointer_events":2}')[0], 200)
        self.assertEqual(json.loads(saved.read_text()), {"schema": 1, "pointer_events": 2})

    def test_rejects_oversized_malformed_and_private_metrics(self):
        self.assertEqual(self.request("POST", "/results", b"x" * (probe.MAX_BODY + 1))[0], 413)
        bodies = [b"{", b"\xff", b"[]", b"null", b'{"schema":true}', b'{"schema":1,"schema":1}',
                  b'{"schema":1,"pressure":NaN}', b'{"schema":1,"pressure":Infinity}',
                  b'{"schema":1,"pressure":1.1}', b'{"schema":1,"tilt_x":91}',
                  b'{"schema":1,"pointer_events":true}', b'{"schema":1,"pointer_events":1.5}',
                  b'{"schema":1,"front_camera":"secret label"}', b'{"schema":1,"deviceId":"secret"}',
                  b'{"schema":1,"labels":["secret"]}', b'{"schema":1,"image":"data:image/png;base64,AA=="}']
        bodies.append(b'{"schema":1,"pressure":' + b"9" * 400 + b"}")
        for body in bodies:
            with self.subTest(body=body):
                self.assertEqual(self.request("POST", "/results", body)[0], 400)
        self.assertFalse((self.output / "results.json").exists())
        self.assertEqual(list(self.output.iterdir()), [])

    def test_rejects_foreign_origin_and_unsupported_post_framing(self):
        body = b'{"schema":1}'
        for headers, expected in [({"Origin": "https://foreign.example"}, 403), ({"Origin": "null"}, 403),
                                  ({"Sec-Fetch-Site": "cross-site"}, 403), ({"Content-Length": "-1"}, 400),
                                  ({"Transfer-Encoding": "chunked"}, 400), ({"Content-Type": "text/plain"}, 415)]:
            with self.subTest(headers=headers):
                self.assertEqual(self.request("POST", "/results", body, headers)[0], expected)
        self.assertEqual(self.request("POST", "/../results", body)[0], 404)
        self.assertFalse((self.output / "results.json").exists())

    def test_output_refuses_source_cloud_symlinks_and_unique_data(self):
        root = Path(self.temporary.name)
        source = probe.HTML.parent.parent
        (root / "source-link").symlink_to(source, target_is_directory=True)
        with patch.object(Path, "home", return_value=root):
            for path in (source / "artifacts/browser", root / "source-link/results", root / "Documents/results"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    probe.output_directory(path)
        with self.assertRaises(ValueError):
            probe.output_directory(root)


class BrowserScriptTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node is needed only for the hardware-free browser mock")
    def test_browser_metrics_consent_and_stop_with_mocked_devices(self):
        source = probe.HTML.read_text().split("<script>", 1)[1].split("</script>", 1)[0]
        harness = r"""
const vm = require('node:vm'), assert = require('node:assert/strict');
const source = __SOURCE__;
const elements = new Map(), documentEvents = {}, frames = [], videoFrames = [], allTracks = [];
const context2d = {fillRect(){}, beginPath(){}, arc(){}, fill(){}, moveTo(){}, lineTo(){}, stroke(){}, clearRect(){}};
let holdPlay = null, capture = null, uploaded = null, mediaCalls = 0;
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    handlers: {}, width: 1200, height: 400, videoWidth: 0, videoHeight: 0, paused: true,
    addEventListener(type, handler){this.handlers[type] = handler;},
    getContext(type){return type === 'webgl' ? null : context2d;},
    getBoundingClientRect(){return {left: 0, top: 0, width: 300, height: 180};},
    async play(){this.videoWidth = 640; this.videoHeight = 480; this.paused = false; if(holdPlay) await holdPlay;},
    requestVideoFrameCallback(callback){videoFrames.push(callback); return videoFrames.length;},
    cancelVideoFrameCallback(){}, setPointerCapture(){}
  });
  return elements.get(id);
}
function track(kind, facing = 'user') {
  const result = {kind, readyState: 'live', stop(){this.readyState = 'ended';},
    getSettings(){return {facingMode: facing, deviceId: 'private-device-id'};}, addEventListener(){}};
  allTracks.push(result); return result;
}
class MediaStream {
  constructor(tracks){this.tracks = tracks;}
  getTracks(){return this.tracks;}
  getVideoTracks(){return this.tracks.filter(value => value.kind === 'video');}
  getAudioTracks(){return this.tracks.filter(value => value.kind === 'audio');}
}
class AudioContext {
  constructor(){this.state = 'running'; this.sampleRate = 48000;}
  async resume(){}
  async close(){this.state = 'closed';}
  createMediaStreamSource(){return {connect(){}, disconnect(){}};}
  createAnalyser(){return {fftSize: 0, disconnect(){}, getFloatTimeDomainData(values){values.fill(.25);}};}
}
const sandbox = {
  document: {getElementById: element, addEventListener(type, callback){documentEvents[type] = callback;},
    hidden: false, documentElement: {scrollWidth: 1000, scrollHeight: 2000}},
  window: {isSecureContext: true, addEventListener(){}},
  navigator: {mediaDevices: {
    async getUserMedia(constraints){mediaCalls++; if(capture) return capture;
      const tracks = [track('video', constraints.video.facingMode.exact || 'user')];
      if(constraints.audio) tracks.push(track('audio')); return new MediaStream(tracks);},
    getSupportedConstraints(){return {facingMode: true};},
    async enumerateDevices(){return [{kind: 'videoinput', label: 'private-label', deviceId: 'private-id'}, {kind: 'audioinput'}];}
  }},
  screen: {orientation: {type: 'landscape-primary', angle: 90}}, innerWidth: 1000, innerHeight: 1000,
  performance: {now(){return 0;}}, requestAnimationFrame(callback){frames.push(callback);},
  MediaStream, AudioContext,
  async fetch(url, options){assert.equal(url, '/results'); assert.equal(options.credentials, 'omit');
    uploaded = JSON.parse(options.body); return {ok: true};}
};
vm.createContext(sandbox); vm.runInContext(source, sandbox);
const state = () => vm.runInContext('state', sandbox), click = id => element(id).handlers.click();
async function flushUntil(check) {for(let n = 0; n < 20 && !check(); n++) await Promise.resolve(); assert.ok(check());}
(async () => {
  assert.equal(mediaCalls, 0);
  await click('start'); assert.equal(state().media_status, 'ok'); assert.equal(state().front_camera, 'ok');
  await click('back'); assert.equal(state().back_camera, 'ok');
  videoFrames.at(-1)(200, {presentedFrames: 12});
  const pointer = {target: element('ink'), pointerType: 'pen', pressure: .7, tiltX: 23, tiltY: -12,
    buttons: 1, button: 0, clientX: 40, clientY: 70, pageX: 40, pageY: 500, pointerId: 1};
  documentEvents.pointerdown(pointer); documentEvents.pointermove({...pointer, clientX: 55});
  documentEvents.pointerup({...pointer, buttons: 0, pressure: 0});
  documentEvents.pointermove({...pointer, buttons: 0, pressure: 0});
  frames.shift()(200); await click('save');
  assert.equal(uploaded.pointer_type, 'pen'); assert.equal(uploaded.page_y, 500);
  assert.equal(uploaded.pen_hover_events, 1); assert.equal(uploaded.drawing_segments, 1);
  assert.equal(uploaded.video_frames, 1); assert.equal(uploaded.preview_visible, true);
  assert.equal(uploaded.rms_mean, .25); assert.equal(uploaded.audio_context, 'running');
  assert.ok(!JSON.stringify(uploaded).includes('private-'));
  click('stop'); assert.ok(allTracks.every(value => value.readyState === 'ended'));
  assert.equal(state().media_status, 'stopped');
  let resolveCapture;
  capture = new Promise(resolve => {resolveCapture = resolve;});
  const before = mediaCalls, pending = click('start');
  await flushUntil(() => mediaCalls > before); click('stop');
  resolveCapture(new MediaStream([track('video'), track('audio')])); await pending;
  capture = null; assert.equal(state().media_status, 'stopped');
  assert.ok(allTracks.every(value => value.readyState === 'ended'));
  let resolvePlay;
  holdPlay = new Promise(resolve => {resolvePlay = resolve;});
  const beforeTracks = allTracks.length, pendingPlay = click('start');
  await flushUntil(() => allTracks.length > beforeTracks); await Promise.resolve();
  click('stop'); resolvePlay(); await pendingPlay;
  assert.equal(state().camera_status, 'stopped'); assert.equal(state().media_status, 'stopped');
  assert.ok(allTracks.every(value => value.readyState === 'ended'));
  console.log(JSON.stringify(uploaded));
})().catch(error => {console.error(error); process.exitCode = 1;});
""".replace("__SOURCE__", json.dumps(source))
        result = subprocess.run([shutil.which("node"), "-"], input=harness, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        metrics = probe.validate_metrics(json.loads(result.stdout))
        self.assertEqual(metrics["pointer_type"], "pen")
        self.assertEqual(metrics["rms_mean"], 0.25)


if __name__ == "__main__":
    unittest.main()
