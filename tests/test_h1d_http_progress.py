from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import unittest
from agent.service_lifecycle import serve_http


class HTTPProgressTests(unittest.TestCase):
    def test_stalled_probe_has_one_handler_and_recovers_after_completion(self):
        entered=threading.Event(); release=threading.Event(); good=threading.Event()
        stop=threading.Event(); lock=threading.Lock(); metrics=dict(calls=0,active=0,maximum=0)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                with lock:
                    metrics["calls"]+=1; metrics["active"]+=1
                    metrics["maximum"]=max(metrics["maximum"],metrics["active"])
                entered.set()
                try:
                    release.wait(3)
                    self.send_response(200); self.send_header("Content-Length","2"); self.end_headers()
                    try: self.wfile.write(b"{}")
                    except OSError: pass
                finally:
                    with lock: metrics["active"]-=1
        class Guard:
            def progress(self,*,healthy):
                if healthy: good.set()
        server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        worker=threading.Thread(target=serve_http,args=(server,Guard(),stop,"/health"),kwargs=dict(probe_interval=.05,probe_timeout=.05))
        worker.start()
        try:
            self.assertTrue(entered.wait(2)); time.sleep(.25)
            self.assertEqual(metrics["calls"],1)
            self.assertFalse(good.is_set())
            release.set(); self.assertTrue(good.wait(2))
            self.assertEqual(metrics["maximum"],1)
        finally:
            release.set(); stop.set(); server.shutdown(); worker.join(timeout=5)
        self.assertFalse(worker.is_alive())


if __name__ == "__main__": unittest.main()
