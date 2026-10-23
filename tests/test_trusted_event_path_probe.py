import unittest

from agent.diagnostics.trusted_event_path_probe import trace_trusted_event_path


class TrustedEventPathProbeTests(unittest.TestCase):
    def _run(self, **overrides):
        calls = []

        def mark(name, result=True):
            calls.append(name)
            return result

        funcs = {
            "bind": lambda event: mark("bind", True),
            "bridge": lambda event: mark("bridge", {"event_type": "DETECTION"}),
            "correlate": lambda detection: mark("correlate", True),
            "persist": lambda detection: mark("persist", True),
            "ack": lambda event: mark("ack", True),
        }
        funcs.update(overrides)
        result = trace_trusted_event_path(
            object(),
            bind=funcs["bind"],
            bridge=funcs["bridge"],
            correlate=funcs["correlate"],
            persist=funcs["persist"],
            ack=funcs["ack"],
        )
        return result, calls

    def test_success_reaches_ack(self):
        result, calls = self._run()
        self.assertEqual(result["marker"], "TRUSTED_EVENT_SUCCESS")
        self.assertEqual(calls, ["bind", "bridge", "correlate", "persist", "ack"])

    def test_each_failure_marker_is_closed_and_no_ack(self):
        failures = (
            ("bind", "TRUSTED_EVENT_DELIVERY_BINDING_FAILED"),
            ("bridge", "TRUSTED_EVENT_BRIDGE_FAILED"),
            ("correlate", "TRUSTED_EVENT_CORRELATION_FAILED"),
            ("persist", "TRUSTED_EVENT_PERSISTENCE_FAILED"),
            ("ack", "TRUSTED_EVENT_ACK_FAILED"),
        )
        for name, expected in failures:
            def fail(*args, _name=name):
                if _name == "bind":
                    return False
                if _name == "bridge":
                    return None
                if _name in {"correlate", "persist", "ack"}:
                    return False
                return True

            result, calls = self._run(**{name: fail})
            self.assertEqual(result["marker"], expected)
            self.assertNotIn("ack", calls[:-1])

    def test_exception_is_redacted_and_does_not_leak_arguments(self):
        def fail(_event):
            raise RuntimeError("secret-token-and-event-id")

        result, calls = self._run(bind=fail)
        self.assertEqual(result["marker"], "TRUSTED_EVENT_DELIVERY_BINDING_FAILED_EXCEPTION")
        self.assertEqual(result["exception_class"], "RuntimeError")
        self.assertNotIn("secret", repr(result))
        self.assertEqual(calls, [])

    def test_tenant_identity_cases_stop_at_the_injected_boundary(self):
        cases = (
            ("tenantless", "bind", "TRUSTED_EVENT_DELIVERY_BINDING_FAILED"),
            ("spoofed", "persist", "TRUSTED_EVENT_PERSISTENCE_FAILED"),
            ("cross_tenant", "persist", "TRUSTED_EVENT_PERSISTENCE_FAILED"),
        )
        for label, boundary, expected in cases:
            event = {"tenant_case": label}
            calls = []

            def bind(value):
                calls.append("bind")
                return False if boundary == "bind" else value

            def bridge(value):
                calls.append("bridge")
                return {"event_type": "DETECTION", "tenant_case": value["tenant_case"]}

            def correlate(value):
                calls.append("correlate")
                return True

            def persist(value):
                calls.append("persist")
                return False if boundary == "persist" else True

            def ack(value):
                calls.append("ack")
                return True

            result = trace_trusted_event_path(
                event, bind=bind, bridge=bridge, correlate=correlate,
                persist=persist, ack=ack,
            )
            self.assertEqual(result["marker"], expected)
            self.assertNotIn("ack", calls)


if __name__ == "__main__":
    unittest.main()
