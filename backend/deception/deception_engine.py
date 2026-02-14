class DeceptionEngine:
    def deploy(self, threat_type):
        strategies = {
            "SQL Injection": "fake_database",
            "XSS": "sandbox_response",
            "DDoS": "rate_limiting",
            "Port Scan": "fake_ports"
        }

        return strategies.get(threat_type, "monitor")
