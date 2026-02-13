class RiskEngine:
    def calculate(self, network_result, web_result):
        score = 0

        if network_result and network_result["confidence"] > 70:
            score += 50

        if web_result and web_result["confidence"] > 70:
            score += 50

        return min(score, 100)
