import re
import math
from collections import Counter

COMMON_SHELL_OPERATORS = [
    ";", "&&", "||", "|", "`", "$(", ">", "<"
]

def entropy(s):
    if not s:
        return 0
    probs = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log(p, 2) for p in probs)

def extract_command_features(payload):
    payload = payload.lower()

    return {
        "length": len(payload),
        "operator_count": sum(payload.count(op) for op in COMMON_SHELL_OPERATORS),
        "dotdot_count": payload.count("../"),
        "slash_count": payload.count("/"),
        "has_backtick": int("`" in payload),
        "has_dollar_paren": int("$(" in payload),
        "entropy": entropy(payload),
        "num_special_chars": len(re.findall(r"[^\w\s]", payload)),
        "contains_pipe": int("|" in payload),
    }
