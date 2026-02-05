import math


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

