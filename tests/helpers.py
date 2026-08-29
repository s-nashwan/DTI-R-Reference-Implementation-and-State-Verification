class CounterNonce:
    def __init__(self, start: int = 1):
        self.value = start

    def __call__(self) -> bytes:
        value = self.value
        self.value += 1
        return value.to_bytes(16, "big")

class SequenceNonce:
    def __init__(self, values):
        self.values = list(values)
        self.index = 0

    def __call__(self) -> bytes:
        if self.index >= len(self.values):
            raise RuntimeError("nonce sequence exhausted")
        value = self.values[self.index]
        self.index += 1
        return value
