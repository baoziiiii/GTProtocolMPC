class CipherSuite:
    def __init__(self):
        self.scheme = None
        self.modulus_length = None

    def __repr__(self):
        return "Encryption Scheme: %s\nModulus Length: %d" % (self.scheme, self.modulus_length)