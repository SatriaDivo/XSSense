class Detector:
    @staticmethod
    def is_reflected(payload, response_text):
        if response_text is None:
            return False
        return payload in response_text
