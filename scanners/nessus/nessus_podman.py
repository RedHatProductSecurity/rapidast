CLASSNAME = "Nessus"


class Nessus:
    def __init__(self, *args):
        raise RuntimeError("nessus scanner is not supported with 'general.container.type=podman' config option")
