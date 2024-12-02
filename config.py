from .wrapper import SpecWrapper

spectree = SpecWrapper(
    "falcon-asgi", title="Falcon API", version="1.0.0", mode="strict"
)


def get_spectree():
    return spectree
