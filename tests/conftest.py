import pytest
from ms45emu import load_pair, Machine
from ms45emu.image import find_pair


def _pair(kind):
    if find_pair(kind) is None:
        pytest.skip(f"no {kind} pair on this machine (see ms45emu/image.py)")
    return load_pair(kind)


@pytest.fixture
def stock():
    return Machine(_pair("stock"))


@pytest.fixture
def patched():
    return Machine(_pair("patched"))
