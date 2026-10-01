"""The safety monitor's code sum, computed by the DME's own routine."""
from ms45emu import dme


def test_stock_sum_matches_stored(stock):
    assert dme.romtest_sum_native(stock) == dme.romtest_sum_stored(stock)


def test_patched_sum_matches_stored(patched):
    # Leaving this stale is what made the monitor reset the DME at start-up.
    assert dme.romtest_sum_native(patched) == dme.romtest_sum_stored(patched)


def test_patched_sum_differs_from_stock(stock, patched):
    assert dme.romtest_sum_native(patched) != dme.romtest_sum_native(stock)
