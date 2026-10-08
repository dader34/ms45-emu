"""BMW's data files: a program (.0PA) and a calibration (.0DA) written
onto a read's boot loader. The files here are written out of the stock
pair, so no SP-Daten is needed."""
import pytest

from ms45emu import daten
from ms45emu.image import Pair, MPC_SIZE, PROGRAM_ID, PROGRAM_ID_OFFSET


def record(kind, address, data=b""):
    body = bytes([len(data), address >> 8, address & 0xFF, kind]) + bytes(data)
    return ":" + (body + bytes([-sum(body) & 0xFF])).hex().upper()


def write_daten(path, *blocks):
    """(address, data) blocks the way SP-Daten's files have them: 64 KB under
    each linear address record, the last record of a block of type 0x10."""
    lines = []
    for start, data in blocks:
        for at in range(0, len(data), 0x20):
            address = start + at
            if at == 0 or not address & 0xFFFF:
                lines.append(record(0x02, 0, b"\x00\x00"))
                lines.append(record(0x04, 0, (address >> 16).to_bytes(2, "big")))
            lines.append(record(0x10 if at + 0x20 >= len(data) else 0x00, address & 0xFFFF, data[at:at + 0x20]))
    lines.append(record(0x01, 0))
    path.write_text("\r\n".join(lines) + "\r\n")
    return str(path)


def program_file(path, pair):
    lo, hi = daten.PROGRAM
    return write_daten(path, (0, pair.mpc), (daten.EXTERNAL + lo, pair.flash[lo:hi]))


def calibration_file(path, flash):
    lo, hi = daten.CALIBRATION
    return write_daten(path, (daten.EXTERNAL + lo, flash[lo:hi]))


def blank(pair):
    """The pair's boot loader and nothing else: what a DME holds after both regions were erased."""
    flash = bytearray(pair.flash)
    for lo, hi in (daten.CALIBRATION, daten.PROGRAM):
        flash[lo:hi] = b"\xff" * (hi - lo)
    return Pair(bytes(flash), b"\xff" * MPC_SIZE, "blank", check_program=False)


def test_records_with_both_kinds_of_address_and_bmws_type(tmp_path):
    p = tmp_path / "x.0DA"
    p.write_text("\n".join([
        "; a comment",
        record(0x04, 0, b"\x02\x04"), record(0x00, 0x0010, b"\x01\x02"),
        record(0x02, 0, b"\x10\x00"), record(0x10, 0x0004, b"\x03"),            # segment 0x1000: + 0x10000
        record(0x01, 0), record(0x00, 0, b"\xEE"),
    ]))
    assert list(daten.records(str(p))) == [(0x2040010, b"\x01\x02"), (0x2050004, b"\x03")]


def test_a_damaged_record_is_refused(tmp_path):
    p = tmp_path / "x.0PA"
    p.write_text(record(0x00, 0, b"\x01\x02")[:-2] + "00")
    with pytest.raises(ValueError, match="line 1"):
        list(daten.records(str(p)))


def test_a_program_and_a_calibration_make_the_pair_they_came_from(stock, tmp_path):
    pair = stock.pair
    program = program_file(tmp_path / "7561382A.0PA", pair)
    calibration = calibration_file(tmp_path / "P7561515.0DA", pair.flash)
    said = []
    built = daten.build(blank(pair), program, calibration, say=said.append)
    assert built.flash == pair.flash and built.mpc == pair.mpc and not said
    assert built.traced and "7561382A.0PA + P7561515.0DA" in built.name
    assert daten.calibration_token(calibration) == daten.token(pair.flash, daten.PROGRAM_TOKEN)


def test_a_program_alone_keeps_a_calibration_made_for_it(stock, tmp_path):
    pair = stock.pair
    said = []
    built = daten.build(pair, program_file(tmp_path / "p.0PA", pair), say=said.append)
    assert built.flash == pair.flash and not said


def test_a_calibration_is_found_next_to_the_program(stock, tmp_path):
    pair = stock.pair
    program = program_file(tmp_path / "p.0PA", pair)
    other = bytearray(pair.flash)
    other[daten.CALIBRATION_TOKEN:daten.CALIBRATION_TOKEN + 6] = b"457X9L"
    calibration_file(tmp_path / "A_other.0DA", other)                # first by name, for another program
    calibration_file(tmp_path / "B_good.0DA", pair.flash)
    said = []
    built = daten.build(blank(pair), program, say=said.append)
    assert built.flash == pair.flash
    assert len(said) == 1 and "B_good.0DA" in said[0]
    # and one that is named is used as it is, with a word about it
    said = []
    built = daten.build(blank(pair), program, str(tmp_path / "A_other.0DA"), say=said.append)
    assert built.flash == bytes(other) and len(said) == 1 and "another program" in said[0]


def test_a_program_of_another_family_is_refused(stock, tmp_path):
    flash = bytearray(stock.pair.flash)
    flash[PROGRAM_ID_OFFSET:PROGRAM_ID_OFFSET + len(PROGRAM_ID)] = b"0044560BO02S"       # an MS45.0 program
    program = program_file(tmp_path / "7561380A.0PA", Pair(bytes(flash), stock.pair.mpc, "ms45.0", check_program=False))
    with pytest.raises(ValueError, match="not an MS45.1 program"):
        daten.build(stock.pair, program, calibration_file(tmp_path / "c.0DA", flash), say=lambda text: None)


def test_a_file_for_another_module_is_refused(stock, tmp_path):
    p = write_daten(tmp_path / "tcu.0PA", (0x0A0000, bytes(64)))
    with pytest.raises(ValueError, match="not an MS45 program"):
        daten.build(stock.pair, p)


def test_with_a_program_the_external_flash_is_enough(stock, tmp_path, monkeypatch):
    pair = stock.pair
    flash = tmp_path / "read_Flash.bin"
    flash.write_bytes(pair.flash)
    monkeypatch.setenv("MS45_FLASH", str(flash))
    monkeypatch.delenv("MS45_MPC", raising=False)
    monkeypatch.setattr(daten, "IMAGES_DIR", str(tmp_path))
    monkeypatch.setattr(daten, "find_pair", lambda kind: None)
    built = daten.load("stock", program_file(tmp_path / "p.0PA", pair), say=lambda text: None)
    assert built.flash == pair.flash and built.mpc == pair.mpc


def test_a_kept_boot_loader_is_enough_for_a_program(stock, tmp_path, monkeypatch):
    pair = stock.pair
    program = program_file(tmp_path / "p.0PA", pair)
    for name in ("MS45_FLASH", "MS45_MPC"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(daten, "IMAGES_DIR", str(tmp_path))
    monkeypatch.setattr(daten, "find_pair", lambda kind: None)
    monkeypatch.delenv("MS45_BOOT", raising=False)
    with pytest.raises(FileNotFoundError, match="stock_boot.bin"):
        daten.load("stock", program, say=lambda text: None)

    (tmp_path / "stock_boot.bin").write_bytes(pair.flash[:daten.BOOT_SIZE])
    calibration = calibration_file(tmp_path / "c.0DA", pair.flash)
    built = daten.load("stock", program, say=lambda text: None)             # the calibration is found next to it
    lo, hi = daten.CALIBRATION[0], daten.PROGRAM[1]
    assert built.flash[:hi] == daten.without_aif(pair.flash)[:hi] and built.mpc == pair.mpc
    assert set(built.flash[hi:]) == {0xFF}                                  # nothing of a read above the program
    assert "c.0DA on the kept boot loader" in built.name and calibration


def test_the_kept_boot_loader_has_no_programming_log(stock, tmp_path, monkeypatch):
    pair = stock.pair
    lo, hi = daten.AIF
    if set(pair.flash[lo:hi]) == {0xFF}:
        pytest.skip("the stock read has an empty programming log already")
    read = tmp_path / "read_Flash.bin"
    read.write_bytes(pair.flash)
    kept = daten.keep_boot(str(read), str(tmp_path / "stock_boot.bin"))
    data = open(kept, "rb").read()
    assert len(data) == daten.BOOT_SIZE and set(data[lo:hi]) == {0xFF}
    assert data[:lo] == pair.flash[:lo] and data[hi:] == pair.flash[hi:daten.BOOT_SIZE]

    # and one that was kept as it was read is emptied on the way in
    (tmp_path / "stock_boot.bin").write_bytes(pair.flash[:daten.BOOT_SIZE])
    for name in ("MS45_FLASH", "MS45_MPC", "MS45_BOOT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(daten, "IMAGES_DIR", str(tmp_path))
    monkeypatch.setattr(daten, "find_pair", lambda kind: None)
    built = daten.load("stock", program_file(tmp_path / "p.0PA", pair), say=lambda text: None)
    assert set(built.flash[lo:hi]) == {0xFF}
    # a read that is named keeps its own: it is that DME's
    monkeypatch.setenv("MS45_FLASH", str(read))
    built = daten.load("stock", program_file(tmp_path / "p.0PA", pair), say=lambda text: None)
    assert built.flash[lo:hi] == pair.flash[lo:hi]
