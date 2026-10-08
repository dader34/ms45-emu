"""The function map (ms45emu/funcmap.py, tools/funcmap.py)."""
from ms45emu import dme
from ms45emu.board import Board
from ms45emu.funcmap import FunctionMap, branch_target, canonical
from ms45emu.xref import Xref, parse_address

SCHEDULER_TASK = 0x3B38C
DME1_BUILDER = 0x4B528


def test_branch_decoding():
    assert branch_target(0x4BE9C, 0x4BFFF68D) == (0x4B528, True)       # bl 0x4B528
    assert branch_target(0x100, 0x48000012) == (0x10, False)           # ba 0x10
    assert branch_target(0x1000, 0x4082FFF0) == (0xFF0, False)         # bne -0x10
    assert branch_target(0, 0x60000000) is None
    assert canonical(0xFFE40000) == 0xFFF40000 and canonical(0x4B528) == 0x4B528


def test_sweep_finds_the_traced_routines(stock):
    fm = FunctionMap(stock.pair)
    assert len(fm.functions) > 3000
    for addr, name in ((DME1_BUILDER, "dme1_builder"), (SCHEDULER_TASK, "scheduler_task"),
                       (dme.AXIS_SEARCH_8, "axis_search_8"), (dme.INTERP_8, "interp_8"),
                       (dme.ROMTEST_ACCUMULATE, "romtest_accumulate"), (dme.FLASH_CRC_RETURN - 0x22C, "flash_crc32_walker")):
        f = fm.at(addr)
        assert f is not None and f.start == addr, (hex(addr), f)
        assert f.name == name
    builder = fm.at(DME1_BUILDER)
    assert builder.start < dme.TACH_STORE_ADDR < builder.end          # the hooked sth is inside it
    assert builder.callers == [dme.FRAME_TASK_BUILDER_CALL]
    assert fm.label(dme.TACH_STORE_ADDR) == "dme1_builder+0x19C"
    assert len(fm.at(dme.INTERP_8).callers) > 100                     # the lookup library's call sites
    assert fm.at(dme.INTERP_8).end == dme.LOOKUP_ENTRIES[dme.LOOKUP_ENTRIES.index(dme.INTERP_8) + 1]
    assert fm.by_name("segment_task").start == 0x3223C
    assert fm.at(fm.tasks[12]).name == "segment_task"                 # the task table, read from the image
    assert fm.by_name("task10").start == 0xFFFC9068                   # an unnamed task is still named a task
    assert "task" in fm.at(SCHEDULER_TASK).sources
    assert all(f.size > 0 for f in fm.functions)
    assert fm.at(0x6E550) is None                                      # free MPC space, no code in the stock pair
    assert fm.variable(dme.KL15_FLAG) == "kl15"
    assert "dme1_builder 0x4B528 f" in fm.ghidra_symbols().splitlines()
    assert "dme1_builder 0x4B528 f" in fm.ghidra_symbols(0xFFE00000).splitlines()
    assert "romtest_accumulate 0xFFE77688 f" in fm.ghidra_symbols(0xFFE00000).splitlines()
    j = fm.to_json()
    assert j["program"] == "0044570LO02S" and any(f["name"] == "dme1_builder" for f in j["functions"])


def test_coverage_and_xref_names(stock):
    b = Board(stock.pair)
    b.boot(max_insns=b.ips // 2)
    fm = FunctionMap(stock.pair)
    fm.cover(b, b.ips // 20)                                           # 50 ms: five 10 ms frames
    builder, scheduler = fm.at(DME1_BUILDER), fm.at(SCHEDULER_TASK)
    assert 3 <= builder.entries <= 7 and builder.hits >= builder.entries
    assert scheduler.hits > 0
    assert len(fm.executed) > 200
    x = Xref(b, [parse_address("r13-0x4BEC")], fmap=fm)
    b.run(b.ips // 50)
    x.detach()
    text = x.report()
    assert "(r13-0x4bec) N:" in text
    assert "in dme1_builder" in text
    assert "(task" in text or "(scheduler_task" in text or "(fn_" in text
