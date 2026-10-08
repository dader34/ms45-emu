Put a matching MPC + external flash pair here, or point the MS45_* variables
at them (see ms45emu/image.py):

    stock_Flash.bin    stock_MPC.bin      an unpatched 0044570LO02S pair
    patched_Flash.bin  patched_MPC.bin    the same pair with the map switch built in
    shifter_Flash.bin  shifter_MPC.bin    the map switch with the gear lever as its trigger
    three_Flash.bin    three_MPC.bin      the map switch with three maps, DSC x4 (bench_map2.bin / bench_map3.bin are maps 2 and 3)
    seven_Flash.bin    seven_MPC.bin      the map switch with all seven maps, DSC x4 (bench_map2.bin .. bench_map7.bin)

    stock_boot.bin                        the boot loader of an external flash read (its first 256 KB) with
                                          the programming log emptied, for starting one of BMW's .0PA files
                                          without a read: python -m ms45emu.daten keep-boot READ_Flash.bin

The map switch pairs are built from the stock pair by the app's builder:

    node tools/build_pairs.js images/stock_Flash.bin images/stock_MPC.bin images/

Nothing in this directory is committed.
