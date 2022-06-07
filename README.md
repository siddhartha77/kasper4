# Kasper4 - StuffIt 4 Password Recovery
Author: Greg Esposito

Designed to be used with [MaskProcessor](https://github.com/hashcat/maskprocessor) to crack hashes found in the MKey resource of StuffIt 4 archives.

Usage: Kasper4.exe MKEY_HASH

## Test Hashes

```
0659c2e6ee79454a  thea
864eed03a9b4e824  florence
4ddabd585e0cfd55  12345678
f615d8ac23be32fe  abcdefghijkl
191dee4a13759f73  12345678901234567
```

## Utilities
- kasper4-test.bat: Run Kasper4 against test hashes
- DistributedKasper4.vbs: Distribute a keyspace to multiple instances of Kasper4
