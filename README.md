# OpenWithIDA
Open application with ida.exe/ida64.exe
Place the compiled executable OpenWithIDA.exe in root installation folder.

Run like so:

```
OpenWithIDA <target-file>
```

### Notes:
If compiling with `icl`, make sure to use `/permissive` (or remove `/permissive-`):
```
icl /GS- /TC /GA /W3 /QxHost /Gy /Zi /O3 /fp:fast=2 /Quse-intel-optimized-headers /D "_CRT_SECURE_NO_WARNINGS" /D "NDEBUG" /D "_CONSOLE" /Qipo /Qopt-matmul /arch:CORE-AVX2 /Oi /nologo /Qparallel /Ob2 /Ot  OpenWith_IDA_Pro.c
```
