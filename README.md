# mzchecksum

DOS EXE checksum tool

## Usage

```
Usage: mzchecksum [options] file

Major modes (mutually exclusive):
  -g, --get              Display and verify the DOS EXE checksum (default)
  -s, --set VALUE        Set checksum to four hex digits or to 'auto'

Checksum scope (mutually exclusive):
  -l, --logical          Exclude bytes beyond the MZ logical size (default)
  -p, --physical         Include all physical file bytes

Verification target:
  -t, --target HEX       Required checksum sum; exactly four hex digits
                         with optional 0x/0X prefix (default FFFF)

Other:
  -h, --help             Show this help

Examples:
  mzchecksum program.exe
  mzchecksum --physical --target FFFF program.exe
  mzchecksum --set auto program.exe
  mzchecksum --set 1234 --target FFFF program.exe
```

## Examples

```
$ mzchecksum test.exe
Signature: MZ
Logical size: 34448 bytes
Physical size: 34448 bytes
Overlay size: 0 bytes
Checksum field: 0x0000
Checksum scope: logical (34448 bytes)
Target sum: 0xFFFF
Computed sum: 0xCFF1
Verification: MISMATCH
```

```
$ mzchecksum --set auto test.exe
Signature: MZ
Logical size: 34448 bytes
Physical size: 34448 bytes
Overlay size: 0 bytes
Checksum field: 0x0000 -> 0x300E (auto)
Checksum scope: logical (34448 bytes)
Target sum: 0xFFFF
Computed sum: 0xFFFF
Verification: OK
```
