# ⯰ ERIS

See the [spec](https://eris.codeberg.page/spec/) for more information.

The latest version of this library should be available at
https://codeberg.org/eris/nim-eris

## Test

```
git clone --recursive https://git.sr.ht/~ehmry/eris
cd eris

nim c -d:release -r tests/test_small
nim c -d:release -r tests/test_large
```

## Todo
* Optimise the Chacha20 and BLAKE2 primatives
* Split unpure modules (TKRZW) to separate libraries
