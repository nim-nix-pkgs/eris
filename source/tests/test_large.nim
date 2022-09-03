import eris, eris/private/chacha20/src/chacha20, eris/private/blake2/blake2
import std/[asyncdispatch, monotimes, streams, strutils, times, unittest]

const tests = [
    ("100MiB (block size 1KiB)", 100'i64 shl 20, bs1k,
        "urn:erisx3:BICSAEKJ54ICM7NNNTCWFQJORW7Y5ANVA4IY3CR63LQYX5R4EP4YJK4FSSWCHHVVYKFUSZBGDCGGB3JZXJRQ5BKH7NKCIDGMJCXUFKUYWU"),
    ("1GiB (block size 32KiB)", 1'i64 shl 30, bs32k,
        "urn:erisx3:B4BKQZDUWTWZQ4CQR4LQ6TQI5Q4JTNP53IRBHCFTV6V55OVUYFBFYL3QY5OARBXZYZSFYKIZEQZLPEXFL6BHF2VHS2RFHDOMSIFE4BJOO4"),
    ("256GiB (block size 32KiB)", 256'i64 shl 30, bs32k,
        "urn:erisx3:B4BZJGA6LLGJNJRAMHB3AECXEVV7WOUUJW4H727MPJVFJZNOL3DCZMNYOGAFLKBXYUPJZXB6GLX26L4HHUHQ3GAPF2B2ZUDIXCLNXAFZJM"),
    ]

template measureThroughput(label: string; bytes: int64; body: untyped): untyped =
  let start = getMonoTime()
  body
  let
    stop = getMonoTime()
    period = stop - start
    bytesPerSec = t[1].int64 div period.inSeconds
  echo label, " - ", formatSize(bytesPerSec), "/s"

when not defined(largetests):
  echo "`largetests` is not defined"

suite "stream":

  type
    TestStream = ref TestStreamObj
    TestStreamObj = object of StreamObj
      key: array[32, byte]
      nonce: Nonce
      counter: Counter
      pos: uint64
      len: uint64

  proc testAtEnd(s: Stream): bool =
    var test = TestStream(s)
    test.len <= test.pos

  proc testReadData(s: Stream; buffer: pointer; bufLen: int): int =
    assert(bufLen mod chacha20.BlockSize == 0)
    var test = TestStream(s)
    zeroMem(buffer, bufLen)
    test.counter = chacha20(test.key, test.nonce, test.counter, buffer, buffer, bufLen)
    test.pos.inc(bufLen)
    bufLen

  proc newTestStream(name: string; contentSize: uint64): TestStream =
    new(result)
    var ctx: Blake2b
    ctx.init(32)
    ctx.update(name)
    ctx.final(result.key)
    result.len = contentSize
    result.atEndImpl = testAtEnd
    result.readDataImpl = testReadData

  var
    secret: Secret
    store = newDiscardStore()
  for i, t in tests:
    test $i:
      when not defined(largetests): skip()
      else:
        checkpoint t[0]
        measureThroughput(t[0], t[1]):
          var
            str = newTestStream(t[0], t[1].uint64)
            cap = waitFor store.encode(t[2], str, secret)
          check($cap == t[3])

suite "ingest":
  for i, t in tests:
    test $i:
      when not defined(largetests): skip()
      else:
        checkpoint t[0]
        var
          store = newDiscardStore()
          ingest = newErisIngest(store, t[2])
          key: array[32, byte]
          nonce: Nonce
          counter: Counter
          buffer = newSeq[byte](t[2].int)
          zeros = newSeq[byte](buffer.len)
        block:
          var ctx: Blake2b
          ctx.init(32)
          ctx.update(t[0])
          ctx.final(key)
        measureThroughput(t[0], t[1]):
          while ingest.position.int64 < t[1]:
            counter = chacha20(key, nonce, counter, zeros, buffer)
            waitFor ingest.append(buffer)
          check(ingest.position.int64 == t[1])
          let
            a = waitFor ingest.cap
            b = parseErisUrn t[3]
          check(a.level == b.level)
          check(a.blockSize == b.blockSize)
          check(a == b)
