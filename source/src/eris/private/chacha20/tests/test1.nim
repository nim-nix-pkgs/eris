import unittest

include chacha20

test "quarterRound":
  block:
    var a, b, c, d: uint32
    a = 0x11111111'u32
    b = 0x01020304'u32
    c = 0x9b8d6f43'u32
    d = 0x01234567'u32
    quarterRound(a, b, c, d)
    check(a == 0xea2a92f4'u32)
    check(b == 0xcb1cf8ce'u32)
    check(c == 0x4581472e'u32)
    check(d == 0x5881c4bb'u32)

  block:
    var
      a = [
        0x879531e0'u32, 0xc5ecf37d'u32, 0x516461b1'u32, 0xc9a62f8a'u32,
        0x44c20ef3'u32, 0x3390af7f'u32, 0xd9fc690b'u32, 0x2a5f714c'u32,
        0x53372767'u32, 0xb00a5631'u32, 0x974c541a'u32, 0x359e9963'u32,
        0x5c971061'u32, 0x3d631689'u32, 0x2098d9d6'u32, 0x91dbd320'u32]
      b = [
        0x879531e0'u32, 0xc5ecf37d'u32, 0xbdb886dc'u32, 0xc9a62f8a'u32,
        0x44c20ef3'u32, 0x3390af7f'u32, 0xd9fc690b'u32, 0xcfacafd2'u32,
        0xe46bea80'u32, 0xb00a5631'u32, 0x974c541a'u32, 0x359e9963'u32,
        0x5c971061'u32, 0xccc07c79'u32, 0x2098d9d6'u32, 0x91dbd320'u32]

    quarterRound(a, 2, 7, 8, 13)
    check(a == b)

test "block":
  var
    key: array[32, byte]
    nonce: array[12, byte]
    counter = 1'u32
  for i in 0..31:
    key[i] = i.uint8
  nonce[3] = 0x09'u8
  nonce[7] = 0x4a'u8

  var a: State

  let initial = init(key, counter, nonce)
  a = initial

  let b = [
      0x61707865'u32, 0x3320646e'u32, 0x79622d32'u32, 0x6b206574'u32,
      0x03020100'u32, 0x07060504'u32, 0x0b0a0908'u32, 0x0f0e0d0c'u32,
      0x13121110'u32, 0x17161514'u32, 0x1b1a1918'u32, 0x1f1e1d1c'u32,
      0x00000001'u32, 0x09000000'u32, 0x4a000000'u32, 0x00000000'u32]
  check(a == b)

  for _ in 1..10:
    innerBlock(a)
  let c = [
    0x837778ab'u32, 0xe238d763'u32, 0xa67ae21e'u32, 0x5950bb2f'u32,
    0xc4f2d0c7'u32, 0xfc62bb2f'u32, 0x8fa018fc'u32, 0x3f5ec7b7'u32,
    0x335271c2'u32, 0xf29489f3'u32, 0xeabda8fc'u32, 0x82e46ebd'u32,
    0xd19c12b4'u32, 0xb04e16de'u32, 0x9e83d0cb'u32, 0x4e3c50a2'u32]
  check(a == c)

  for i in 0..15:
    a[i] = a[i] + initial[i]

  let d = [
    0xe4e7f110'u32, 0x15593bd1'u32, 0x1fdd0f50'u32, 0xc47120a3'u32,
    0xc7f4d1c7'u32, 0x0368c033'u32, 0x9aaa2204'u32, 0x4e6cd4c3'u32,
    0x466482d2'u32, 0x09aa9f07'u32, 0x05d7c214'u32, 0xa2028bd9'u32,
    0xd19c12b5'u32, 0xb94e16de'u32, 0xe883d0cb'u32, 0x4e3c50a2'u32]
  check(a == d)

proc toHex(buf: string): string =
  const alphabet = "0123456789abcdef"
  result = newString(buf.len shl 1)
  for i, b in buf:
    result[(i shl 1) + 0] = alphabet[b.uint8 shr 4]
    result[(i shl 1) + 1] = alphabet[b.uint8 and 0xf]

proc toHex(buf: seq[byte]): string =
  const alphabet = "0123456789abcdef"
  result = newString(buf.len shl 1)
  for i, b in buf:
    result[(i shl 1) + 0] = alphabet[b shr 4]
    result[(i shl 1) + 1] = alphabet[b and 0xf]

suite "The ChaCha20 Block Functions":

  test "1":
    var
      key: Key
      nonce: Nonce
      counter = 0'u32
      data = newSeq[byte](64)
    discard chacha20(key, nonce, counter, data, data)
    let
      a = data.toHex
      b = "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
    check(a == b)

  test "2":
    var
      key: Key
      nonce: Nonce
      counter = 1'u32
      data = newSeq[byte](64)
    discard chacha20(key, nonce, counter, data, data)
    let
      a = data.toHex
      b = "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"
    check(a == b)

  test "3":
    var
      key: Key
      nonce: Nonce
      counter = 1'u32
      data = newSeq[byte](64)
    key[31] = 1
    discard chacha20(key, nonce, counter, data, data)
    let
      a = data.toHex
      b = "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0"
    check(a == b)

  test "4":
    var
      key: Key
      nonce: Nonce
      counter = 2'u32
      data = newSeq[byte](64)
    key[1] = 0xff
    discard chacha20(key, nonce, counter, data, data)
    let
      a = data.toHex
      b = "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096"
    check(a == b)

  test "5":
    var
      key: Key
      nonce: Nonce
      counter = 0'u32
      data = newSeq[byte](64)
    nonce[11] = 2
    discard chacha20(key, nonce, counter, data, data)
    let
      a = data.toHex
      b = "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d"
    check(a == b)

suite "ChaCha20 Encryption":

  test "1":
    var
      key: Key
      nonce: Nonce
      plain = newString(64)
    let
      test = chacha20(plain, key, nonce)
      a = test.toHex
      b = "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
    check(a == b)

  test "2":
    var
      key: Key
      nonce: Nonce
    key[31] = 1
    nonce[11] = 2
    let counter = 1'u32
    let plain = """Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to"""
    let
      test = chacha20(plain, key, nonce, counter)
      a = test.toHex
      b = "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221"
    check(a == b)

  test "3":
    var
      key = [0x1c'u8, 0x92'u8, 0x40'u8, 0xa5'u8, 0xeb'u8, 0x55'u8, 0xd3'u8,
          0x8a'u8, 0xf3'u8, 0x33'u8, 0x88'u8, 0x86'u8, 0x04'u8, 0xf6'u8,
          0xb5'u8, 0xf0, 0x47'u8, 0x39'u8, 0x17'u8, 0xc1'u8, 0x40'u8, 0x2b'u8,
          0x80'u8, 0x09'u8, 0x9d'u8, 0xca'u8, 0x5c'u8, 0xbc'u8, 0x20'u8,
          0x70'u8, 0x75'u8, 0xc0'u8]
      nonce: Nonce
    nonce[11] = 2
    let counter = 42'u32
    let plain = """'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe:
All mimsy were the borogoves,
And the mome raths outgrabe."""
    let
      test = chacha20(plain, key, nonce, counter)
      a = test.toHex
      b = "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"
    check(a == b)

