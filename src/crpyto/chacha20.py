#!/usr/bin/env python
# Reference: ChaCha20 and Poly1305 for IETF Protocols
# https://datatracker.ietf.org/doc/html/rfc8439
# %% imports
from array import array
from dataclasses import dataclass, field

# %% ChaCha Basic Ops
def add(a, b):
    return (a + b) & 0xFFFFFFFF

def xor(a, b):
    return a ^ b

def left_roll(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

def test_ops():
    """
    For example, let's see the add, XOR, and roll operations from the
    fourth line with sample numbers:

        a = 0x11111111
        b = 0x01020304
        c = 0x77777777
        d = 0x01234567
        c = c + d = 0x77777777 + 0x01234567 = 0x789abcde
        b = b ^ c = 0x01020304 ^ 0x789abcde = 0x7998bfda
        b = b <<< 7 = 0x7998bfda <<< 7 = 0xcc5fed3c
    """
    a = 0x11111111
    b = 0x01020304
    c = 0x77777777
    d = 0x01234567
    c = add(c, d)
    assert c == 0x789abcde
    b = xor(b, c)
    assert b == 0x7998bfda
    b = left_roll(b, 7)
    assert b == 0xcc5fed3c

test_ops()

# %% ChaCha Quarter Round
def chacha_quarter_round(a: int, b: int, c: int, d: int) -> tuple:
    """
    The basic operation of the ChaCha algorithm is the quarter round.  It
    operates on four 32-bit unsigned integers, denoted a, b, c, and d.
    The operation is as follows (in C-like notation):

        a += b; d ^= a; d <<<= 16;
        c += d; b ^= c; b <<<= 12;
        a += b; d ^= a; d <<<= 8;
        c += d; b ^= c; b <<<= 7;

    Where "+" denotes integer addition modulo 2^32, "^" denotes a bitwise
    Exclusive OR (XOR), and "<<< n" denotes an n-bit left roll (towards
    the high bits).
    """
    a = add(a, b); d = xor(d, a); d = left_roll(d, 16)
    c = add(c, d); b = xor(b, c); b = left_roll(b, 12)
    a = add(a, b); d = xor(d, a); d = left_roll(d, 8)
    c = add(c, d); b = xor(b, c); b = left_roll(b, 7)
    return a, b, c, d

def test_quarter():
    """
    For a test vector, we will use the same numbers as in the example,
    adding something random for c.

        a = 0x11111111
        b = 0x01020304
        c = 0x9b8d6f43
        d = 0x01234567

    After running a Quarter Round on these four numbers, we get these:

        a = 0xea2a92f4
        b = 0xcb1cf8ce
        c = 0x4581472e
        d = 0x5881c4bb
    """
    a = 0x11111111
    b = 0x01020304
    c = 0x9b8d6f43
    d = 0x01234567
    a, b, c, d = chacha_quarter_round(a, b, c, d)
    assert a == 0xea2a92f4
    assert b == 0xcb1cf8ce
    assert c == 0x4581472e
    assert d == 0x5881c4bb

test_quarter()

# %% Quarter Round on State
@dataclass
class ChaChaState:
    state: array = field(default_factory=lambda: array('L', [0] * 16))

    def __getitem__(self, index):
        return self.state[index]
    
    def __setitem__(self, index, value):
        self.state[index] = value

    def quarter_round(self, x, y, z, w):
        """
        The ChaCha state does not have four integer numbers: it has 16.  So
        the quarter-round operation works on only four of them -- hence the
        name.  Each quarter round operates on four predetermined numbers in
        the ChaCha state.  We will denote by QUARTERROUND(x, y, z, w) a
        quarter-round operation on the numbers at indices x, y, z, and w of
        the ChaCha state when viewed as a vector.  For example, if we apply
        QUARTERROUND(1, 5, 9, 13) to a state, this means running the quarter-
        round operation on the elements marked with an asterisk, while
        leaving the others alone:

            0  *a   2   3
            4  *b   6   7
            8  *c  10  11
            12  *d  14  15

        Note that this run of quarter round is part of what is called a
        "column round".
        """
        self[x], self[y], self[z], self[w] = chacha_quarter_round(self[x], self[y], self[z], self[w])


def test_state():
    """
    For a test vector, we will use a ChaCha state that was generated
    randomly:

    Sample ChaCha State

        879531e0  c5ecf37d  516461b1  c9a62f8a
        44c20ef3  3390af7f  d9fc690b  2a5f714c
        53372767  b00a5631  974c541a  359e9963
        5c971061  3d631689  2098d9d6  91dbd320

    We will apply the QUARTERROUND(2, 7, 8, 13) operation to this state.
    For obvious reasons, this one is part of what is called a "diagonal
    round":

    After applying QUARTERROUND(2, 7, 8, 13)

        879531e0  c5ecf37d *bdb886dc  c9a62f8a
        44c20ef3  3390af7f  d9fc690b *cfacafd2
        *e46bea80  b00a5631  974c541a  359e9963
        5c971061 *ccc07c79  2098d9d6  91dbd320

    Note that only the numbers in positions 2, 7, 8, and 13 changed.
    """
    state = ChaChaState(array('L', [
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
    ]))
    state.quarter_round(2, 7, 8, 13)
    expected = array('L', [
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
        0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
    ])
    assert state.state == expected

test_state()