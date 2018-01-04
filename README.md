In a Nutshell
=============

This is a block cipher algorithm that implements arbitrary length
block size that does not have to be byte aligned. The bit pushing is
based on BitBuf package and cipher itself is a Feistel network cipher
that uses a cryptographic hash function as a mixed (except for 1 bit
block size, which uses just one bit from hash and XORs it to the
input).


Reference
=========

Abes(key, blockLenBits, options)
--------------------------------

```
const Abes = require('abes');
const BitBuf = require('bitbuf');
const assert = require('assert');

var x = new Abes('verysecret', 11);
var p1 = BitBuf.from('10110111000');
var c = x.encrypt(p1);
var p2 = x.decrypt(c);
assert.equal(p1.toString(), p2.toString());
```

Just figure it out. Also key can be an arbitrary length BitBuf. Only
one block is encrypted or decrypted at the time.


Author
======

Timo J. Rinne <tri@iki.fi>


License
=======

GPL-2.0
