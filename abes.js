'use strict';

const crypto = require('crypto');
const BitBuf = require('bitbuf');
const bitBufHash = require('bitbufhash');

var Abes = function(key, blockLenBits, options) {
	this.options = {
		hashName: ((options &&
					(typeof(options) === 'object') &&
					options.hasOwnProperty('hashName') &&
					options.hashName) ?
				   options.hashName :
				   'sha512'),
		rounds: ((options &&
				  (typeof(options) === 'object') &&
				  options.hasOwnProperty('rounds') &&
				  options.rounds) ?
				 options.rounds :
				 5)
	};
    function keySchedule(key, rounds, leftLenBits, rightLenBits, hashName) {
		var i, a = [], nb = Buffer.allocUnsafe(6);
		for (i = 0; i < rounds; i++) {
			nb.writeUIntBE(i * 2, 0, 6);
			a.push(bitBufHash(nb, key, Math.min(Math.max(rightLenBits, 64), 1024), hashName).trim());
			nb.writeUIntBE(i * 2 + 1, 0, 6);
			a.push(bitBufHash(nb, key, Math.min(Math.max(leftLenBits, 64), 1024), hashName).trim());
		}
		return a;
    }
    if (! (Number.isSafeInteger(blockLenBits) && (blockLenBits >= 0))) {
		throw new Error('Invalid block length');
    }
    if (! (Number.isSafeInteger(this.options.rounds) && (this.options.rounds >= 2))) {
		throw new Error('Invalid number of rounds');
    }
    if (! ((typeof(key) === 'string') || Buffer.isBuffer(key) || BitBuf.isBitBuf(key))) {
		throw new Error('Invalid key');
    }
	if (! ((typeof(this.options.hashName) === 'string') &&
		   (crypto.getHashes().indexOf(this.options.hashName) >= 0))) {
		throw new Error('Invalid hash');
	}
	this.blockLenBits = blockLenBits;
	switch (this.blockLenBits) {
	case 0:
		break;
	case 1:
		this.magic = bitBufHash(BitBuf.from('000000000000000000000000000000000000000000000001'),
								key,
								1,
								this.options.hashName).get(0);
		break;
	default:
		this.leftLenBits = Math.trunc(this.blockLenBits / 2);
		this.rightLenBits = this.blockLenBits - this.leftLenBits;
		this.subkey = keySchedule(key,
								  this.options.rounds,
								  this.leftLenBits,
								  this.rightLenBits,
								  this.options.hashName);
	}
};

Abes.prototype.encrypt = function(data) {
    var i, lb, rb;
    if (! BitBuf.isBitBuf(data)) {
		data = BitBuf.from(data, this.blockLenBits);
    }
    if (data.length != this.blockLenBits) {
		throw new Error('Invalid input size');
    }
	switch (this.blockLenBits) {
	case 0:
		return new BitBuf(0);
	case 1:
		return BitBuf.from((data.get(0) ^ this.magic) ? "1" : "0");
	default:
		lb = data.slice(0, this.leftLenBits);
		rb = data.slice(this.leftLenBits, this.blockLenBits);
		for (i = 0; i < this.options.rounds; i++) {
			lb = lb.xor(bitBufHash(rb, this.subkey[2 * i], this.leftLenBits, this.options.hashName));
			rb = rb.xor(bitBufHash(lb, this.subkey[(2 * i) + 1], this.rightLenBits, this.options.hashName));
		}
		return BitBuf.concat([lb, rb]);
	}
	//NOTREACHED
};

Abes.prototype.decrypt = function(data) {
    var i, lb, rb;
    if (! BitBuf.isBitBuf(data)) {
		data = BitBuf.from(data, this.blockLenBits);
    }
    if (data.length != this.blockLenBits) {
		throw new Error('Invalid input size');
    }
	switch (this.blockLenBits) {
	case 0:
		return new BitBuf(0);
	case 1:
		return BitBuf.from((data.get(0) ^ this.magic) ? "1" : "0");
	default:
		lb = data.slice(0, this.leftLenBits);
		rb = data.slice(this.leftLenBits, this.blockLenBits);
		for (i = this.options.rounds; i > 0; i--) {
			rb = rb.xor(bitBufHash(lb, this.subkey[(2 * i) - 1], this.rightLenBits, this.options.hashName));
			lb = lb.xor(bitBufHash(rb, this.subkey[(2 * i) - 2], this.leftLenBits, this.options.hashName));
		}
		return BitBuf.concat([lb, rb]);
	}
	//NOTREACHED
};

module.exports = Abes;
