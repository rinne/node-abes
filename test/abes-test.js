'use strict';

const Abes = require('../abes.js');
const BitBuf = require('bitbuf');
const assert = require('assert');

(function() {
	var x = new Abes('verysecret', 11);
	var p1 = BitBuf.from('10110111000');
	var c = x.encrypt(p1);
	var p2 = x.decrypt(c);
	assert.equal(p1.toString(), p2.toString());
	console.log('ok');
	process.exit(0);
})();
