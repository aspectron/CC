var coinkey 		  = require('coinkey');
var coininfo		  = require('coininfo');
var coinstring		= require('coinstring');
var ecdsa         = require('ecdsa');
var binstring 		= require('btc-transaction/node_modules/binstring');
var Script 			  = require('btc-transaction/node_modules/btc-script');
var Address			  = require('btc-transaction/node_modules/btc-address');
var cryptoHash 		= require('btc-transaction/node_modules/btc-script/node_modules/crypto-hashing');
var Opcode 			  = require('btc-transaction/node_modules/btc-opcode');
var TransactionIn	= require('btc-transaction/lib/transaction-in');
var TransactionOut= require('btc-transaction/lib/transaction-out');
var bufferutils 	= require('./bufferutils');
var bs58			    = require('bs58');
var BigInteger 		= require('bigi');
var SIGHASH_ALL 	= 1;
var sha256 			= cryptoHash.sha256;

module.exports 		= require('btc-transaction');
var Transaction 	= module.exports.Transaction;


var addressTypes = {
  pubkeyhash: {
    mainnet:{
    	0: true,
    	48: true
    },
    testnet:{
    	111: true
    }
  },
  scripthash: {
    mainnet:{
    	5: true
    },
    testnet:{
    	196: true
    }
  }
};

var versionBytes = {
  mainnet: {
    0: 'pubkeyhash',
    5: 'scripthash',
    48: 'pubkeyhash'
  },
  testnet: {
    111: 'pubkeyhash',
    196: 'scripthash'
  }
};

Address.validateType = function(version, addressType, network) {
  return (addressTypes[addressType][network || Address.defaultNetwork][version])
}

Address.prototype.getType = function(network) {
  return versionBytes[network || Address.defaultNetwork][this.version]
}

Address.prototype.decodeString = function(string, network) {
  var bytes = toBytes( bs58.decode(string) );

  var hash = bytes.slice(0, 21);

  //var checksum = sha256(sha256(hash, {asBytes: true}), {asBytes: true});
  var checksum = sha256.x2(hash, { in : 'bytes',  out: 'bytes' });

  if (checksum[0] != bytes[21] ||
    checksum[1] != bytes[22] ||
    checksum[2] != bytes[23] ||
    checksum[3] != bytes[24]) {
    throw new Error('Address Checksum validation failed: ' + string);
  }

  var version = hash.shift();
  var addressType = versionBytes[network || Address.defaultNetwork][version]
  if (!Address.validateType(version, addressType, network)) {
    throw new Error('Address version (' + version + ') not supported: ' + string +
      ' for ' + addressType);
  }

  this.hash = hash;
  this.version = version;
};

Script.prototype.getSignatureList = function(){
	var list = [], chunks = this.chunks;
	if (chunks[0]==0 && chunks[chunks.length-1][chunks[chunks.length-1].length-1] == Opcode.map.OP_CHECKMULTISIG){
		for(var i=1;i<chunks.length-1;i++){				
			list.push(chunks[i]);
		}
	}
	return list;
}

Script.prototype.getMinSigRequired = function(){
  var m = this.chunks[0];
  return m - (Opcode.map.OP_1 - 1)
}

Script.prototype.toAddress = function(network) {
  var outType = this.getOutType();
  if (outType == 'pubkeyhash') {
    return new Address(this.chunks[2], 'pubkeyhash', network || Script.defaultNetwork)
  } else if (outType == 'pubkey') {
    // convert pubkey into a pubkeyhash and do address
    return new Address(cryptoHash.sha256ripe160(this.chunks[0], {
        out: 'bytes'
      }),
      'pubkeyhash', network || Script.defaultNetwork)
  } else if (outType == 'scripthash') {
    return new Address(this.chunks[1], 'scripthash', network || Script.defaultNetwork)
  } else if (outType == 'multisig'){
    return createMultiSig(this.getMinSigRequired(), this.scriptListPubkey());
  } else {
    return false
  }
}

Script.prototype.isSigningComplete = function(){
  var minSigRequired = this.getMinSigRequired();
  var signatures  = this.getSignatureList();

  return minSigRequired <= signatures.length;
}

Script.prototype.scriptListPubkey = function(){
	var r = [];
	for(var i=1; i < this.chunks.length-2; i++){
		r.push(this.chunks[i]);
	}
	return r;
}

Script.prototype.writeBytes = function(e) {
	e.length < Opcode.map.OP_PUSHDATA1 ? this.buffer.push(e.length) : 
	e.length <= 255 ? (this.buffer.push(Opcode.map.OP_PUSHDATA1), this.buffer.push(e.length)) : 
	e.length <= 65535 ? (this.buffer.push(Opcode.map.OP_PUSHDATA2), this.buffer.push(e.length & 255), this.buffer.push(e.length >>> 8 & 255)) : 
	(this.buffer.push(Opcode.map.OP_PUSHDATA4), this.buffer.push(e.length & 255), this.buffer.push(e.length >>> 8 & 255), this.buffer.push(e.length >>> 16 & 255), this.buffer.push(e.length >>> 24 & 255)), this.buffer = this.buffer.concat(e), this.chunks.push(e)
}

Script.createMultiSigInputScript = function(signatures, script) {
  script = new Script(script);
  var m = script.chunks[0]
  k = m - (Opcode.map.OP_1 - 1)
  if (k > signatures.length){
    console.log('Not enough sigs')
  }
  var inScript = new Script();
  inScript.writeOp(Opcode.map.OP_0);
  signatures.map(function(sig) {
    inScript.writeBytes(sig)
  });
  inScript.writeBytes(script.buffer);
  return inScript;
}

Transaction.prototype.getRedeemScript = function(inputIndex){
  if (!this.ins[inputIndex] || !this.ins[inputIndex].script) {
    return false;
  };
  var chunks        = this.ins[inputIndex].script.chunks;
  var redeemScript  = (chunks[chunks.length-1] == Opcode.map.OP_CHECKMULTISIG ) ? this.ins[inputIndex].script : new CC.script(chunks[chunks.length-1]);
  return redeemScript;
}

Transaction.prototype.getInputSignatures = function(inputIndex){
  if (!this.ins[inputIndex] || !this.ins[inputIndex].script) {
    return [];
  };

  return this.ins[inputIndex].script.getSignatureList();
}

Transaction.prototype.isSigningComplete = function(inputIndex){
  inputIndex = inputIndex || 0;
  var redeemScript = this.getRedeemScript(inputIndex);
  if (!redeemScript) {
    return false;
  };

  return redeemScript.isSigningComplete();
}

Transaction.prototype.p2shsign = function(index, script, key, type) {
	key 				= (key instanceof coinkey) ? key: coinkey.fromWif(key);
	type 				= type || SIGHASH_ALL;
	var hash 			= Buffer( this.hashTransactionForSignature(script, index, type) ),
	signature 			= ecdsa.sign(hash, key.privateKey);
	var buffer 			= Buffer( ecdsa.serializeSig(signature).concat([type]) );
	var sig 			= binstring(buffer, {out:'bytes'});
	//console.log('sig', sig+'')
	return sig;
}

Transaction.prototype.signMultiSig = function(inputIndex, redeemScript, key, type){
	type = type || SIGHASH_ALL;
	var signatures = this.ins[inputIndex].script.getSignatureList();
	signatures.push(this.p2shsign(inputIndex, redeemScript, key, type));

	console.log('beforeOrdering:signatures', signatures.map(function(s){return s.join(':')}))

	//getting signatures in correct order
	signatures = this.getOrderedSig(signatures, inputIndex, redeemScript, type);

	console.log('afterOrdering:signatures', signatures.map(function(s){return s.join(':')}))

	this.ins[inputIndex].script = Script.createMultiSigInputScript(signatures, redeemScript);
}

Transaction.prototype.getOrderedSig = function(signatures, inputIndex, redeemScript, type){
	var pkeys 			= redeemScript.extractPubkeys(), key2SigMap={};
	var hash 			= Buffer( this.hashTransactionForSignature(redeemScript, inputIndex, type) );
	pkeys 				= pkeys.sort()
	//console.log('pkeys\n', pkeys, 'signatures:\n', signatures.join("\n")+'')
	for(var i=0; i<pkeys.length; i++){
		key2SigMap[ toHex(pkeys[i]) ] = 1;
	}
	for(var i=0; i < signatures.length; i++){
		var sigCopy 		= signatures[i];
		type 				= sigCopy.pop();//extract "type" info
		
		//console.log('sigCopy1', sigCopy, 'signatures.length', signatures.length, 'i:', i)
		for(var k = 0; k < 2; k++){
			var publicKey = recoverPublicKey( toBuffer(hash), toBuffer(sigCopy), k );

			//console.log('publicKey', publicKey)
			if (key2SigMap[publicKey]) {
				sigCopy.push(type);
				key2SigMap[publicKey] = sigCopy;
				//console.log('sigCopy2', sigCopy)
				break;
			};
		}
	}
	//console.log('key2SigMap', key2SigMap)
	var orderedSignatures = [];
	for(var i=0; i<pkeys.length; i++){
		var sig = key2SigMap[ toHex(pkeys[i]) ];
		if (sig && sig !=1) {
			orderedSignatures.push(sig);
		};
	}

	//console.log('orderedSignatures', orderedSignatures.join("\n")+'');
	return orderedSignatures;
}


Transaction.prototype.toBuffer = function () {
  var txInSize = this.ins.reduce(function(a, x) {
    return a + (40 + bufferutils.varIntSize(x.script.buffer.length) + x.script.buffer.length)
  }, 0)

  var txOutSize = this.outs.reduce(function(a, x) {
    return a + (8 + bufferutils.varIntSize(x.script.buffer.length) + x.script.buffer.length)
  }, 0)

  var buffer = new Buffer(
    8 +
    bufferutils.varIntSize(this.ins.length) +
    bufferutils.varIntSize(this.outs.length) +
    txInSize +
    txOutSize
  )

  var offset = 0
  function writeSlice(slice) {
    if (!slice.copy) {
      console.log('slice.copy', slice)
    };
    slice.copy(buffer, offset)
    offset += slice.length
  }
  function writeUInt32(i) {
    buffer.writeUInt32LE(i, offset)
    offset += 4
  }
  function writeUInt64(i) {
    bufferutils.writeUInt64LE(buffer, i, offset)
    offset += 8
  }
  function writeVarInt(i) {
    var n = bufferutils.writeVarInt(buffer, i, offset)
    offset += n
  }

  writeUInt32(this.version)
  writeVarInt(this.ins.length)

  this.ins.forEach(function(txin) {
    writeSlice(binstring(binstring(txin.outpoint.hash, { in : 'hex',
      out: 'bytes'
    }).reverse(), {in:'bytes', out:'buffer'}))
    writeUInt32(txin.outpoint.index)
    writeVarInt(txin.script.buffer.length)
    writeSlice(new Buffer(txin.script.buffer))
    writeUInt32(txin.sequence)
  })

  writeVarInt(this.outs.length)
  this.outs.forEach(function(txout) {
    //console.log('txout', txout, BigInteger.fromByteArrayUnsigned(txout.value.reverse()).intValue())
    writeUInt64(BigInteger.fromByteArrayUnsigned(txout.value.reverse()).intValue())
    writeVarInt(txout.script.buffer.length)
    writeSlice(new Buffer(txout.script.buffer))
  })

  writeUInt32(this.lock_time)

  return buffer
}

Transaction.prototype.toHex = function() {
  return this.toBuffer().toString('hex')
}

Transaction.fromBuffer = function(buffer) {
  var offset = 0
  function readSlice(n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }
  function readUInt32() {
    var i = buffer.readUInt32LE(offset)
    offset += 4
    return i
  }
  function readUInt64() {
    var i = bufferutils.readUInt64LE(buffer, offset)
    offset += 8
    return i
  }
  function readVarInt() {
    var vi = bufferutils.readVarInt(buffer, offset)
    offset += vi.size
    return vi.number
  }

  var tx = new Transaction()
  tx.version = readUInt32()

  var vinLen = readVarInt()
  for (var i = 0; i < vinLen; ++i) {
    var hash = readSlice(32)
    var vout = readUInt32()
    var scriptLen = readVarInt()
    var script = readSlice(scriptLen)
    var script = toBytes( script );
    var sequence = readUInt32()
    //console.log('script', script)
    tx.ins.push(new TransactionIn({
      outpoint:{
        hash: toHex( toBytes( hash ).reverse() ),
        index: vout
      },
      script: new Script(script),
      sequence: sequence
    }))
  }

  var voutLen = readVarInt()
  for (i = 0; i < voutLen; ++i) {
    var value = readUInt64()
    var scriptLen = readVarInt()
    var script = toBytes( readSlice(scriptLen) );
    //console.log('value', value)

    if ("number" == typeof value) {
      value = BigInteger(value.toString(), 10);
    }

    if ("string" == typeof value) {
      value = BigInteger(value, 10);
    }

    if (value instanceof BigInteger) {
      value = value.toByteArrayUnsigned().reverse();
      while (value.length < 8) value.push(0);
    } else if (Array.isArray(value)) {
      // Nothing to do
    }

    tx.outs.push(new TransactionOut({
      value: value,
      script: new Script(script)
    }))
  }

  tx.lock_time = readUInt32()
  //assert.equal(offset, buffer.length, 'Transaction has unexpected data')

  return tx
}

Transaction.fromHex = function(hex) {
  return Transaction.fromBuffer(new Buffer(hex, 'hex'))
}

//Utility functions
//helper function for 0.0006*scale floating number calculation issue 
String.prototype.left_trim = function(s) {
	return this.replace(new RegExp('^'+s+'+'),"");
}

String.prototype.right_pad = function(field){
	var w = this.length;
	var l = field.length;
	var pad = w < l ? l-w : 0;
	return this + (field.substr(0, pad));
}

function multiply(x, y){
	var exp = 0;
	function int(x){
		var xs = x.toString();
		if (xs.indexOf('.') > -1) {
			x = parseFloat(xs);
			var xr = xs.split('.')[1];
			var ex = xr.left_trim('0').length;
			var xp = Math.pow(10, ex);
			x = xs.replace('.', '').left_trim('0').right_pad(xp.toString().replace('1', ''))
			//console.log('ex', ex, xp, x2, x * xp,  x.toString().replace('.', '').left_trim('0'))
			exp += xr.length;
		};
		return x;
	}

	var x1 = int(x), y1 = int(y);
	var result = (x1*y1)/Math.pow(10, exp);

	//console.log(x1, y1, exp, result, x*y)
	return result;
}

function createMultiSig(count, pubKeys){
	var rs  = Script.createMultiSigOutputScript(count, pubKeys);

	var x 	= cryptoHash.ripemd160(cryptoHash.sha256(rs.buffer, {out: 'bytes'}), {out: 'bytes'});
	x.unshift(0x05);
	var r = x;
	r 					= sha256.x2(r, {out: 'bytes'});
	var checksum 		= r.slice(0,4);
	var redeemScript 	= toHex(rs.buffer);
	var address 		= bs58.encode(x.concat(checksum));

	return {
		address:address,
		redeemScript: redeemScript
	};
}

function toBuffer(v){
	return binstring(v, {out:'buffer'});
}

function toHex(v){
	return binstring(v, {out:'hex'});
}

function toBytes(v){
	return binstring(v, {out:'bytes'});
}

function recoverPublicKey(hash, signature, i){
	var e = BigInteger.fromBuffer(hash)
	var parsed = ecdsa.parseSig(signature)
	var Qprime = ecdsa.recoverPubKey(e, parsed, i);
	return Qprime.getEncoded().toString('hex');
}


module.exports.coinkey 		= coinkey;
module.exports.coininfo		= coininfo;
module.exports.ecdsa 		  = ecdsa;
module.exports.script 		= Script;
module.exports.binstring  = binstring;

module.exports.multiply 		    = multiply;
module.exports.toBuffer 		    = toBuffer;
module.exports.toHex 			      = toHex;
module.exports.toBytes 			    = toBytes;
module.exports.createMultiSig 	= createMultiSig;
module.exports.recoverPublicKey = recoverPublicKey;
