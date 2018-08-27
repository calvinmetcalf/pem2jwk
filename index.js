const parseASN1 = require('parse-asn1')
const curves = require('./curves')
const Buffer = require('safe-buffer').Buffer
var EC = require('elliptic').ec

function encode(buf) {
  var str = Buffer.from(buf.toArray()).toString('base64');
  while (str[str.length - 1] === '=') {
    str = str.slice(0, -1);
  }
  return str.replace(/\+/g, '-').replace(/\//g, '_');
}

module.exports = pem2jwk;

function pem2jwk(pem) {
  const out = parseASN1(pem);
  if (out.type === 'dsa') {
    throw new Error('dsa keys not supported');
  }
  if (out.type === 'rsa' || out.modulus) {
    return handleRSA(out)
  }
  if (out.curve || out.type === 'ec') {
    return handleEC(out);
  }

}
function handleEC(parsedKey) {
  if (parsedKey.curve) {
    // priv
    let curveId = curves[parsedKey.curve.join('.')]
    if (!curveId) throw new Error('unknown curve ' + parsedKey.curve.join('.'))
    let curve = new EC(curveId)
    let key = curve.keyFromPrivate(parsedKey.privateKey)
    const pub = key.getPublic()
    const priv = key.getPrivate();
    return {
      kty: 'EC',
      crv: curveId,
      x: encode(pub.x),
      y: encode(pub.y),
      ext: true,
      d: encode(priv),
      // key_ops: ['sign'],
    };
  } else {
    // pub
    let data = parsedKey.data;
    let curveId = curves[data.algorithm.curve.join('.')];
    let curve = new EC(curveId)
    let pubkey = data.subjectPrivateKey.data
    let key = curve.keyFromPrivate(pubkey)
    const pub = key.getPublic()
    return {
      kty: 'EC',
      crv: curveId,
      x: encode(pub.x),
      y: encode(pub.y),
      ext: true,
      // key_ops: ['verify'],
    }
  }
}

function handleRSA(parsedKey) {
  if (parsedKey.version) {
    return {
      kty: 'RSA',
      n: encode(parsedKey.modulus),
      e: encode(parsedKey.publicExponent),
      d: encode(parsedKey.privateExponent),
      p: encode(parsedKey.prime1),
      q: encode(parsedKey.prime2),
      dp: encode(parsedKey.exponent1),
      dq: encode(parsedKey.exponent2),
      qi: encode(parsedKey.coefficient),
      // key_ops: ['sign', 'decrypt'],
      ext: true
    };
  } else {
    return {
      kty: 'RSA',
      n: encode(parsedKey.modulus),
      e: encode(parsedKey.publicExponent),
      // key_ops: ['verify', 'encrypt'],
      ext: true
    };

  }
}
