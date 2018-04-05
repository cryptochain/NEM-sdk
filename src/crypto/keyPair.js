import nacl from '../external/nacl-fast';
import convert from '../utils/convert';
import Helpers from '../utils/helpers';
import SHA3 from 'sha3'; // in fact this is Keccak

const { byteToHexString, hexStringToByte } = Helpers;

/***
* Create a BinaryKey object
*
* @param {Uint8Array} keyData - A key data
*/
let BinaryKey = function(keyData) {
    this.data = keyData;
    this.toString = function() {
        return convert.ua2hex(this.data);
    }
}

let hashfunc = function(dest, data, dataLength) {
    let hash = new SHA3.SHA3Hash(512);
    hash.update(data);
    return convert.hex2ua(hash.digest('hex'));
}

/***
* Create an hasher class
*/
class Hasher {
    constructor() {
        this.sha3 = new SHA3.SHA3Hash(512);
    }

    reset() {
        this.sha3 = new SHA3.SHA3Hash(512);
    }

    update(data) {
        if (data instanceof BinaryKey) {
            this.sha3.update(data.data);
        } else if (data instanceof Uint8Array) {
            this.sha3.update(data);
        } else if (typeof data === "string") {
            let converted = convert.hex2ua(data);
            this.sha3.update(converted);
        } else {
            throw new Error("unhandled argument");
        }
    }

    finalize() {
        let hash = this.sha3.digest('hex');
        return convert.hex2ua(hash);
    }
}

/***
* Create a KeyPair Object
*
* @param {string} privkey - An hex private key
*/
let KeyPair = function(privkey) {
    this.publicKey = new BinaryKey(new Uint8Array(nacl.lowlevel.crypto_sign_PUBLICKEYBYTES));
    this.secretKey = convert.hex2ua_reversed(privkey);
    nacl.lowlevel.crypto_sign_keypair_hash(this.publicKey.data, this.secretKey, hashfunc);

    // Signature
    this.sign = (data) => {
        let sig = new Uint8Array(64);
        let hasher = new Hasher();
        let r = nacl.lowlevel.crypto_sign_hash(sig, this, data, hasher);
        if (!r) {
            alert("Couldn't sign the tx, generated invalid signature");
            throw new Error("Couldn't sign the tx, generated invalid signature");
        }
        return new BinaryKey(sig);
    }
}

/**
* Create a NEM KeyPair
*
* @param {string} hexdata - An hex private key
*
* @return {object} - The NEM KeyPair object
*/
let create = function(hexdata) {
    // Errors
    if(!hexdata) throw new Error('Missing argument !');
    if (!Helpers.isPrivateKeyValid(hexdata)) throw new Error('Private key is not valid !');
    // Processing
    let r = new KeyPair(hexdata);
    // Result
    return r;
}

/**
 * Verify a signature.
 *
 * @param {string} publicKey - The public key to use for verification.
 * @param {string} data - The data to verify.
 * @param {string} signature - The signature to verify.
 *
 * @return {boolean}  - True if the signature is valid, false otherwise.
 */
let verifySignature = function(publicKey, data, signature) {
    // Errors
    if(!publicKey || !data || !signature) throw new Error('Missing argument !');
    if (!Helpers.isPublicKeyValid(publicKey)) throw new Error('Public key is not valid !');

    if (!Helpers.isHexadecimal(signature)) {
        //console.error('Signature must be hexadecimal only !');
        return false;
    }
    if (signature.length !== 128) {
        //console.error('Signature length is incorrect !')
        return false;
    }

    // Create an hasher object
    let hasher = new Hasher();
    // Convert public key to Uint8Array
    let _pk = convert.hex2ua(publicKey);
    // Convert signature to Uint8Array
    let _signature = convert.hex2ua(signature);

    const c = nacl;
    const p = [c.gf(), c.gf(), c.gf(), c.gf()];
    const q = [c.gf(), c.gf(), c.gf(), c.gf()];

    if (c.unpackneg(q, _pk)) return false;

    let h = new Uint8Array(64);
    hasher.reset();
    hasher.update(_signature.subarray(0, 64/2));
    hasher.update(_pk);
    hasher.update(data);
    h = hasher.finalize();

    c.reduce(h);
    c.scalarmult(p, q, h);

    const t = new Uint8Array(64);
    c.scalarbase(q, _signature.subarray(64/2));
    c.add(p, q);
    c.pack(t, p);

    return 0 === nacl.lowlevel.crypto_verify_32(_signature, 0, t, 0);
}

module.exports = {
    create,
    verifySignature
}
