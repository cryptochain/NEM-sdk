import KeyPair from './keyPair';
import convert from '../utils/convert';
import Address from '../model/address';
import nacl from '../external/nacl-fast';
import Network from '../model/network';
import Helpers from '../utils/helpers';
import crypto from 'crypto';
import SHA3 from 'sha3'; // in fact this is Keccak

const { byteToHexString, hexStringToByte } = Helpers;

/**
 * Derive a private key from a password using count iterations of SHA3-256
 *
 * @param {string} password - A wallet password
 * @param {number} count - A number of iterations above 0
 *
 * @return {object} - The derived private key
 */
let derivePassSha = function(password, count) {
    // Errors
    if(!password) throw new Error('Missing argument !');
    if(!count || count <= 0) throw new Error('Please provide a count number above 0');
    // Processing
    let data = password;
    if (process.env.NODE_ENV !== 'production') {
        console.time('sha3^n generation time');
    }
    for (let i = 0; i < count; ++i) {
        const hash = new SHA3.SHA3Hash(256);
        hash.update(data);
        data = hexStringToByte(hash.digest('hex'));
    }
    if (process.env.NODE_ENV !== 'production') {
        console.timeEnd('sha3^n generation time');
    }
    // Result
    return {
        'priv': byteToHexString(data)
    };
};

/**
 * Reveal the private key of an account or derive it from the wallet password
 *
 * @param {object} common- An object containing password and privateKey field
 * @param {object} walletAccount - A wallet account object
 * @param {string} algo - A wallet algorithm
 *
 * @return {object|boolean} - The account private key in and object or false
 */
let passwordToPrivatekey = function(common, walletAccount, algo) {
    // Errors
    if(!common || !walletAccount || !algo) throw new Error('Missing argument !');

    let r = undefined;

    if (algo === "trezor") { // HW wallet
        r = { 'priv': '' };
        common.isHW = true;
    } else if (!common.password) {
        throw new Error('Missing argument !');
    }

    // Processing
    if (algo === "pass:6k") { // Brain wallets
        if (!walletAccount.encrypted && !walletAccount.iv) {
            // Account private key is generated simply using a passphrase so it has no encrypted and iv
            r = derivePassSha(common.password, 6000);
        } else if (!walletAccount.encrypted || !walletAccount.iv) {
            // Else if one is missing there is a problem
            //console.log("Account might be compromised, missing encrypted or iv");
            return false;
        } else {
            // Else child accounts have encrypted and iv so we decrypt
            let pass = derivePassSha(common.password, 20);
            let obj = {
                ciphertext: hexStringToByte(walletAccount.encrypted),
                iv: convert.hex2ua(walletAccount.iv),
                key: convert.hex2ua(pass.priv)
            };
            let d = decrypt(obj);
            r = { 'priv': d };
        }
    } else if (algo === "pass:bip32") { // Wallets from PRNG
        let pass = derivePassSha(common.password, 20);
        let obj = {
            ciphertext: hexStringToByte(walletAccount.encrypted),
            iv: convert.hex2ua(walletAccount.iv),
            key: convert.hex2ua(pass.priv)
        };
        let d = decrypt(obj);
        r = { 'priv': d };
    } else if (algo === "pass:enc") { // Private Key wallets
        let pass = derivePassSha(common.password, 20);
        let obj = {
            ciphertext: hexStringToByte(walletAccount.encrypted),
            iv: convert.hex2ua(walletAccount.iv),
            key: convert.hex2ua(pass.priv)
        };
        let d = decrypt(obj);
        r = { 'priv': d };
    } else if (!r) {
        //console.log("Unknown wallet encryption method");
        return false;
    }
    // Result
    common.privateKey = r.priv;
    return true;
}

/**
 * Check if a private key correspond to an account address
 *
 * @param {string} priv - An account private key
 * @param {number} network - A network id
 * @param {string} _expectedAddress - The expected NEM address
 *
 * @return {boolean} - True if valid, false otherwise
 */
let checkAddress = function(priv, network, _expectedAddress) {
    // Errors
    if (!priv || !network || !_expectedAddress) throw new Error('Missing argument !');
    if (!Helpers.isPrivateKeyValid(priv)) throw new Error('Private key is not valid !');
    //Processing
    let expectedAddress = _expectedAddress.toUpperCase().replace(/-/g, '');
    let kp = KeyPair.create(priv);
    let address = Address.toAddress(kp.publicKey.toString(), network);
    // Result
    return address === expectedAddress;
};

function hashfunc(dest, data, dataLength) {
    let hash = new SHA3.SHA3Hash(512);
    hash.update(data);
    return convert.hex2ua(hash.digest('hex'));
}

function key_derive(shared, salt, sk, pk) {
    nacl.lowlevel.crypto_shared_key_hash(shared, pk, sk, hashfunc);
    for (let i = 0; i < salt.length; i++) {
        shared[i] ^= salt[i];
    }
    let hash = new SHA3.SHA3Hash(256);
    hash.update(shared);
    return hash.digest('hex');
}

/**
 * Generate a random key
 *
 * @return {Uint8Array} - A random key
 */
let randomKey = function() {
    let rkey = crypto.randomBytes(32)
    return rkey;
};

/**
 * Encrypt hex data using a key
 *
 * @param {string} data - An hex string
 * @param {Uint8Array} key - An Uint8Array key
 *
 * @return {object} - The encrypted data
 */
let encrypt = function(data, key, iv) {
    // Errors
    if (!data || !key) throw new Error('Missing argument !');
    // Processing
    const actualIV = iv || crypto.randomBytes(16);
    let cipherAES = crypto.createCipheriv('aes256', key, actualIV);
    let encrypted = cipherAES.update(data, 'hex', 'hex');
    encrypted += cipherAES.final('hex');
    // Result
    return {
        ciphertext: encrypted,
        iv: actualIV,
        key: key
    };
};

/**
 * Decrypt data
 *
 * @param {object} data - An encrypted data object
 *
 * @return {string} - The decrypted hex string
 */
let decrypt = function(data) {
    // Errors
    if (!data) throw new Error('Missing argument !');
    // Processing
    let decipherAES = crypto.createDecipheriv('aes256', data.key, data.iv);
    let decrypted = decipherAES.update(data.ciphertext, 'hex', 'hex');
    decrypted += decipherAES.final('hex');
    // Result
    return decrypted;
};

/**
 * Encode a private key using a password
 *
 * @param {string} privateKey - An hex private key
 * @param {string} password - A password
 *
 * @return {object} - The encoded data
 */
let encodePrivKey = function(privateKey, password) {
    // Errors
    if (!privateKey || !password) throw new Error('Missing argument !');
    if (!Helpers.isPrivateKeyValid(privateKey)) throw new Error('Private key is not valid !');
    // Processing
    let pass = derivePassSha(password, 20);
    let r = encrypt(privateKey, convert.hex2ua(pass.priv));
    // Result
    return {
        ciphertext: r.ciphertext,
        iv: convert.ua2hex(r.iv),
    };
};

/***
 * Encode a message, separated from encode() to help testing
 *
 * @param {string} senderPriv - A sender private key
 * @param {string} recipientPub - A recipient public key
 * @param {string} msg - A text message
 * @param {Uint8Array} iv - An initialization vector
 * @param {Uint8Array} salt - A salt
 *
 * @return {string} - The encoded message
 */
let _encode = function(senderPriv, recipientPub, msg, iv, salt) {
    // Errors
    if (!senderPriv || !recipientPub || !msg || !iv || !salt) throw new Error('Missing argument !');
    if (!Helpers.isPrivateKeyValid(senderPriv)) throw new Error('Private key is not valid !');
    if (!Helpers.isPublicKeyValid(recipientPub)) throw new Error('Public key is not valid !');
    // Processing
    let sk = convert.hex2ua_reversed(senderPriv);
    let pk = convert.hex2ua(recipientPub);
    let shared = new Uint8Array(32);
    let encKey = key_derive(shared, salt, sk, pk);
    console.log(encKey);

    // let cipherAES = crypto.createCipheriv('aes256', convert.hex2ua(encKey), iv);
    // let encrypted = cipherAES.update(convert.hex2ua(convert.utf8ToHex(msg)), null, 'hex');
    // encrypted += cipherAES.final('hex');
    let encrypted = encrypt(convert.utf8ToHex(msg), convert.hex2ua(encKey), iv).ciphertext;
    // Result
    let result = convert.ua2hex(salt) + convert.ua2hex(iv) + encrypted;
    return result;
};

/**
 * Encode a message
 *
 * @param {string} senderPriv - A sender private key
 * @param {string} recipientPub - A recipient public key
 * @param {string} msg - A text message
 *
 * @return {string} - The encoded message
 */
let encode = function(senderPriv, recipientPub, msg) {
    // Errors
    if (!senderPriv || !recipientPub || !msg) throw new Error('Missing argument !');
    if (!Helpers.isPrivateKeyValid(senderPriv)) throw new Error('Private key is not valid !');
    if (!Helpers.isPublicKeyValid(recipientPub)) throw new Error('Public key is not valid !');
    // Processing
    let iv = nacl.randomBytes(16)
    //console.log("IV:", convert.ua2hex(iv));
    let salt = nacl.randomBytes(32)
    let encoded = _encode(senderPriv, recipientPub, msg, iv, salt);
    // Result
    return encoded;
};

/**
 * Decode an encrypted message payload
 *
 * @param {string} recipientPrivate - A recipient private key
 * @param {string} senderPublic - A sender public key
 * @param {string} _payload - An encrypted message payload
 *
 * @return {string} - The decoded payload as hex
 */
let decode = function(recipientPrivate, senderPublic, _payload) {
    // Errors
    if(!recipientPrivate || !senderPublic || !_payload) throw new Error('Missing argument !');
    if (!Helpers.isPrivateKeyValid(recipientPrivate)) throw new Error('Private key is not valid !');
    if (!Helpers.isPublicKeyValid(senderPublic)) throw new Error('Public key is not valid !');
    // Processing
    let binPayload = convert.hex2ua(_payload);
    let salt = new Uint8Array(binPayload.buffer, 0, 32);
    let iv = new Uint8Array(binPayload.buffer, 32, 16);
    let payload = new Uint8Array(binPayload.buffer, 48);
    let sk = convert.hex2ua_reversed(recipientPrivate);
    let pk = convert.hex2ua(senderPublic);
    let shared = new Uint8Array(32);
    let r = key_derive(shared, salt, sk, pk);
    let encKey = r;
    let encIv = {
        iv: convert.ua2words(iv, 16)
    };
    let encrypted = {
        'ciphertext': convert.ua2words(payload, payload.length)
    };
    let decipherAES = crypto.createDecipheriv('aes', encKey, encIv);
    let decrypted = cipherAES.update(encrypted, 'utf8', 'hex');
    // Result
    let hexplain = byteToHexString(decipherAES.final('utf-8'));
    return hexplain;
};

module.exports = {
    derivePassSha,
    passwordToPrivatekey,
    checkAddress,
    randomKey,
    decrypt,
    encrypt,
    encodePrivKey,
    _encode,
    encode,
    decode
}
