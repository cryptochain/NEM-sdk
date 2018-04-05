const CryptoJS = require('crypto-js');
const SHA3 = require('sha3');

const count = 6000;

console.log(new Date().getTime().toString());
console.time('sha3^n NATIVE generation time');
for (let i = 0; i < count; ++i) {
  const hash = new SHA3.SHA3Hash(256);
  hash.update(new Date().getTime().toString());
}
console.timeEnd('sha3^n NATIVE generation time');

console.time('sha3^n JS generation time');
for (let i = 0; i < count; ++i) {
  const hash = CryptoJS.SHA3(new Date().getTime().toString(), {
    outputLength: 256
  });
}
console.timeEnd('sha3^n JS generation time');
