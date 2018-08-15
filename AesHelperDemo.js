const AesHelper = require('./AesHelper.js');

const aesHelper = new AesHelper('my_secret');
const s = 'hello aes';
const es = aesHelper.encrypt(s);
console.log(es);
const ds = aesHelper.decrypt(es);
console.log(ds);
console.log(ds === s);
