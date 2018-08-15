const crypto = require('crypto');

module.exports = class AesHelper {
    constructor(secret) {
        this.secret = secret;
        this.cipher = crypto.createCipher("aes-256-cbc", this.secret);
        this.decipher = crypto.createDecipher("aes-256-cbc", this.secret);
    }

    encrypt(string_data) {
        const buffer = Buffer.from(string_data, 'utf8');
        return this.crypt(this.cipher, buffer).toString('base64');
    }

    decrypt(base64_data) {
        const buffer = Buffer.from(base64_data, 'base64');
        return this.crypt(this.decipher, buffer).toString('utf8');
    }

    crypt(cipher, buffer_data) {
        const text = cipher.update(buffer_data, 'utf8');
        const pad = cipher.final();
        return Buffer.concat([ text, pad ]);
    }
};
