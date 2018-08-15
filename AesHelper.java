import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class AesHelper {
    private SecretKeySpec aesKeySpec;
    private IvParameterSpec ivParameterSpec;

    public AesHelper(String secret) throws Exception {
        byte[] keyBytes = secret.getBytes("UTF-8");
        byte[][] bytes = EVP_BytesToKey(32, 16, null, keyBytes, 1);
        this.aesKeySpec = new SecretKeySpec(bytes[0], "AES");
        this.ivParameterSpec = new IvParameterSpec(bytes[1]);
    }

    public byte[] encrypt(byte[] text) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.aesKeySpec, this.ivParameterSpec);
        return cipher.doFinal(text);
    }

    public byte[] decrypt(byte[] encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.aesKeySpec, this.ivParameterSpec);
        return cipher.doFinal(encryptedText);
    }

    /**
     * Java version of OpenSSL EVP_BytesToKey. Derives key and IV from
     * password and salt.
     *
     * https://www.openssl.org/docs/crypto/EVP_BytesToKey.html
     *
     * Source: https://olabini.com/blog/tag/evp_bytestokey/
     *
     * @param key_len
     * @param iv_len
     * @param salt
     * @param data
     * @param count
     *
     * @return derived Key and IV
     */
    private static byte[][] EVP_BytesToKey(int key_len, int iv_len, byte[] salt,
                                           byte[] data, int count) throws Exception {

        final MessageDigest md = MessageDigest.getInstance("md5");

        byte[][] both = new byte[2][];
        byte[] key = new byte[key_len];
        int key_ix = 0;
        byte[] iv = new byte[iv_len];
        int iv_ix = 0;
        both[0] = key;
        both[1] = iv;
        byte[] md_buf = null;
        int nkey = key_len;
        int niv = iv_len;
        int i = 0;
        if (data == null) {
            return both;
        }
        int addmd = 0;
        for (;;) {
            md.reset();
            if (addmd++ > 0) {
                md.update(md_buf);
            }
            md.update(data);
            if (null != salt) {
                md.update(salt, 0, 8);
            }
            md_buf = md.digest();
            for (i = 1; i < count; i++) {
                md.reset();
                md.update(md_buf);
                md_buf = md.digest();
            }
            i = 0;
            if (nkey > 0) {
                for (;;) {
                    if (nkey == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    key[key_ix++] = md_buf[i];
                    nkey--;
                    i++;
                }
            }
            if (niv > 0 && i != md_buf.length) {
                for (;;) {
                    if (niv == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    iv[iv_ix++] = md_buf[i];
                    niv--;
                    i++;
                }
            }
            if (nkey == 0 && niv == 0) {
                break;
            }
        }
        for (i = 0; i < md_buf.length; i++) {
            md_buf[i] = 0;
        }
        return both;
    }
}
