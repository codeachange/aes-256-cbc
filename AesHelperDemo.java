import java.util.Base64;

class AesHelperDemo {
    public static void main(String[] args) throws Exception {
        AesHelper aesHelper = new AesHelper("my_secret");
        String str = "hello aes";
        byte[] encrypted = aesHelper.encrypt(str.getBytes("UTF-8"));
        System.out.println(Base64.getEncoder().encodeToString(encrypted));
        byte[] decrypted = aesHelper.decrypt(encrypted);
        System.out.println(new String(decrypted));
    }
}
