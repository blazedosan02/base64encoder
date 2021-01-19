package mainpackage;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import javax.crypto.spec.IvParameterSpec;

public class aesTest2 {

    public byte[] encrypt(String text, SecretKey key, byte [] iv) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encrypted = cipher.doFinal(text.getBytes());

        return encrypted;

    }

}
