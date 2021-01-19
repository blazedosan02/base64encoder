package mainpackage;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import javax.crypto.spec.IvParameterSpec;

public class aesTest2 {

    public byte[] encrypt(String text, SecretKey key, String stringiv) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(stringiv.getBytes("UTF-8"));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encrypted = cipher.doFinal(text.getBytes());

        return encrypted;

    }

}
