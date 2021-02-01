package mainpackage;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Encryption {

    public byte[] encrypt(String text, SecretKey key, String stringiv) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(stringiv.getBytes());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));

        return encrypted;

    }

    public String decrypt(String encodedMessage, SecretKey key, String stringiv) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(stringiv.getBytes("UTF-8"));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] decryptedMessage = cipher.doFinal(Base64.getDecoder().decode(encodedMessage));

        return new String(decryptedMessage);

    }

}
