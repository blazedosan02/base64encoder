package mainpackage;

import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Encryption {

    public byte[] encrypt(String text, SecretKey key, IvParameterSpec ivparameterspec) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        cipher.init(Cipher.ENCRYPT_MODE, key, ivparameterspec);

        byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));

        return encrypted;

    }

    public String decrypt(String encodedMessage, SecretKey key, IvParameterSpec ivparameterspec) throws Exception, BadPaddingException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        cipher.init(Cipher.DECRYPT_MODE, key, ivparameterspec);

        byte[] decryptedMessage = cipher.doFinal(Base64.getDecoder().decode(encodedMessage));

        return new String(decryptedMessage);

    }

}
