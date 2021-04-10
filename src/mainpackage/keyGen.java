package mainpackage;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.JOptionPane;

/**
 *
 * @author Mark
 */
public class keyGen {

    protected String generateKey() {

        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException ex) {
            JOptionPane.showMessageDialog(null, "Error Generating Key");
        }
        SecureRandom random = new SecureRandom(); // cryptograph. secure random 
        keyGen.init(random);
        SecretKey secretKey = keyGen.generateKey();

        return new String(Base64.getEncoder().encode(secretKey.getEncoded()));

    }

    public String generateIV() throws NoSuchAlgorithmException, NoSuchPaddingException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);

        IvParameterSpec ivParams = new IvParameterSpec(iv);

        //ENCODE IN BASE 64
        byte[] encodedIVBytes = Base64.getEncoder().encode(ivParams.getIV());

        String encodedIVArray = new String(encodedIVBytes);

        return encodedIVArray;
    }

}
