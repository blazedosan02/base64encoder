package mainpackage;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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

}
