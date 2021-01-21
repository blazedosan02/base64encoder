/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mainpackage;

import java.awt.CardLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

/**
 *
 * @author Mark
 */
public class startframe extends javax.swing.JFrame {

    String menuSelect = "BASE64";

    private static final int IV_LENGTH_BYTE = 12;
    private static final int AES_KEY_BIT = 128;

    /**
     * Creates new form startframe
     */
    public startframe() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jMenuItem1 = new javax.swing.JMenuItem();
        encodeButton = new javax.swing.JButton();
        decodeButton = new javax.swing.JButton();
        cleanButton = new javax.swing.JButton();
        mainLayeredPane = new javax.swing.JLayeredPane();
        base64Panel = new javax.swing.JPanel();
        firstLabel = new javax.swing.JLabel();
        base64FieldInput = new javax.swing.JTextField();
        base64FieldOutput = new javax.swing.JTextField();
        secondLabel = new javax.swing.JLabel();
        copyInputTextButton = new javax.swing.JButton();
        copyOutputTextButton = new javax.swing.JButton();
        aesPanel = new javax.swing.JPanel();
        firstLabelAes = new javax.swing.JLabel();
        secondLabelAes = new javax.swing.JLabel();
        keyLabel = new javax.swing.JLabel();
        aesFieldInput = new javax.swing.JTextField();
        aesKeyField = new javax.swing.JTextField();
        aesFieldOutPut = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        aesIVField = new javax.swing.JTextField();
        mainMenuBar = new javax.swing.JMenuBar();
        fileMenu = new javax.swing.JMenu();
        aboutMenu = new javax.swing.JMenuItem();
        optionsMenu = new javax.swing.JMenu();
        encodeMenu = new javax.swing.JMenuItem();
        decodeMenu = new javax.swing.JMenuItem();
        methodMenu = new javax.swing.JMenu();
        base64Menu = new javax.swing.JMenuItem();
        aesMenu = new javax.swing.JMenuItem();
        jMenu1 = new javax.swing.JMenu();
        aesKeyGenMenu = new javax.swing.JMenuItem();

        jMenuItem1.setText("jMenuItem1");

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Base 64 Encoder/Decoder");
        setResizable(false);

        encodeButton.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
        encodeButton.setText("Encode");
        encodeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encodeButtonActionPerformed(evt);
            }
        });

        decodeButton.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
        decodeButton.setText("Decode");
        decodeButton.setEnabled(false);
        decodeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decodeButtonActionPerformed(evt);
            }
        });

        cleanButton.setFont(new java.awt.Font("Arial", 0, 14)); // NOI18N
        cleanButton.setText("Clean");
        cleanButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cleanButtonActionPerformed(evt);
            }
        });

        mainLayeredPane.setLayout(new java.awt.CardLayout());

        base64Panel.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        base64Panel.setOpaque(false);

        firstLabel.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        firstLabel.setText("Text To Encode");

        base64FieldInput.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N

        base64FieldOutput.setEditable(false);
        base64FieldOutput.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N

        secondLabel.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        secondLabel.setText("Encoded Text ");

        copyInputTextButton.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        copyInputTextButton.setText("Copy");
        copyInputTextButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                copyInputTextButtonActionPerformed(evt);
            }
        });

        copyOutputTextButton.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        copyOutputTextButton.setText("Copy");
        copyOutputTextButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                copyOutputTextButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout base64PanelLayout = new javax.swing.GroupLayout(base64Panel);
        base64Panel.setLayout(base64PanelLayout);
        base64PanelLayout.setHorizontalGroup(
            base64PanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(base64PanelLayout.createSequentialGroup()
                .addGap(37, 37, 37)
                .addGroup(base64PanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(secondLabel)
                    .addComponent(firstLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(base64PanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(base64FieldInput)
                    .addComponent(base64FieldOutput, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(base64PanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(copyInputTextButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(copyOutputTextButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        base64PanelLayout.setVerticalGroup(
            base64PanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(base64PanelLayout.createSequentialGroup()
                .addGap(21, 21, 21)
                .addGroup(base64PanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(firstLabel)
                    .addComponent(base64FieldInput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(copyInputTextButton))
                .addGap(29, 29, 29)
                .addGroup(base64PanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(secondLabel)
                    .addComponent(base64FieldOutput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(copyOutputTextButton))
                .addContainerGap(48, Short.MAX_VALUE))
        );

        mainLayeredPane.add(base64Panel, "base64Card");

        firstLabelAes.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        firstLabelAes.setText("Text To Encode");

        secondLabelAes.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        secondLabelAes.setText("Encoded Text ");

        keyLabel.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        keyLabel.setText("Key");

        aesFieldInput.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N

        aesKeyField.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N

        aesFieldOutPut.setEditable(false);

        jLabel1.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        jLabel1.setText("IV");

        aesIVField.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N

        javax.swing.GroupLayout aesPanelLayout = new javax.swing.GroupLayout(aesPanel);
        aesPanel.setLayout(aesPanelLayout);
        aesPanelLayout.setHorizontalGroup(
            aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(aesPanelLayout.createSequentialGroup()
                .addGap(32, 32, 32)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(aesPanelLayout.createSequentialGroup()
                        .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(keyLabel)
                            .addComponent(secondLabelAes)
                            .addComponent(firstLabelAes))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(aesFieldInput, javax.swing.GroupLayout.DEFAULT_SIZE, 245, Short.MAX_VALUE)
                            .addComponent(aesKeyField)
                            .addComponent(aesFieldOutPut, javax.swing.GroupLayout.Alignment.TRAILING)))
                    .addGroup(aesPanelLayout.createSequentialGroup()
                        .addGap(64, 64, 64)
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 21, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(aesIVField)))
                .addContainerGap(33, Short.MAX_VALUE))
        );
        aesPanelLayout.setVerticalGroup(
            aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, aesPanelLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(firstLabelAes)
                    .addComponent(aesFieldInput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(keyLabel)
                    .addComponent(aesKeyField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(aesIVField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(9, 9, 9)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(secondLabelAes)
                    .addComponent(aesFieldOutPut, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(27, 27, 27))
        );

        mainLayeredPane.add(aesPanel, "aesCard");

        fileMenu.setText("File");

        aboutMenu.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        aboutMenu.setText("About");
        aboutMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                aboutMenuActionPerformed(evt);
            }
        });
        fileMenu.add(aboutMenu);

        mainMenuBar.add(fileMenu);

        optionsMenu.setText("Options");

        encodeMenu.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        encodeMenu.setText("Encode");
        encodeMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encodeMenuActionPerformed(evt);
            }
        });
        optionsMenu.add(encodeMenu);

        decodeMenu.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        decodeMenu.setText("Decode");
        decodeMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decodeMenuActionPerformed(evt);
            }
        });
        optionsMenu.add(decodeMenu);

        mainMenuBar.add(optionsMenu);

        methodMenu.setText("Method");

        base64Menu.setText("Base64");
        base64Menu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                base64MenuActionPerformed(evt);
            }
        });
        methodMenu.add(base64Menu);

        aesMenu.setText("Aes");
        aesMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                aesMenuActionPerformed(evt);
            }
        });
        methodMenu.add(aesMenu);

        mainMenuBar.add(methodMenu);

        jMenu1.setText("Tools ");

        aesKeyGenMenu.setText("AesKeyGen");
        aesKeyGenMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                aesKeyGenMenuActionPerformed(evt);
            }
        });
        jMenu1.add(aesKeyGenMenu);

        mainMenuBar.add(jMenu1);

        setJMenuBar(mainMenuBar);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(mainLayeredPane, javax.swing.GroupLayout.PREFERRED_SIZE, 405, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(50, 50, 50)
                .addComponent(encodeButton)
                .addGap(49, 49, 49)
                .addComponent(decodeButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(cleanButton)
                .addGap(37, 37, 37))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(mainLayeredPane, javax.swing.GroupLayout.PREFERRED_SIZE, 144, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(6, 6, 6)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(encodeButton)
                    .addComponent(decodeButton)
                    .addComponent(cleanButton))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void encodeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encodeButtonActionPerformed
        // TODO add your handling code here:

        if (base64FieldInput.getText().equals("")) {

            JOptionPane.showMessageDialog(null, "Input must not be empty");

        } else {

            switch (menuSelect) {

                case "BASE64":

                    encodeBase64();

                    break;

                case "AES": {
                    try {
                        encodeAES();
                    } catch (Exception ex) {
                        Logger.getLogger(startframe.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                break;

            }

        }


    }//GEN-LAST:event_encodeButtonActionPerformed

    private void aboutMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_aboutMenuActionPerformed
        // TODO add your handling code here:

        JOptionPane.showMessageDialog(null, "Marco Lecona 2021");

    }//GEN-LAST:event_aboutMenuActionPerformed

    private void decodeMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decodeMenuActionPerformed
        // TODO add your handling code here:

        switch (menuSelect) {

            case "BASE64":
                base64FieldInput.setText("");

                base64FieldOutput.setText("");

                firstLabel.setText("Text To Decode");

                secondLabel.setText("Decoded Text");
                break;

            case "AES":

                aesFieldInput.setText("");

                //  aesKeyField.setEditable(false);
                aesFieldOutPut.setText("");

                firstLabelAes.setText("Text To Decode");

                secondLabelAes.setText("Decoded Text");

                break;

        }

        encodeButton.setEnabled(false);

        decodeButton.setEnabled(true);


    }//GEN-LAST:event_decodeMenuActionPerformed

    private void decodeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decodeButtonActionPerformed
        // TODO add your handling code here:

        switch (menuSelect) {

            case "BASE64":
                decodeBase64();
                break;

            case "AES": {
                try {
                    decodeAES();
                } catch (Exception ex) {
                    Logger.getLogger(startframe.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            break;

        }

    }//GEN-LAST:event_decodeButtonActionPerformed

    private void encodeMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encodeMenuActionPerformed
        // TODO add your handling code here:

        switch (menuSelect) {

            case "BASE64":
                base64FieldInput.setText("");

                base64FieldOutput.setText("");

                firstLabel.setText("Text To Encode");

                secondLabel.setText("Encoded Text");
                break;

            case "AES":
                aesFieldInput.setText("");
                aesFieldOutPut.setText("");
        }

        encodeButton.setEnabled(true);

        decodeButton.setEnabled(false);

    }//GEN-LAST:event_encodeMenuActionPerformed

    private void cleanButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cleanButtonActionPerformed
        // TODO add your handling code here:

        switch (menuSelect) {

            case "BASE64":
                base64FieldInput.setText("");
                base64FieldOutput.setText("");
                break;

            case "AES":
                aesFieldInput.setText("");
                aesKeyField.setText("");
                aesIVField.setText("");
                aesFieldOutPut.setText("");
                break;
        }


    }//GEN-LAST:event_cleanButtonActionPerformed

    private void aesMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_aesMenuActionPerformed

        menuSelect = "AES";

        CardLayout card = (CardLayout) mainLayeredPane.getLayout();
        card.show(mainLayeredPane, "aesCard");

    }//GEN-LAST:event_aesMenuActionPerformed

    private void base64MenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_base64MenuActionPerformed

        menuSelect = "BASE64";

        CardLayout card = (CardLayout) mainLayeredPane.getLayout();
        card.show(mainLayeredPane, "base64Card");
    }//GEN-LAST:event_base64MenuActionPerformed

    private void aesKeyGenMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_aesKeyGenMenuActionPerformed
        // TODO add your handling code here:

        aesKeyGen aessKeyGen = new aesKeyGen();

        aessKeyGen.setVisible(true);


    }//GEN-LAST:event_aesKeyGenMenuActionPerformed

    private void copyInputTextButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_copyInputTextButtonActionPerformed
        // TODO add your handling code here:

        copySelection(base64FieldInput);

    }//GEN-LAST:event_copyInputTextButtonActionPerformed

    private void copyOutputTextButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_copyOutputTextButtonActionPerformed
        // TODO add your handling code here:
        
        copySelection(base64FieldOutput);
    }//GEN-LAST:event_copyOutputTextButtonActionPerformed

    public void encodeBase64() {

        String textToEncode = base64FieldInput.getText();

        byte[] encodedBytes = Base64.getEncoder().encode(textToEncode.getBytes());

        String encodedByteArray = new String(encodedBytes);

        base64FieldOutput.setText(encodedByteArray);

    }

    public void decodeBase64() {

        String textToEncode = base64FieldInput.getText();

        byte[] decodedBytes = Base64.getDecoder().decode(textToEncode);

        String decodedByteArray = new String(decodedBytes);

        base64FieldOutput.setText(decodedByteArray);
    }

    public void encodeAES() throws NoSuchAlgorithmException, Exception {

        aesTest2 aesTest2 = new aesTest2();

        String textToEncode = aesFieldInput.getText();

        String textKey = aesKeyField.getText();

        String textIV = aesIVField.getText();

        if (aesKeyField.getText().equals("") || aesIVField.getText().equals("") || aesFieldInput.getText().equals("")) {

            JOptionPane.showMessageDialog(null, "Text To Encode / KeyField/ IV Field must not be empty");
        } else if (textIV.length() < 16 || textIV.length() > 16) {

            JOptionPane.showMessageDialog(null, "The IV Lengh Must Be 16 Bytes");

            aesIVField.setText("");

        } else {

            //Decoding Base 64 Key to Secretkey
            byte[] decodedAesBytes = Base64.getDecoder().decode(textKey);

            SecretKey originalKey = new SecretKeySpec(decodedAesBytes, 0, decodedAesBytes.length, "AES");

            String base64Encrypted = Base64.getEncoder().encodeToString(aesTest2.encrypt(textToEncode, originalKey, textIV));

            aesFieldOutPut.setText(base64Encrypted);

        }

    }

    public void decodeAES() throws NoSuchAlgorithmException, Exception {

        aesTest2 aesTest2 = new aesTest2();

        String textToDecode = aesFieldInput.getText();

        String textKey = aesKeyField.getText();

        String textIV = aesIVField.getText();

        //Decoding Base 64 Key to Secretkey
        byte[] decodedAesBytes = Base64.getDecoder().decode(textKey);

        SecretKey originalKey = new SecretKeySpec(Arrays.copyOf(decodedAesBytes, 16), "AES");

        aesFieldOutPut.setText(aesTest2.decrypt(textToDecode, originalKey, textIV));

    }

    public void copySelection(JTextField fieldname) {

        if (fieldname.getText().equals("")) {

            JOptionPane.showMessageDialog(null, "Field to copy is empty");

        } else {

            StringSelection stringSelection = new StringSelection(fieldname.getText());
            Clipboard clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard();
            clpbrd.setContents(stringSelection, null);

        }

    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) throws NoSuchAlgorithmException, Exception {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(startframe.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(startframe.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(startframe.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(startframe.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new startframe().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenuItem aboutMenu;
    private javax.swing.JTextField aesFieldInput;
    private javax.swing.JTextField aesFieldOutPut;
    private javax.swing.JTextField aesIVField;
    private javax.swing.JTextField aesKeyField;
    private javax.swing.JMenuItem aesKeyGenMenu;
    private javax.swing.JMenuItem aesMenu;
    private javax.swing.JPanel aesPanel;
    private javax.swing.JTextField base64FieldInput;
    private javax.swing.JTextField base64FieldOutput;
    private javax.swing.JMenuItem base64Menu;
    private javax.swing.JPanel base64Panel;
    private javax.swing.JButton cleanButton;
    private javax.swing.JButton copyInputTextButton;
    private javax.swing.JButton copyOutputTextButton;
    private javax.swing.JButton decodeButton;
    private javax.swing.JMenuItem decodeMenu;
    private javax.swing.JButton encodeButton;
    private javax.swing.JMenuItem encodeMenu;
    private javax.swing.JMenu fileMenu;
    private javax.swing.JLabel firstLabel;
    private javax.swing.JLabel firstLabelAes;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JLabel keyLabel;
    private javax.swing.JLayeredPane mainLayeredPane;
    private javax.swing.JMenuBar mainMenuBar;
    private javax.swing.JMenu methodMenu;
    private javax.swing.JMenu optionsMenu;
    private javax.swing.JLabel secondLabel;
    private javax.swing.JLabel secondLabelAes;
    // End of variables declaration//GEN-END:variables
}
