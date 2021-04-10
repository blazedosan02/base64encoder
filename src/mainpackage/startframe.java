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
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

/**
 *
 * @author Mark
 */
public class startframe extends javax.swing.JFrame {
    
    String menuSelect = "AES";
    
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
        aesPanel = new javax.swing.JPanel();
        firstLabelAes = new javax.swing.JLabel();
        secondLabelAes = new javax.swing.JLabel();
        aesFieldInput = new javax.swing.JTextField();
        aesKeyField = new javax.swing.JTextField();
        aesFieldOutPut = new javax.swing.JTextField();
        aesIVField = new javax.swing.JTextField();
        copyEncodedAesTextButton = new javax.swing.JButton();
        copyKeyButton = new javax.swing.JButton();
        newKeyButton = new javax.swing.JButton();
        ivGenButton = new javax.swing.JButton();
        copyIVButton = new javax.swing.JButton();
        base64Panel = new javax.swing.JPanel();
        firstLabel = new javax.swing.JLabel();
        base64FieldInput = new javax.swing.JTextField();
        base64FieldOutput = new javax.swing.JTextField();
        secondLabel = new javax.swing.JLabel();
        copyInputTextButton = new javax.swing.JButton();
        copyOutputTextButton = new javax.swing.JButton();
        mainMenuBar = new javax.swing.JMenuBar();
        fileMenu = new javax.swing.JMenu();
        aboutMenu = new javax.swing.JMenuItem();
        optionsMenu = new javax.swing.JMenu();
        encodeMenu = new javax.swing.JMenuItem();
        decodeMenu = new javax.swing.JMenuItem();
        methodMenu = new javax.swing.JMenu();
        base64Menu = new javax.swing.JMenuItem();
        aesMenu = new javax.swing.JMenuItem();

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

        firstLabelAes.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        firstLabelAes.setText("Text To Encode");

        secondLabelAes.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        secondLabelAes.setText("Encoded Text ");

        aesFieldInput.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N

        aesKeyField.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N

        aesFieldOutPut.setEditable(false);

        aesIVField.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N

        copyEncodedAesTextButton.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        copyEncodedAesTextButton.setText("Copy");
        copyEncodedAesTextButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                copyEncodedAesTextButtonActionPerformed(evt);
            }
        });

        copyKeyButton.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        copyKeyButton.setText("Copy");
        copyKeyButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                copyKeyButtonActionPerformed(evt);
            }
        });

        newKeyButton.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        newKeyButton.setText("Key");
        newKeyButton.setToolTipText("Generates New Key");
        newKeyButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newKeyButtonActionPerformed(evt);
            }
        });

        ivGenButton.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        ivGenButton.setText("IV");
        ivGenButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ivGenButtonActionPerformed(evt);
            }
        });

        copyIVButton.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
        copyIVButton.setText("Copy");
        copyIVButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                copyIVButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout aesPanelLayout = new javax.swing.GroupLayout(aesPanel);
        aesPanel.setLayout(aesPanelLayout);
        aesPanelLayout.setHorizontalGroup(
            aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(aesPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(firstLabelAes)
                    .addComponent(secondLabelAes)
                    .addComponent(newKeyButton)
                    .addComponent(ivGenButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(aesFieldInput, javax.swing.GroupLayout.DEFAULT_SIZE, 245, Short.MAX_VALUE)
                    .addComponent(aesKeyField)
                    .addComponent(aesFieldOutPut, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(aesIVField))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(copyEncodedAesTextButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(copyKeyButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(copyIVButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        aesPanelLayout.setVerticalGroup(
            aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(aesPanelLayout.createSequentialGroup()
                .addContainerGap(13, Short.MAX_VALUE)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(firstLabelAes)
                    .addComponent(aesFieldInput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(aesKeyField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(copyKeyButton)
                    .addComponent(newKeyButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(aesIVField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(ivGenButton)
                    .addComponent(copyIVButton))
                .addGap(5, 5, 5)
                .addGroup(aesPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(secondLabelAes)
                    .addComponent(aesFieldOutPut, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(copyEncodedAesTextButton))
                .addGap(25, 25, 25))
        );

        mainLayeredPane.add(aesPanel, "aesCard");

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
                    .addComponent(copyOutputTextButton, javax.swing.GroupLayout.DEFAULT_SIZE, 78, Short.MAX_VALUE)
                    .addComponent(copyInputTextButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
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
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        mainLayeredPane.add(base64Panel, "base64Card");

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

        setJMenuBar(mainMenuBar);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(mainLayeredPane, javax.swing.GroupLayout.PREFERRED_SIZE, 426, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addComponent(encodeButton)
                .addGap(79, 79, 79)
                .addComponent(decodeButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(cleanButton)
                .addGap(20, 20, 20))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(mainLayeredPane, javax.swing.GroupLayout.PREFERRED_SIZE, 155, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(7, 7, 7)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(decodeButton)
                    .addComponent(encodeButton)
                    .addComponent(cleanButton))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void encodeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encodeButtonActionPerformed
        // TODO add your handling code here:

        try {
            
            switch (menuSelect) {
                
                case "BASE64":
                    
                    if (base64FieldInput.getText().equals("")) {
                        
                        JOptionPane.showMessageDialog(null, "Input must not be empty");
                        
                    } else {
                        
                        encodeBase64();
                    }
                    
                    break;
                
                case "AES": {
                    try {
                        encodeAES();
                    } catch (InvalidAlgorithmParameterException invex) {
                        JOptionPane.showMessageDialog(null, "Empty IV/Incorrect IV Must Be In Base 64 Format");
                    } catch (IllegalArgumentException ille) {
                        JOptionPane.showMessageDialog(null, "Insert a 16 byte length IV");
                    }
                }
                
                break;
                
            }
            
        } catch (Exception e) {
            
            JOptionPane.showMessageDialog(null, "Error While Encoding,Try Again");
            
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
                
                aesFieldOutPut.setText("");
                
                firstLabelAes.setText("Text To Decode");
                
                secondLabelAes.setText("Decoded Text");
                
                break;
            
        }
        
        encodeButton.setEnabled(false);
        
        decodeButton.setEnabled(true);
        

    }//GEN-LAST:event_decodeMenuActionPerformed

    private void decodeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decodeButtonActionPerformed
        switch (menuSelect) {
            
            case "BASE64":
                
                if (base64FieldInput.getText().equals("")) {
                    
                    JOptionPane.showMessageDialog(null, "Field To decode mut not be empty");
                    
                } else {
                    
                    decodeBase64();
                    
                }
                
                break;
            
            case "AES": {
                
                if (aesFieldInput.getText().equals("") || aesKeyField.getText().equals("") || aesIVField.getText().equals("")) {
                    
                    JOptionPane.showMessageDialog(null, "Text To Encode / KeyField/ IV Field must not be empty");
                    
                } else {
                    
                    try {
                        decodeAES();
                    } catch (InvalidAlgorithmParameterException invex) {
                        
                        JOptionPane.showMessageDialog(null, "Empty IV/Incorrect IV Must Be In Base 64 Format");
                    } catch (IllegalArgumentException ille) {
                        JOptionPane.showMessageDialog(null, "Insert a 16 byte length IV");
                    } catch (Exception ex) {
                        Logger.getLogger(startframe.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    
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
                firstLabelAes.setText("Text To Encode");
                secondLabelAes.setText("Encoded Text");
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

    private void copyInputTextButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_copyInputTextButtonActionPerformed
        // TODO add your handling code here:

        copySelection(base64FieldInput);

    }//GEN-LAST:event_copyInputTextButtonActionPerformed

    private void copyOutputTextButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_copyOutputTextButtonActionPerformed
        // TODO add your handling code here:

        copySelection(base64FieldOutput);
    }//GEN-LAST:event_copyOutputTextButtonActionPerformed

    private void copyEncodedAesTextButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_copyEncodedAesTextButtonActionPerformed
        // TODO add your handling code here:

        copySelection(aesFieldOutPut);
    }//GEN-LAST:event_copyEncodedAesTextButtonActionPerformed

    private void newKeyButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newKeyButtonActionPerformed
        // TODO add your handling code here:

        keyGen keyGen = new keyGen();
        
        aesKeyField.setText(keyGen.generateKey());

    }//GEN-LAST:event_newKeyButtonActionPerformed

    private void copyKeyButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_copyKeyButtonActionPerformed
        
        copySelection(aesKeyField);
    }//GEN-LAST:event_copyKeyButtonActionPerformed

    private void ivGenButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ivGenButtonActionPerformed
        try {
            // TODO add your handling code here:

            keyGen keyGen = new keyGen();
            
            aesIVField.setText(keyGen.generateIV());
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(startframe.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(startframe.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_ivGenButtonActionPerformed

    private void copyIVButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_copyIVButtonActionPerformed
        // TODO add your handling code here
        
        copySelection(aesIVField);
    }//GEN-LAST:event_copyIVButtonActionPerformed
    
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
    
    public void encodeAES() throws NoSuchAlgorithmException, Exception, InvalidAlgorithmParameterException, IllegalArgumentException {
        
        Encryption encryption = new Encryption();
        
        String textToEncode = aesFieldInput.getText();
        
        String textKey = aesKeyField.getText();
        
        String textIV = aesIVField.getText();
        
        byte[] decodedIV = Base64.getDecoder().decode(textIV);
        IvParameterSpec retrieved_iv = new IvParameterSpec(decodedIV);
        
        if (aesKeyField.getText().equals("") || aesFieldInput.getText().equals("")) {
            
            JOptionPane.showMessageDialog(null, "Text To Encode / KeyField Field must not be empty");
            
        } else {

            //Decoding Base 64 Key to Secretkey
            byte[] decodedAesBytes = Base64.getDecoder().decode(textKey);
            
            SecretKey originalKey = new SecretKeySpec(decodedAesBytes, 0, decodedAesBytes.length, "AES");
            
            String base64Encrypted = Base64.getEncoder().encodeToString(encryption.encrypt(textToEncode, originalKey, retrieved_iv));
            
            aesFieldOutPut.setText(base64Encrypted);
            
        }
        
    }
    
    public void decodeAES() throws NoSuchAlgorithmException, Exception, BadPaddingException, IllegalArgumentException {
        
        Encryption encryption = new Encryption();
        
        String textToDecode = aesFieldInput.getText();
        
        String textKey = aesKeyField.getText();
        
        String textIV = aesIVField.getText();
        
        byte[] decodedIV = Base64.getDecoder().decode(textIV);
        IvParameterSpec retrieved_iv = new IvParameterSpec(decodedIV);

        //Decoding Base 64 Key to Secretkey
        byte[] decodedAesBytes = Base64.getDecoder().decode(textKey);
        
        SecretKey originalKey = new SecretKeySpec(Arrays.copyOf(decodedAesBytes, 16), "AES");

        //Encoding decrypted message in base 64
        String decryptedMessageBase64 = encryption.decrypt(textToDecode, originalKey, retrieved_iv); // Takes the raw descrypted message

        byte[] decryptedBase64Bytes = Base64.getEncoder().encode(decryptedMessageBase64.getBytes()); //Encodes the raw message into base 64

        String encodedDecryptedMessage = new String(decryptedBase64Bytes); //Converts the encoded decrypted message into a string

        aesFieldOutPut.setText(encodedDecryptedMessage);
        
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
    private javax.swing.JMenuItem aesMenu;
    private javax.swing.JPanel aesPanel;
    private javax.swing.JTextField base64FieldInput;
    private javax.swing.JTextField base64FieldOutput;
    private javax.swing.JMenuItem base64Menu;
    private javax.swing.JPanel base64Panel;
    private javax.swing.JButton cleanButton;
    private javax.swing.JButton copyEncodedAesTextButton;
    private javax.swing.JButton copyIVButton;
    private javax.swing.JButton copyInputTextButton;
    private javax.swing.JButton copyKeyButton;
    private javax.swing.JButton copyOutputTextButton;
    private javax.swing.JButton decodeButton;
    private javax.swing.JMenuItem decodeMenu;
    private javax.swing.JButton encodeButton;
    private javax.swing.JMenuItem encodeMenu;
    private javax.swing.JMenu fileMenu;
    private javax.swing.JLabel firstLabel;
    private javax.swing.JLabel firstLabelAes;
    private javax.swing.JButton ivGenButton;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JLayeredPane mainLayeredPane;
    private javax.swing.JMenuBar mainMenuBar;
    private javax.swing.JMenu methodMenu;
    private javax.swing.JButton newKeyButton;
    private javax.swing.JMenu optionsMenu;
    private javax.swing.JLabel secondLabel;
    private javax.swing.JLabel secondLabelAes;
    // End of variables declaration//GEN-END:variables
}
