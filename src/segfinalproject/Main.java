/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package segfinalproject;

import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author anasollano
 */
public class Main {
    
    private char[] password;
    byte[] salt;
    public boolean error = false;
    
    public Main(char[] password){
        this.password = password;
    }
    
    public String encryptText(String text) {
        Security.setProperty("crypto.policy", "unlimited");
        // Create salt
        salt = createSalt();
        // Create key
        SecretKeySpec key = createKey();
        // Encrypting
        try {
            Cipher cipher = Cipher.getInstance("AES"); System.out.println(Cipher.getMaxAllowedKeyLength("AES"));
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedTextBytes = cipher.doFinal(text.getBytes("UTF-8"));
            return encode64(prependBytes(encryptedTextBytes));
        }
        catch(UnsupportedEncodingException | InvalidKeyException | 
                NoSuchAlgorithmException | BadPaddingException | 
                IllegalBlockSizeException | NoSuchPaddingException e){
            System.err.println(e.toString());
            error = true;
            return null;
        }
    }
    
    public void encryptFile(){
        
    }
    
    public String decryptText(String text){
        return "I'm decrypting waby";
    }
    
    public void decryptFile(){
        
    }
    
    public boolean checkPass(){
        String pass = String.valueOf(password);
        if (pass.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])"
                + "(?=.*[@#$%^&+=])(?=\\S+$).{8,}$")){
            return true;
        }
        return false;
    }
    
    private String encode64(byte[] cipherText){
        String encodedString = Base64.encodeToString(cipherText, Base64.NO_WRAP);
        return encodedString;
    }
    
    private byte[] createSalt(){
        // Secure random creation of salt
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);
        salt = bytes;
        return salt;
    }
    
    private SecretKeySpec createKey(){
        try{
            // Converting keys
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            // User chosen password is helping create the key along with the salt
            PBEKeySpec spec = new PBEKeySpec(password, salt, 65556, 256);
            // Creating key
            SecretKey secretKey = factory.generateSecret(spec);
            SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
            return secret;
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException e){
            error = true;
            System.err.print(e.toString());
            return null;
        }
    }
    
   
    private byte[] prependBytes(byte[] encryptedTextBytes){
        byte[] buffer = new byte[salt.length + encryptedTextBytes.length];
        System.arraycopy(salt, 0, buffer, 0, salt.length);
        System.arraycopy(encryptedTextBytes, 0, buffer, salt.length, encryptedTextBytes.length);
        System.out.println(Arrays.toString(buffer));
        return buffer;
    }
}
