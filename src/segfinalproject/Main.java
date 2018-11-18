/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package segfinalproject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author anasollano
 */
public class Main {
    
    static byte[] salt;
    public static boolean error = false;
    
    public static String encryptText(String text, char[] password) {
        // Security.setProperty("crypto.policy", "unlimited");
        // Create salt
        salt = createSalt();
        // Create key
        SecretKeySpec key = createKey(password);
        // Encrypting
        try {
            Cipher cipher = Cipher.getInstance("AES");
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
    
    public static boolean encryptFile(String inPath, char[] password, boolean delete, String newPath){
        // Create salt
        salt = createSalt();
        // Create key
        SecretKeySpec key = createKey(password);
        Cipher cipher;
        // Instances of encryption
        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        catch(InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e){
            System.err.println(e.toString());
            return false;
        }
        File inFile = new File(inPath);
        FileOutputStream fos;
        
        try (FileInputStream fis = new FileInputStream(inFile)) {
            // Reading file
            byte[] inputBytes = new byte[(int) inFile.length()];
            fis.read(inputBytes);
            // Encrypting file
            byte[] outputBytes = cipher.doFinal(inputBytes);
            // Prepping writing with new name
            String outPath = "";
            String[] tokens = inPath.split("\\.(?=[^\\.]+$)");
            // If user chooses to delete:
            if (delete) {
                outPath = tokens[0] + ".cfr." + tokens[1];
            } else {
                String[] splitName = inFile.getName().split("\\.(?=[^\\.]+$)");
                outPath = newPath + "\\" + splitName[0] + ".cfr." + splitName[1];
            }
            fos = new FileOutputStream(outPath);
            fos.write(outputBytes);
            fos.close();
            return true;
        }
        catch (Exception e){
            System.err.println(e.toString());
            return false;
        }
    }
    
    public static String decryptText(String text, char[] password){
        // Remove salt
        ByteBuffer buffer = ByteBuffer.wrap(new Base64().decode(text, Base64.NO_WRAP));
        salt = new byte[20];
        buffer.get(salt, 0, salt.length);
        byte[] encryptedTextBytes = new byte[buffer.capacity() - salt.length];
        buffer.get(encryptedTextBytes);        
        // Create Key
        SecretKeySpec key = createKey(password);

        try {
            // Decrypting
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
            return new String(decryptedTextBytes);
        }
        catch(InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | 
                IllegalBlockSizeException | NoSuchPaddingException e){ 
            System.err.println(e.toString());
            return "null";
        }
    }
    
    public static void decryptFile(){
        
    }
    
    public static boolean checkPass(char[] password){
        String pass = String.valueOf(password);
        if (pass.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])"
                + "(?=.*[@#$%^&+=])(?=\\S+$).{8,}$")){
            return true;
        }
        return false;
    }
    
    private static String encode64(byte[] cipherText){
        String encodedString = Base64.encodeToString(cipherText, Base64.NO_WRAP);
        return encodedString;
    }
    
    private static byte[] createSalt(){
        // Secure random creation of salt
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);
        salt = bytes;
        return salt;
    }
    
    private static SecretKeySpec createKey(char[] password){
        try {
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
    
    private static byte[] prependBytes(byte[] encryptedTextBytes){
        byte[] buffer = new byte[salt.length + encryptedTextBytes.length];
        System.arraycopy(salt, 0, buffer, 0, salt.length);
        System.arraycopy(encryptedTextBytes, 0, buffer, salt.length, encryptedTextBytes.length);
        return buffer;
    }
    
    public static boolean deleteFile(String path){
        File file = new File(path);
        try {
            return Files.deleteIfExists(file.toPath());
        }
        catch(IOException e){
            System.err.println(e.toString());
        }
        return false;
    }
}
