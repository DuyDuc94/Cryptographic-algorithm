/*
 * DuyDuc94
 */
package aes_algorithm;

/**
 *
 * @author duy20
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String secretKey = "DuyDuc94";
        String originalString = "1-2-3-4-5-6-7-8-9-0-6-3-2-5-67-8-4-32-4-6-878-5";

        AESAlgorithm aes = new AESAlgorithm();
        System.out.println("HEX: ");
        String encryptedString1 = aes.encryptHex(originalString, secretKey);
        System.out.println("Encrypt: " + encryptedString1);
        String decryptedString1 = aes.decryptHex(encryptedString1, secretKey);
        System.out.println("Decrypt: " + decryptedString1);
        
        System.out.println("Base64: ");
        String encryptedString2 = aes.encrypt(originalString, secretKey);
        System.out.println("Encrypt: " + encryptedString2);
        String decryptedString2 = aes.decrypt(encryptedString2, secretKey);
        System.out.println("Decrypt: " + decryptedString2);
    }

}
