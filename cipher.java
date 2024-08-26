import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class AES {
    private SecretKey key;
    private final int KEY_SIZE = 128;
    private final int T_LEN = 128;
    private Cipher encryptionCipher;

    public void setKey(String base64Key) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public void init() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        key = generator.generateKey();
    }

    public String encrypt(String message) throws Exception {
        if (key == null) throw new IllegalStateException("Key is not initialized");
        
        byte[] messageInBytes = message.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        if (key == null) throw new IllegalStateException("Key is not initialized");
        
        byte[] messageInBytes = decode(encryptedMessage);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            AES aes = new AES();

            // Prompt user to enter an action
            System.out.print("Enter 'generate' to create a new key or 'use' to input an existing base64-encoded key: ");
            String action = scanner.nextLine().trim().toLowerCase();

            if ("generate".equals(action)) {
                // Generate and display a new key
                aes.init();
                SecretKey key = aes.key;
                String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());
                System.out.println("Generated Key (Base64): " + base64Key);

                // Encrypt a message
                System.out.print("Enter the message to encrypt: ");
                String message = scanner.nextLine();
                String encryptedMessage = aes.encrypt(message);
                System.out.println("Encrypted Message: " + encryptedMessage);

                // Decrypt the message
                String decryptedMessage = aes.decrypt(encryptedMessage);
                System.out.println("Decrypted Message: " + decryptedMessage);

            } else if ("use".equals(action)) {
                // Use an existing key
                System.out.print("Enter the base64-encoded key: ");
                String base64Key = scanner.nextLine();
                aes.setKey(base64Key);

                // Prompt user to enter the encrypted message
                System.out.print("Enter the encrypted message: ");
                String encryptedMessage = scanner.nextLine();

                // Decrypt the message
                String decryptedMessage = aes.decrypt(encryptedMessage);
                System.out.println("Decrypted Message: " + decryptedMessage);

            } else {
                System.out.println("Invalid action. Please enter 'generate' or 'use'.");
            }

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}