import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.util.*;
import javax.crypto.spec.*;
import javax.crypto.SecretKeyFactory;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class CryptographyCont {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException{
        Scanner scanner = new Scanner(System.in);

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        String saltString = Base64.getEncoder().encodeToString(salt);
        saltString = "vwZLxEY1ejf5tYAzQI6LcQ==";
        Base64.getDecoder().decode(saltString);

        System.out.println("Enter the key: ");
        String keyString = scanner.nextLine();

        PBEKeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        byte [] encoded = sharedKey.getEncoded();

        System.out.println("Encrypt or decrypt a message? (e|d)");
        String option = scanner.nextLine();

        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(encoded, "AES");

        if(option.equals("e")){
            System.out.print("Enter message to encrypt: ");
            String message = scanner.nextLine();
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte [] encryptedData = cipher.doFinal(message.getBytes());
            String messageString = new String(Base64.getEncoder().encode(encryptedData));
            System.out.println(messageString);
        }else if(option.equals("d")){
            System.out.print("Enter message to decrypt: ");
            String message = scanner.nextLine();
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte [] decoded = Base64.getDecoder().decode(message);
            byte [] decrypted = cipher.doFinal(decoded);
            message = new String(decrypted);
            System.out.println("Decrypted message: " + message);
        }else{
            System.err.println("wrong option");
            System.exit(1);
        }

        scanner.close();
    }
};