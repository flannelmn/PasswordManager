import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.util.*;
import javax.crypto.spec.*;

public class Cryptography {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter the key: ");
        String keyString = scanner.nextLine();

        System.out.println("Encrypt or decrypt a message? (e|d)");
        String option = scanner.nextLine();

        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(keyString.getBytes(), "AES");

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