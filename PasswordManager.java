import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager {

    private static byte [] passKey;
    private static byte [] salt;
    private static File file;
    
    public static String encrypt(String pass) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException{
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(passKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte [] encryptedData = cipher.doFinal(pass.getBytes());
        String messageString = new String(Base64.getEncoder().encode(encryptedData));
        return messageString;
    }
    
    public static String decrypt(String pass) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException{
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(passKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte [] decoded = Base64.getDecoder().decode(pass);
        byte [] decrypted = cipher.doFinal(decoded);
        pass = new String(decrypted);
        return pass;
    }

    public static String findPassword(String label) throws FileNotFoundException{
        //scan file line by line looking for the label
        Scanner scan = new Scanner(file);
        
        String line;
        while(scan.hasNextLine()){
            line = scan.nextLine();
            if(line.startsWith(label)){
            //return what comes after the colon after the label
                int startOfPass = line.lastIndexOf(":") + 1;
                scan.close();
                return line.substring(startOfPass);
            }
        }

        scan.close();

        return null;
    }

    public static void addPassword(String label, String pass) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException{
        //encrypt pass
        String encryptedPass = encrypt(pass);
        boolean overwritten = false;
        
        //scan file line by line looking for the label
        //because of how the writer works, we basically have to rewrite each line
        //then if we find the label, we will rewrite the line with the new password
        File tempFile = new File("tempFile"); 
        file.renameTo(tempFile);

        file = new File("passwordFile");
        file.createNewFile();

        Scanner scan = new Scanner(tempFile);
        FileWriter writer = new FileWriter("passwordFile", true);

        String line;
        while(scan.hasNextLine()){
            line = scan.nextLine();
            if(line.startsWith(label)){
            //overwrite if pass with label already exists
                writer.write(label + ":" + encryptedPass + "\n");
                overwritten = true;
            }else{
            //otherwise, write what is already in the file
                writer.write(line + "\n");
            }
        }

        //if we get to the end and never find the label, then the label-pass pair are added to the end
        if(!overwritten){
            writer.write(label + ":" + encryptedPass + "\n");
        }

        writer.close();
        scan.close();
        System.out.println("Deleting temp file: " + tempFile.delete());
    }

    public static boolean createFile() throws IOException{
        file = new File("passwordFile");
        return file.createNewFile();
    }

    public static void initializeFile(String pass) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        FileWriter writer = new FileWriter("passwordFile");
        //generate salt
        SecureRandom random = new SecureRandom();
        salt = new byte[16];
        random.nextBytes(salt);

        //generate passKey
        PBEKeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        passKey = sharedKey.getEncoded();

        //encrypt password
        String encryptedToken = encrypt(pass);

        //add salt and token to file
        // salt:encrypted_token
        String saltString = Base64.getEncoder().encodeToString(salt);
        writer.write(saltString + ":" + encryptedToken + "\n");
        writer.close();
    }

    public static boolean verifyFileAccess(String pass) throws FileNotFoundException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeySpecException{
        Scanner scan = new Scanner(file);
        //get encrypted password
        String line = scan.nextLine();
        int startOfPass = line.indexOf(":") + 1;
        String encryptedPass = line.substring(startOfPass);

        //get salt
        salt = Base64.getDecoder().decode(line.substring(0, startOfPass-1));

        //generate passKey
        PBEKeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        passKey = sharedKey.getEncoded();

        scan.close();
        //decrypt the password
        String truePass;
        try {
            truePass = decrypt(encryptedPass);
        } catch (BadPaddingException e){
            return false;
        }
        //check against the given password
        return truePass.equals(pass);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        Scanner scanner = new Scanner(System.in);

        //check for password file, create one if not found
        if(createFile()){
            System.out.println("No password file detected. Creating a new Password file.");
            //ask for initial password
            System.out.println("Enter the passcode you want to use to access your passwords: ");
            String initialPassword = scanner.nextLine();
            //generate salt with encrypted token and add to first line of the file
            initializeFile(initialPassword);
        }else{
            //otherwise, ask for password
            System.out.println("Enter the passcode to access your passwords: ");
            String passwordPassword = scanner.nextLine();

            // verify password password
            boolean correct = verifyFileAccess(passwordPassword);
            while(!correct){
                System.out.println("Incorrect password, please try again.");
                System.out.println("Enter the passcode to access your passwords: ");
                passwordPassword = scanner.nextLine();
                correct = verifyFileAccess(passwordPassword);
            }
        }

        boolean cont = true;
        while(cont){

            System.out.println("a : Add Password");
            System.out.println("r : Read Password");
            System.out.println("q : Quit");

            System.out.println("Enter choice: ");
            String choice = scanner.nextLine();

            
            if(choice.equals("a")){

                System.out.println("Enter label for password: ");
                String label = scanner.nextLine();
                System.out.println("Enter password to store: ");
                String pass = scanner.nextLine();

                addPassword(label, pass);

            }else if(choice.equals("r")){

                System.out.println("Enter label for password: ");
                String label = scanner.nextLine();

                //get password
                String encryptedPass = findPassword(label);
                if(encryptedPass != null){
                    //decrypt and print password
                    String password = decrypt(encryptedPass);
                    System.out.println("Found: " + password);
                }else{
                    System.out.println("Password associated with " + label + " could not be found");
                }
                

            }else{

                System.out.println("Quitting");
                cont = false;

            }
            
            System.out.println();
        }
        

        scanner.close();
    }
}
