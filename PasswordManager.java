import java.util.Scanner;

public class PasswordManager {
    
    public byte[] encrypt(String pass){

    }
    
    public String decrypt(byte[] pass){

    }

    public String findPassword(String label){

    }

    public void addPassword(String label, String pass){
        //overwrite if pass with label already exists
        //otherwise, create new entry
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        boolean cont = true;
        while(cont){
            //check for password file, create one if not found
            //ask for initial password
            System.out.println("Enter the passcode you want to use to access your passwords: ");
            String initalPassword = scanner.nextLine();
            //add salt with encrypted token to first line

            //otherwise, ask for password
            System.out.println("Enter the passcode to access your passwords: ");
            String passwordPassword = scanner.nextLine();

            // verify password password

            

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

                //encrypt password with salt
                //store in file with label

            }else if(choice.equals("r")){

                System.out.println("Enter label for password: ");
                String label = scanner.nextLine();

                //search for label
                //get password associated with label
                //decrypt and print password

                System.out.println("Found: ");

            }else{

                System.out.println("Quitting");
                cont = false;

            }
            
            
        }
        

        scanner.close();
    }
}
