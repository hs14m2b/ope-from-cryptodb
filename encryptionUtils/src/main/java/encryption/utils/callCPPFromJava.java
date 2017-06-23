package encryption.utils;

public class callCPPFromJava {
   static {
      System.loadLibrary("ope"); // ope.dll (Windows) or libope.so (Unixes)
      //System.load("/usr/local/apache-tomcat/shared/lib/libope.so"); // ope.dll (Windows) or libope.so (Unixes)
   }
 
   // Native method declaration
   private native void initOPE();
   private native String encryptNum(String ptValue, int ptRange, int ctRange, String passphrase);
   private native String encryptStr(String ptValue, int ptRange, int ctRange, String passphrase, int precision, boolean shuffle, boolean randomMap, int charRange, int shufRange);
   private native String mapStr(String ptValue, int ptRange, int ctRange, String passphrase, int precision, boolean shuffle, boolean randomMap, int charRange, int shufRange);
   private native String encryptionRange(String ptValue, int ptRange, int ctRange, String passphrase, int precision, boolean shuffle, boolean randomMap, int charRange, int shufRange);
   private native String mapRange(String ptValue, int ptRange, int ctRange, String passphrase, int precision, boolean shuffle, boolean randomMap, int charRange, int shufRange);
   private native String decrypt(String ctValue, int ptRange, int ctRange, String passphrase);
   private native String decryptStr(String ctValue, int ptRange, int ctRange, String passphrase, int precision, boolean shuffle, boolean randomMap, int charRange, int shufRange);
 
   public String encryptNumJava(String ptValue, int ptRange, int ctRange, String passphrase)
   {
     return encryptNum(ptValue, ptRange, ctRange, passphrase);
   }
   public String encryptStrJava(String ptValue, int ptRange, int ctRange, String passphrase, int precision, boolean shuffle, boolean randomMap, int charRange, int shufRange)
   {
     return encryptStr(ptValue, ptRange, ctRange, passphrase, precision, shuffle, randomMap, charRange, shufRange);
   }
   public String mapStrJava(String ptValue, int ptRange, int ctRange, String passphrase, int precision, boolean shuffle, boolean randomMap, int charRange, int shufRange)
   {
     return mapStr(ptValue, ptRange, ctRange, passphrase, precision, shuffle, randomMap, charRange, shufRange);
   }
   public String encryptionRangeJava(String ptValue, int ptRange, int ctRange, String passphrase, int precision, boolean shuffle, boolean randomMap, int charRange, int shufRange)
   {
     return encryptionRange(ptValue, ptRange, ctRange, passphrase, precision, shuffle, randomMap, charRange, shufRange);
   }
   public String mapRangeJava(String ptValue, int ptRange, int ctRange, String passphrase, int precision, boolean shuffle, boolean randomMap, int charRange, int shufRange)
   {
     return mapRange(ptValue, ptRange, ctRange, passphrase, precision, shuffle, randomMap, charRange, shufRange);
   }
   public String decryptJava(String ctValue, int ptRange, int ctRange, String passphrase)
   {
     return decrypt(ctValue, ptRange, ctRange, passphrase);
   }
   public String decryptStrJava(String ctValue, int ptRange, int ctRange, String passphrase, int precision, boolean shuffle, boolean randomMap, int charRange, int shufRange)
   {
     return decryptStr(ctValue, ptRange, ctRange, passphrase, precision, shuffle, randomMap, charRange, shufRange);
   }

/*   // Test Driver
   public static void main(String[] args) {
        //new callCPPFromJava().initOPE();  // Invoke native method
	System.out.println("about to encrypt a number");
	String encValue = new callCPPFromJava().encryptNum("20161121235959999", 64, 128, "P4aa9hrase");
	System.out.println("encrypted value is " + encValue);
	String decValue = new callCPPFromJava().decrypt(encValue, 64, 128, "P4aa9hrase");
	System.out.println("decrypted value is " + decValue);
	int precision = 10;
	int ptRange = 96;
	int ctRange = 192;
	System.out.println("about to encrypt a string with a precision of " + precision + " characters");
	encValue = new callCPPFromJava().encryptStr("TESTING encryption on text",ptRange, ctRange, "P4aa9hrase", precision, true);
	System.out.println("encrypted value is " + encValue);
	System.out.println("encrypted value length is " + encValue.length());
	decValue = new callCPPFromJava().decryptStr(encValue, ptRange, ctRange, "P4aa9hrase", precision, true);
	System.out.println("decrypted value is " + decValue);
	String encRange = new callCPPFromJava().encryptionRange("TESTING encryption on text",ptRange, ctRange, "P4aa9hrase", precision, true);
	System.out.println("Encryption range is " + encRange);
   }
*/
}

