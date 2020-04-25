/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package zp;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author nd160074d
 */
public class Tester {
 
    private static final String PASSPHRASE = "hello";
 
    private static final String DE_INPUT = "x.pgp";
    private static final String DE_OUTPUT = "djofa.txt";
    private static final String DE_KEY_FILE = "dummy.skr";
 
    private static final String E_INPUT = "x.txt";
    private static final String E_OUTPUT = "x.pgp";
    private static final String E_KEY_FILE = "dummy.pkr";
 
 
    public static void testDecrypt() throws Exception {
        PGPFileProcessor p = new PGPFileProcessor();
        p.setInputFileName(DE_INPUT);
        p.setOutputFileName(DE_OUTPUT);
        p.setPassphrase(PASSPHRASE);
        p.setSecretKeyFileName(DE_KEY_FILE);
        System.out.println(p.decrypt());
    }
 
    public static void testEncrypt() throws Exception {
        PGPFileProcessor p = new PGPFileProcessor();
        p.setInputFileName(E_INPUT);
        p.setOutputFileName(E_OUTPUT);
        p.setPassphrase(PASSPHRASE);
        p.setPublicKeyFileName(E_KEY_FILE);
        System.out.println(p.encrypt());
    }
    
   public static void main(String[] arg){
        try {
            testEncrypt();
            testDecrypt();
        } catch (Exception ex) {
            Logger.getLogger(Tester.class.getName()).log(Level.SEVERE, null, ex);
        }
   } 
}
