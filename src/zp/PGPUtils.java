/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package zp;

/**
 *
 * @author nd160074d
 */
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
 
import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
 
public class PGPUtils {
 
    private static final int   BUFFER_SIZE = 1 << 16; // should always be power of 2
    private static final int   KEY_FLAGS = 27;
    private static final int[] MASTER_KEY_CERTIFICATION_TYPES = new int[]{
        PGPSignature.POSITIVE_CERTIFICATION,
        PGPSignature.CASUAL_CERTIFICATION,
        PGPSignature.NO_CERTIFICATION,
        PGPSignature.DEFAULT_CERTIFICATION
    };
 
    /**
     * Load a secret key and find the private key in it
     * @param pgpSecKey The secret key
     * @param pass passphrase to decrypt secret key with
     * @return
     * @throws PGPException
     */
    public static PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecKey, char[] pass)
        throws PGPException, FileNotFoundException, IOException
    {
        if (pgpSecKey == null) return null;
     
        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass);
        return pgpSecKey.extractPrivateKey(decryptor);
    }
 
    public static void encryptFile(
        OutputStream out,
        String fileName,
        List<PGPPublicKey> encKeys,
        boolean armor,
        boolean withIntegrityCheck,
        boolean isCompressed,
        boolean isEncrypted,
        int alg)
        throws IOException, NoSuchProviderException, PGPException
    {
        Security.addProvider(new BouncyCastleProvider());
 
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
 
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData=null;
        if(isCompressed){
            comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        }
        else{
            comData = new PGPCompressedDataGenerator(PGPCompressedData.UNCOMPRESSED);
        }
 
        PGPUtil.writeFileToLiteralData(
                comData.open(bOut),
                PGPLiteralData.BINARY,
                new File(fileName) );
 
        comData.close();
 
        BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(alg);
        dataEncryptor.setWithIntegrityPacket(withIntegrityCheck);
        dataEncryptor.setSecureRandom(new SecureRandom());
 
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
        for(PGPPublicKey key:encKeys){
            encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(key));
        }
 
        byte[] bytes = bOut.toByteArray();
        if(isEncrypted){
            OutputStream cOut = encryptedDataGenerator.open(out, bytes.length);
            cOut.write(bytes);
            cOut.close();
        }
        else{
            out.write(bytes);
        }
        out.close();
    }
 
    @SuppressWarnings("unchecked")
    public static void signEncryptFile(
        OutputStream out,
        String fileName,
        List<PGPPublicKey> publicKeys,
        PGPSecretKey secretKey,
        String password,
        boolean armor,
        boolean withIntegrityCheck,
        boolean isCompressed,
        boolean isEncrypted,
        int alg)
        throws Exception
    {
 
        // Initialize Bouncy Castle security provider
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
 
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
 
        PGPCompressedDataGenerator compressedDataGenerator = null;
        // Initialize compressed data generator
        if(isCompressed){
            compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        }
        else{
            compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.UNCOMPRESSED);
        }
        OutputStream compressedOut=null;
        PGPEncryptedDataGenerator encryptedDataGenerator=null;
        if(isEncrypted){
            BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(alg);
            dataEncryptor.setWithIntegrityPacket(withIntegrityCheck);
            dataEncryptor.setSecureRandom(new SecureRandom());

            encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
            for(PGPPublicKey key:publicKeys){
                encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(key));
            }

            OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[PGPUtils.BUFFER_SIZE]);

            compressedOut = compressedDataGenerator.open(encryptedOut, new byte [PGPUtils.BUFFER_SIZE]);
        }
        else{
            compressedOut = compressedDataGenerator.open(out, new byte [PGPUtils.BUFFER_SIZE]);
        }
 
        // Initialize signature generator
        PGPPrivateKey privateKey = findPrivateKey(secretKey, password.toCharArray());
 
        PGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(),
                HashAlgorithmTags.SHA1);
 
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(signerBuilder);
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
 
        boolean firstTime = true;
        Iterator<String> it = secretKey.getPublicKey().getUserIDs();
        while (it.hasNext() && firstTime) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
            // Exit the loop after the first iteration
            firstTime = false;
        }
        signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
 
        // Initialize literal data generator
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(
            compressedOut,
            PGPLiteralData.BINARY,
            fileName,
            new Date(),
            new byte [PGPUtils.BUFFER_SIZE] );
 
        // Main loop - read the "in" stream, compress, encrypt and write to the "out" stream
        FileInputStream in = new FileInputStream(fileName);
        byte[] buf = new byte[PGPUtils.BUFFER_SIZE];
        int len;
        while ((len = in.read(buf)) > 0) {
            literalOut.write(buf, 0, len);
            signatureGenerator.update(buf, 0, len);
        }
 
        in.close();
        literalDataGenerator.close();
        // Generate the signature, compress, encrypt and write to the "out" stream
        signatureGenerator.generate().encode(compressedOut);
        compressedDataGenerator.close();
        if(isEncrypted){
            encryptedDataGenerator.close();
        }
        if (armor) {
            out.close();
        }
    }
}
