/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package zp;

import java.awt.RenderingHints.Key;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.DefaultListModel;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import static zp.PGPUtils.findPrivateKey;
import static zp.RSAGen.generateKeyRingGenerator;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.io.Streams;

/**
 *
 * @author nd160074d
 */
public class MainFrame extends javax.swing.JFrame {

    private String id;

    static String publicKeyFileName = "dummy.pkr";
    static String secretKeyFileName = "dummy.skr";

    FileInputStream publicIn;
    FileInputStream secretIn;

    private PGPPublicKeyRingCollection publicKeyCollection;
    private PGPSecretKeyRingCollection secretKeyCollection;
    private int keySize;

    /**
     * Creates new form MainFrame
     */
    public MainFrame() {
        try {
            initComponents();

            this.addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosing(WindowEvent e) {
                    saveKeyRings();
                }

            });

            publicIn = new FileInputStream(publicKeyFileName);
            secretIn = new FileInputStream(secretKeyFileName);

            publicKeyCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicIn), new BcKeyFingerprintCalculator());
            secretKeyCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(secretIn), new BcKeyFingerprintCalculator());

            Iterator<PGPPublicKeyRing> rIt = publicKeyCollection.getKeyRings();
            while (rIt.hasNext()) {
                PGPPublicKeyRing ring = rIt.next();
                System.out.println("Nadjen ring");

                Iterator<PGPPublicKey> kIt2 = ring.getPublicKeys();
                while (kIt2.hasNext()) {
                    PGPPublicKey key = kIt2.next();
                    System.out.println("ID:" + key.getKeyID());
                    System.out.println("Master?" + key.isMasterKey());
                    System.out.println("Encryption?:" + key.isEncryptionKey());
                }

            }

            showKeys();

        } catch (FileNotFoundException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        passwordDialog = new javax.swing.JDialog();
        jLabel5 = new javax.swing.JLabel();
        jPasswordField1 = new javax.swing.JPasswordField();
        jButton2 = new javax.swing.JButton();
        buttonGroup1 = new javax.swing.ButtonGroup();
        buttonGroup2 = new javax.swing.ButtonGroup();
        jPanel2 = new javax.swing.JPanel();
        jLabel6 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        kljuceviBrisanje = new javax.swing.JList<>();
        jLabel7 = new javax.swing.JLabel();
        lozinka = new javax.swing.JPasswordField();
        obrisi = new javax.swing.JButton();
        neispravnaLozinka = new javax.swing.JLabel();
        jPanel4 = new javax.swing.JPanel();
        jLabel10 = new javax.swing.JLabel();
        jLabel11 = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        lozinkaPrijem = new javax.swing.JPasswordField();
        dekriptuj = new javax.swing.JButton();
        proveraIntegriteta = new javax.swing.JLabel();
        jLabel14 = new javax.swing.JLabel();
        imeAutor = new javax.swing.JLabel();
        mailAutora = new javax.swing.JLabel();
        inputFile = new javax.swing.JTextField();
        outputFile = new javax.swing.JTextField();
        jLabel17 = new javax.swing.JLabel();
        pogresnaLozinka = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        potvrdaGenerisanje = new javax.swing.JButton();
        rsa1 = new javax.swing.JRadioButton();
        rsa2 = new javax.swing.JRadioButton();
        ime = new javax.swing.JTextField();
        rsa3 = new javax.swing.JRadioButton();
        mejl = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        kljucevi = new javax.swing.JTextArea();
        jPanel3 = new javax.swing.JPanel();
        jLabel8 = new javax.swing.JLabel();
        enkripcija = new javax.swing.JCheckBox();
        potpisivanje = new javax.swing.JCheckBox();
        kompresija = new javax.swing.JCheckBox();
        konverzija = new javax.swing.JCheckBox();
        des = new javax.swing.JRadioButton();
        idea = new javax.swing.JRadioButton();
        jLabel9 = new javax.swing.JLabel();
        lozinkaSlanje = new javax.swing.JPasswordField();
        jScrollPane3 = new javax.swing.JScrollPane();
        javniKljuceviSlanje = new javax.swing.JList<>();
        potvrdaSlanje = new javax.swing.JButton();
        jScrollPane5 = new javax.swing.JScrollPane();
        privatniKljuceviSlanje = new javax.swing.JList<>();
        fajlSlanje = new javax.swing.JTextField();
        jLabel16 = new javax.swing.JLabel();
        jLabel18 = new javax.swing.JLabel();
        jLabel19 = new javax.swing.JLabel();
        jLabel20 = new javax.swing.JLabel();
        jPanel5 = new javax.swing.JPanel();
        jScrollPane6 = new javax.swing.JScrollPane();
        jList1 = new javax.swing.JList<>();
        uveziPrivatni = new javax.swing.JButton();
        jLabel13 = new javax.swing.JLabel();
        izaberiKljuc = new javax.swing.JButton();
        izvezi = new javax.swing.JButton();
        jLabel15 = new javax.swing.JLabel();
        fileName = new javax.swing.JTextField();
        uveziJavni = new javax.swing.JButton();
        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();
        jMenuItem2 = new javax.swing.JMenuItem();
        jMenu3 = new javax.swing.JMenu();
        jMenuItem3 = new javax.swing.JMenuItem();
        jMenu4 = new javax.swing.JMenu();
        jMenuItem4 = new javax.swing.JMenuItem();
        jMenu5 = new javax.swing.JMenu();
        jMenuItem5 = new javax.swing.JMenuItem();

        passwordDialog.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        passwordDialog.setAlwaysOnTop(true);
        passwordDialog.setModal(true);
        passwordDialog.setResizable(false);
        passwordDialog.setSize(new java.awt.Dimension(400, 300));

        jLabel5.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel5.setText("Lozinka:");

        jPasswordField1.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jPasswordField1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jPasswordField1ActionPerformed(evt);
            }
        });

        jButton2.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jButton2.setText("Potvrdi");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout passwordDialogLayout = new javax.swing.GroupLayout(passwordDialog.getContentPane());
        passwordDialog.getContentPane().setLayout(passwordDialogLayout);
        passwordDialogLayout.setHorizontalGroup(
            passwordDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passwordDialogLayout.createSequentialGroup()
                .addGroup(passwordDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(passwordDialogLayout.createSequentialGroup()
                        .addGap(30, 30, 30)
                        .addComponent(jLabel5)
                        .addGap(18, 18, 18)
                        .addComponent(jPasswordField1, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(passwordDialogLayout.createSequentialGroup()
                        .addGap(140, 140, 140)
                        .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, 114, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(87, Short.MAX_VALUE))
        );
        passwordDialogLayout.setVerticalGroup(
            passwordDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passwordDialogLayout.createSequentialGroup()
                .addGap(115, 115, 115)
                .addGroup(passwordDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5)
                    .addComponent(jPasswordField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 159, Short.MAX_VALUE)
                .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, 47, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(51, 51, 51))
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jPanel2.setVisible(false);

        jLabel6.setFont(new java.awt.Font("Tahoma", 0, 36)); // NOI18N
        jLabel6.setText("Brisanje kljuca");

        jScrollPane2.setViewportView(kljuceviBrisanje);

        jLabel7.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel7.setText("Lozinka:");

        obrisi.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        obrisi.setText("OBRISI");
        obrisi.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                obrisiActionPerformed(evt);
            }
        });

        neispravnaLozinka.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        neispravnaLozinka.setForeground(new java.awt.Color(255, 51, 51));

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(57, 57, 57)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 223, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(82, 82, 82)
                        .addComponent(jLabel7)
                        .addGap(63, 63, 63)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(lozinka, javax.swing.GroupLayout.DEFAULT_SIZE, 196, Short.MAX_VALUE)
                            .addComponent(obrisi, javax.swing.GroupLayout.PREFERRED_SIZE, 116, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(neispravnaLozinka, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(265, 265, 265)
                        .addComponent(jLabel6)))
                .addContainerGap(92, Short.MAX_VALUE))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(33, 33, 33)
                .addComponent(jLabel6)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(95, 95, 95)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel7)
                            .addComponent(lozinka, javax.swing.GroupLayout.PREFERRED_SIZE, 29, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(40, 40, 40)
                        .addComponent(neispravnaLozinka, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(79, 79, 79)
                        .addComponent(obrisi))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(38, 38, 38)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 427, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(58, Short.MAX_VALUE))
        );

        jPanel4.setPreferredSize(new java.awt.Dimension(800, 600));
        jPanel4.setVisible(false);

        jLabel10.setFont(new java.awt.Font("Tahoma", 0, 36)); // NOI18N
        jLabel10.setText("Prijem poruke");

        jLabel11.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel11.setText("Odaberite poruku:");

        jLabel12.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel12.setText("Lozinka:");

        dekriptuj.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        dekriptuj.setText("DEKRIPTUJ");
        dekriptuj.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dekriptujActionPerformed(evt);
            }
        });

        proveraIntegriteta.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        proveraIntegriteta.setText("provera integriteta");

        jLabel14.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel14.setText("Autor:");

        imeAutor.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        imeAutor.setText("ime autora");

        mailAutora.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        mailAutora.setText("mail autora");

        jLabel17.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel17.setText("Izlazni fajl:");

        pogresnaLozinka.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        pogresnaLozinka.setForeground(new java.awt.Color(255, 51, 51));

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(282, 282, 282)
                        .addComponent(jLabel10))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(141, 141, 141)
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel11)
                            .addComponent(jLabel12)
                            .addComponent(jLabel17, javax.swing.GroupLayout.PREFERRED_SIZE, 193, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(76, 76, 76)
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(lozinkaPrijem, javax.swing.GroupLayout.DEFAULT_SIZE, 249, Short.MAX_VALUE)
                            .addComponent(inputFile)
                            .addComponent(outputFile)
                            .addComponent(pogresnaLozinka, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(133, 133, 133)
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(proveraIntegriteta, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel14))
                        .addGap(8, 8, 8)
                        .addComponent(imeAutor, javax.swing.GroupLayout.PREFERRED_SIZE, 180, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(mailAutora, javax.swing.GroupLayout.PREFERRED_SIZE, 180, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(326, 326, 326)
                        .addComponent(dekriptuj)))
                .addContainerGap(81, Short.MAX_VALUE))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addGap(27, 27, 27)
                .addComponent(jLabel10)
                .addGap(102, 102, 102)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel11)
                    .addComponent(inputFile, javax.swing.GroupLayout.PREFERRED_SIZE, 29, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(47, 47, 47)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(lozinkaPrijem, javax.swing.GroupLayout.PREFERRED_SIZE, 29, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel12))
                .addGap(49, 49, 49)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(outputFile, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel17, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(pogresnaLozinka)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 46, Short.MAX_VALUE)
                .addComponent(dekriptuj)
                .addGap(46, 46, 46)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(imeAutor)
                    .addComponent(mailAutora)
                    .addComponent(jLabel14))
                .addGap(18, 18, 18)
                .addComponent(proveraIntegriteta, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(25, 25, 25))
        );

        jPanel1.setPreferredSize(new java.awt.Dimension(800, 600));

        potvrdaGenerisanje.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        potvrdaGenerisanje.setText("POTVRDA");
        potvrdaGenerisanje.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                potvrdaGenerisanjeActionPerformed(evt);
            }
        });

        buttonGroup2.add(rsa1);
        rsa1.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        rsa1.setText("1024");
        rsa1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rsa1ActionPerformed(evt);
            }
        });

        buttonGroup2.add(rsa2);
        rsa2.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        rsa2.setText("2048");
        rsa2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rsa2ActionPerformed(evt);
            }
        });

        ime.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                imeActionPerformed(evt);
            }
        });

        buttonGroup2.add(rsa3);
        rsa3.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        rsa3.setText("4096");
        rsa3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rsa3ActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel1.setText("Ime:");

        jLabel4.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel4.setText("Velicina kljuca za RSA:");

        jLabel2.setFont(new java.awt.Font("Tahoma", 0, 36)); // NOI18N
        jLabel2.setText("Generisanje kljuceva");

        jLabel3.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel3.setText("Mejl:");

        kljucevi.setColumns(20);
        kljucevi.setRows(5);
        kljucevi.setPreferredSize(new java.awt.Dimension(164, 150));
        jScrollPane1.setViewportView(kljucevi);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(237, 237, 237)
                .addComponent(jLabel2)
                .addGap(0, 0, Short.MAX_VALUE))
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(112, 112, 112)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(jLabel4)
                                .addGap(51, 51, 51)
                                .addComponent(rsa1)
                                .addGap(39, 39, 39)
                                .addComponent(rsa2, javax.swing.GroupLayout.PREFERRED_SIZE, 78, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(rsa3))
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel1)
                                    .addComponent(mejl, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel3)
                                    .addComponent(ime, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(35, 35, 35)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 335, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(320, 320, 320)
                        .addComponent(potvrdaGenerisanje)))
                .addContainerGap(118, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(62, 62, 62)
                .addComponent(jLabel2)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(79, 79, 79)
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(ime, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(mejl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(38, 38, 38)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 234, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jLabel4)
                    .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(rsa1)
                        .addComponent(rsa2, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(rsa3)))
                .addGap(38, 38, 38)
                .addComponent(potvrdaGenerisanje, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(389, 389, 389))
        );

        jPanel3.setPreferredSize(new java.awt.Dimension(800, 600));
        jPanel3.setVisible(false);

        jLabel8.setFont(new java.awt.Font("Tahoma", 0, 36)); // NOI18N
        jLabel8.setText("Slanje poruke");

        enkripcija.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        enkripcija.setText("Enkripcija");
        enkripcija.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enkripcijaActionPerformed(evt);
            }
        });

        potpisivanje.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        potpisivanje.setText("Potpisivanje");

        kompresija.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        kompresija.setText("Kompresija (ZIP)");

        konverzija.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        konverzija.setText("Konverzija (radix)");
        konverzija.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                konverzijaActionPerformed(evt);
            }
        });

        buttonGroup1.add(des);
        des.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        des.setText("3DES");
        des.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                desActionPerformed(evt);
            }
        });

        buttonGroup1.add(idea);
        idea.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        idea.setText("IDEA");

        jLabel9.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel9.setText("Lozinka:");

        jScrollPane3.setViewportView(javniKljuceviSlanje);

        potvrdaSlanje.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        potvrdaSlanje.setText("POTVRDA");
        potvrdaSlanje.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                potvrdaSlanjeActionPerformed(evt);
            }
        });

        jScrollPane5.setPreferredSize(new java.awt.Dimension(0, 0));

        jScrollPane5.setViewportView(privatniKljuceviSlanje);

        jLabel16.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel16.setText("Naziv fajla:");

        jLabel18.setText("(bez ekstenzije)");

        jLabel19.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel19.setText("Javni kljucevi:");

        jLabel20.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel20.setText("Privatni kljucevi:");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(41, 41, 41)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(279, 279, 279)
                        .addComponent(jLabel8))
                    .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addGroup(jPanel3Layout.createSequentialGroup()
                            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(konverzija)
                                .addComponent(kompresija)
                                .addComponent(potpisivanje)
                                .addComponent(enkripcija))
                            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addGroup(jPanel3Layout.createSequentialGroup()
                                    .addGap(50, 50, 50)
                                    .addComponent(des)
                                    .addGap(37, 37, 37)
                                    .addComponent(idea)
                                    .addGap(238, 238, 238))
                                .addGroup(jPanel3Layout.createSequentialGroup()
                                    .addGap(48, 48, 48)
                                    .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 201, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabel19))
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabel20, javax.swing.GroupLayout.PREFERRED_SIZE, 143, javax.swing.GroupLayout.PREFERRED_SIZE)))))
                        .addGroup(jPanel3Layout.createSequentialGroup()
                            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addGroup(jPanel3Layout.createSequentialGroup()
                                    .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jLabel18)
                                        .addComponent(jLabel9))
                                    .addGap(40, 40, 40))
                                .addGroup(jPanel3Layout.createSequentialGroup()
                                    .addComponent(jLabel16)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)))
                            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(fajlSlanje)
                                .addComponent(lozinkaSlanje, javax.swing.GroupLayout.DEFAULT_SIZE, 310, Short.MAX_VALUE)))))
                .addGap(0, 53, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(potvrdaSlanje)
                .addGap(315, 315, 315))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(34, 34, 34)
                .addComponent(jLabel8)
                .addGap(41, 41, 41)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(enkripcija)
                    .addComponent(des)
                    .addComponent(idea))
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(36, 36, 36)
                        .addComponent(kompresija)
                        .addGap(44, 44, 44)
                        .addComponent(konverzija)
                        .addGap(38, 38, 38)
                        .addComponent(potpisivanje)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 79, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                        .addGap(18, 18, 18)
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jLabel19, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jLabel20, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 220, Short.MAX_VALUE))
                        .addGap(39, 39, 39)))
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(fajlSlanje, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel16))
                        .addGap(25, 25, 25))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addComponent(jLabel18)
                        .addGap(18, 18, 18)))
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jLabel9)
                    .addComponent(lozinkaSlanje, javax.swing.GroupLayout.PREFERRED_SIZE, 37, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(potvrdaSlanje)
                .addGap(28, 28, 28))
        );

        jPanel5.setPreferredSize(new java.awt.Dimension(800, 600));
        jPanel5.setVisible(false);

        jList1.setModel(new javax.swing.AbstractListModel<String>() {
            String[] strings = { "Item 1", "Item 2", "Item 3", "Item 4", "Item 5" };
            public int getSize() { return strings.length; }
            public String getElementAt(int i) { return strings[i]; }
        });
        jScrollPane6.setViewportView(jList1);

        uveziPrivatni.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        uveziPrivatni.setText("Uvezi privatni");
        uveziPrivatni.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                uveziPrivatniActionPerformed(evt);
            }
        });

        jLabel13.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel13.setText("IZVOZ KLJUCA");

        izaberiKljuc.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        izaberiKljuc.setText("Izaberi kljuc");

        izvezi.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        izvezi.setText("Izvezi");
        izvezi.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                izveziActionPerformed(evt);
            }
        });

        jLabel15.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel15.setText("UVOZ KLJUCA");

        fileName.setToolTipText("");

        uveziJavni.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        uveziJavni.setText("Uvezi javni");
        uveziJavni.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                uveziJavniActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addGap(80, 80, 80)
                        .addComponent(jScrollPane6, javax.swing.GroupLayout.PREFERRED_SIZE, 286, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addGap(154, 154, 154)
                        .addComponent(jLabel13)))
                .addGap(151, 151, 151)
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel15)
                    .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addComponent(fileName, javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(izaberiKljuc, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addContainerGap(135, Short.MAX_VALUE))
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addGap(174, 174, 174)
                .addComponent(izvezi)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(uveziJavni)
                .addGap(33, 33, 33)
                .addComponent(uveziPrivatni)
                .addGap(69, 69, 69))
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addGap(65, 65, 65)
                        .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel13)
                            .addComponent(jLabel15))
                        .addGap(60, 60, 60)
                        .addComponent(jScrollPane6, javax.swing.GroupLayout.PREFERRED_SIZE, 236, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(29, 29, 29))
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addGap(229, 229, 229)
                        .addComponent(izaberiKljuc)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(fileName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(42, 42, 42)))
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addGap(19, 19, 19)
                        .addComponent(izvezi)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel5Layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 10, Short.MAX_VALUE)
                        .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(uveziPrivatni)
                            .addComponent(uveziJavni))
                        .addGap(140, 140, 140))))
        );

        jMenu1.setText("Generisanje kljuceva");

        jMenuItem1.setText("Generisanje kljuceva");
        jMenuItem1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem1ActionPerformed(evt);
            }
        });
        jMenu1.add(jMenuItem1);

        jMenuBar1.add(jMenu1);

        jMenu2.setText("Brisanje kljuceva");

        jMenuItem2.setText("Brisanje kljuceva");
        jMenuItem2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem2ActionPerformed(evt);
            }
        });
        jMenu2.add(jMenuItem2);

        jMenuBar1.add(jMenu2);

        jMenu3.setText("Slanje poruke");

        jMenuItem3.setText("Slanje poruke");
        jMenuItem3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem3ActionPerformed(evt);
            }
        });
        jMenu3.add(jMenuItem3);

        jMenuBar1.add(jMenu3);

        jMenu4.setText("Prijem poruke");

        jMenuItem4.setText("Prijem poruke");
        jMenuItem4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem4ActionPerformed(evt);
            }
        });
        jMenu4.add(jMenuItem4);

        jMenuBar1.add(jMenu4);

        jMenu5.setText("Uvoz/Izvoz");

        jMenuItem5.setText("Uvoz/Izvoz");
        jMenuItem5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem5ActionPerformed(evt);
            }
        });
        jMenu5.add(jMenuItem5);

        jMenuBar1.add(jMenu5);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 800, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(jPanel5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 600, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(jPanel5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void imeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_imeActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_imeActionPerformed

    private void rsa1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rsa1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rsa1ActionPerformed

    private void rsa2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rsa2ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rsa2ActionPerformed

    private void rsa3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rsa3ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rsa3ActionPerformed

    private void jPasswordField1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jPasswordField1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jPasswordField1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        try {
            /*
            try {
            
            String password=jPasswordField1.getText();
            //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            
            byte[] input = "Cao ja sam djole.".getBytes();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //SecureRandom random = new SecureRandom();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            PublicKey pubKey = pair.getPublic();
            PrivateKey privKey = pair.getPrivate();
            
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            System.out.println("Private key:"+((RSAPrivateKey)privKey).getPrivateExponent());
            System.out.println("Public key:"+((RSAPublicKey)pubKey).getPublicExponent());
            
            byte[] cipherText = cipher.doFinal(input);
            System.out.println("cipher: ");
            System.out.println(new String(cipherText));
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            byte[] plainText = cipher.doFinal(cipherText);
            System.out.println("plain : " + new String(plainText));
            
            passwordDialog.setVisible(false);
            } catch (InvalidKeyException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
            }
             */

            char pass[] = jPasswordField1.getPassword();
            PGPKeyRingGenerator krgen = generateKeyRingGenerator(id, pass, keySize);

            // Generate public key ring.
            PGPPublicKeyRing pkr = krgen.generatePublicKeyRing();
            publicKeyCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyCollection, pkr);

            // Generate private key ring.
            PGPSecretKeyRing skr = krgen.generateSecretKeyRing();
            secretKeyCollection = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyCollection, skr);

        } catch (Exception ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_jButton2ActionPerformed

    private void potvrdaGenerisanjeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_potvrdaGenerisanjeActionPerformed
        id = ime.getText() + "/" + mejl.getText();
        if (rsa1.isSelected()) {
            keySize = 1024;
        }
        if (rsa2.isSelected()) {
            keySize = 2048;
        }
        if (rsa3.isSelected()) {
            keySize = 4096;
        }
        passwordDialog.setLocationRelativeTo(null);
        passwordDialog.setVisible(true);

    }//GEN-LAST:event_potvrdaGenerisanjeActionPerformed

    private void jMenuItem1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem1ActionPerformed
        jPanel1.setVisible(true);
        jPanel2.setVisible(false);
        jPanel3.setVisible(false);
        jPanel4.setVisible(false);
        jPanel5.setVisible(false);

        showKeys();
    }//GEN-LAST:event_jMenuItem1ActionPerformed

    private void jMenuItem2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem2ActionPerformed
        jPanel1.setVisible(false);
        jPanel2.setVisible(true);
        jPanel3.setVisible(false);
        jPanel4.setVisible(false);
        jPanel5.setVisible(false);
        DefaultListModel<String> modelAddList = new DefaultListModel();
        Iterator<PGPPublicKeyRing> rIt = publicKeyCollection.getKeyRings();
        while (rIt.hasNext()) {
            PGPPublicKeyRing ring = rIt.next();
            modelAddList.addElement("" + ring.getPublicKey().getKeyID());
        }
        kljuceviBrisanje.setModel(modelAddList);
        neispravnaLozinka.setText("");
    }//GEN-LAST:event_jMenuItem2ActionPerformed

    private void obrisiActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_obrisiActionPerformed
        try {
            PGPSecretKey privateKey = secretKeyCollection.getSecretKey(Long.parseLong(kljuceviBrisanje.getSelectedValue()));
            Iterator<String> it = privateKey.getUserIDs();
            if (PGPUtils.findPrivateKey(privateKey, lozinka.getText().toCharArray()) != null) {
                PGPPublicKeyRing publicRing = publicKeyCollection.getPublicKeyRing(Long.parseLong(kljuceviBrisanje.getSelectedValue()));
                PGPSecretKeyRing secretRing = secretKeyCollection.getSecretKeyRing(Long.parseLong(kljuceviBrisanje.getSelectedValue()));
                publicKeyCollection = PGPPublicKeyRingCollection.removePublicKeyRing(publicKeyCollection, publicRing);
                secretKeyCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(secretKeyCollection, secretRing);
                neispravnaLozinka.setText("");
            } else {
                neispravnaLozinka.setText("Neispravna lozinka!");
            }

            DefaultListModel<String> modelAddList = new DefaultListModel();

            Iterator<PGPPublicKeyRing> rIt = publicKeyCollection.getKeyRings();
            while (rIt.hasNext()) {
                PGPPublicKeyRing ring = rIt.next();
                modelAddList.addElement("" + ring.getPublicKey().getKeyID());
            }

            kljuceviBrisanje.setModel(modelAddList);
        } catch (PGPException ex) {
            neispravnaLozinka.setText("Neispravna lozinka!");
        } catch (IOException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_obrisiActionPerformed

    private void desActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_desActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_desActionPerformed

    private void potvrdaSlanjeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_potvrdaSlanjeActionPerformed
        try {

            FileOutputStream out = null;
            PGPPublicKeyRing publicRing = publicKeyCollection.getPublicKeyRing(Long.parseLong(javniKljuceviSlanje.getSelectedValue()));
            PGPPublicKey publicKey = null;
            while (publicKey == null) {
                Iterator<PGPPublicKey> kIt = publicRing.getPublicKeys();
                while (publicKey == null && kIt.hasNext()) {
                    PGPPublicKey key = kIt.next();
                    System.out.println("Nadjen kljuc " + key.getKeyID());
                    if (key.isEncryptionKey()) {
                        publicKey = key;
                    }
                }
            }
            try {
                String inputFileName = fajlSlanje.getText() + ".txt";
                out = new FileOutputStream(fajlSlanje.getText() + ".pgp");

                if (potpisivanje.isSelected()) {
                    PGPSecretKeyRing secretRing = secretKeyCollection.getSecretKeyRing(Long.parseLong(privatniKljuceviSlanje.getSelectedValue()));
                    PGPSecretKey secretKey = null;
                    while (secretKey == null) {
                        Iterator<PGPSecretKey> kIt = secretRing.getSecretKeys();
                        while (secretKey == null && kIt.hasNext()) {
                            PGPSecretKey key = kIt.next();
                            System.out.println("Nadjen kljuc " + key.getKeyID());
                            if (key.isSigningKey()) {
                                secretKey = key;
                            }
                        }
                    }

                    PGPUtils.signEncryptFile(out, inputFileName, publicKey, secretKey, lozinkaSlanje.getText(), false, true);
                } else {
                    if (kompresija.isSelected()) {
                        PGPUtils.encryptFile(out, inputFileName, publicKey, false, true, true);
                    } else {
                        PGPUtils.encryptFile(out, inputFileName, publicKey, false, true, false);
                    }
                }
                out.close();

            } catch (FileNotFoundException ex) {
                Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchProviderException ex) {
                Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
            } catch (Exception ex) {
                Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                try {
                    out.close();
                } catch (IOException ex) {
                    Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        } catch (PGPException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_potvrdaSlanjeActionPerformed

    private void jMenuItem3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem3ActionPerformed
        jPanel1.setVisible(false);
        jPanel2.setVisible(false);
        jPanel3.setVisible(true);
        jPanel4.setVisible(false);
        jPanel5.setVisible(false);

        DefaultListModel<String> modelAddList = new DefaultListModel();

        Iterator<PGPPublicKeyRing> rIt = publicKeyCollection.getKeyRings();
        while (rIt.hasNext()) {
            PGPPublicKeyRing ring = rIt.next();
            modelAddList.addElement("" + ring.getPublicKey().getKeyID());
        }

        javniKljuceviSlanje.setModel(modelAddList);

        DefaultListModel<String> modelAddList2 = new DefaultListModel();

        Iterator<PGPSecretKeyRing> rIt2 = secretKeyCollection.getKeyRings();
        while (rIt2.hasNext()) {
            PGPSecretKeyRing ring = rIt2.next();
            modelAddList2.addElement("" + ring.getSecretKey().getKeyID());
        }

        privatniKljuceviSlanje.setModel(modelAddList2);
    }//GEN-LAST:event_jMenuItem3ActionPerformed

    private void dekriptujActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dekriptujActionPerformed
        FileInputStream in = null;
        try {
            in = new FileInputStream(inputFile.getText());
            FileOutputStream out = new FileOutputStream(outputFile.getText());
            this.decryptFile(in, out, secretKeyCollection, lozinkaPrijem.getText().toCharArray(),publicKeyCollection);
            in.close();
            out.close();
            proveraIntegriteta.setText("Uspeh!");
        } catch (FileNotFoundException ex) {
            pogresnaLozinka.setText(ex.getMessage());
        } catch (Exception ex) {
            pogresnaLozinka.setText(ex.getMessage());
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                in.close();
            } catch (IOException ex) {
                pogresnaLozinka.setText(ex.getMessage());
            }
        }
    }//GEN-LAST:event_dekriptujActionPerformed

    private void jMenuItem4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem4ActionPerformed
        jPanel1.setVisible(false);
        jPanel2.setVisible(false);
        jPanel3.setVisible(false);
        jPanel4.setVisible(true);
        jPanel5.setVisible(false);
    }//GEN-LAST:event_jMenuItem4ActionPerformed

    private void uveziPrivatniActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_uveziPrivatniActionPerformed
        try {
            PGPSecretKeyRing pkr = new PGPSecretKeyRing(new FileInputStream(fileName.getText()), new BcKeyFingerprintCalculator());
            secretKeyCollection = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyCollection, pkr);
            refreshList();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_uveziPrivatniActionPerformed

    private void jMenuItem5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem5ActionPerformed
        jPanel1.setVisible(false);
        jPanel2.setVisible(false);
        jPanel3.setVisible(false);
        jPanel4.setVisible(false);
        jPanel5.setVisible(true);

        refreshList();

    }//GEN-LAST:event_jMenuItem5ActionPerformed

    private void izveziActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_izveziActionPerformed
        try {
            int index = jList1.getSelectedIndex();
            PGPPublicKeyRing ring = null;
            Iterator<PGPPublicKeyRing> rIt = publicKeyCollection.getKeyRings();

            for (int i = 0; i < index + 1; i++) {
                ring = rIt.next();
            }

            /*BufferedOutputStream pubout = new BufferedOutputStream
            (new FileOutputStream(""+jList1.getSelectedValue()+".asc"));
            
            ring.encode(pubout);
            pubout.close();*/
            //PGPSecretKeyRing pkr=new PGPSecretKeyRing(new FileInputStream("secret.asc"),new BcKeyFingerprintCalculator());
            ArmoredOutputStream secretOut = new ArmoredOutputStream(new FileOutputStream("" + jList1.getSelectedValue() + ".asc"));
            ring.encode(secretOut);
            secretOut.close();

        } catch (FileNotFoundException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_izveziActionPerformed

    private void uveziJavniActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_uveziJavniActionPerformed
        try {
            PGPPublicKeyRing pkr = new PGPPublicKeyRing(PGPUtil.getDecoderStream(new FileInputStream(fileName.getText())), new BcKeyFingerprintCalculator());
            publicKeyCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyCollection, pkr);
            refreshList();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_uveziJavniActionPerformed

    private void konverzijaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_konverzijaActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_konverzijaActionPerformed

    private void enkripcijaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_enkripcijaActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_enkripcijaActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new MainFrame().setVisible(true);
            }
        });
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.ButtonGroup buttonGroup2;
    private javax.swing.JButton dekriptuj;
    private javax.swing.JRadioButton des;
    private javax.swing.JCheckBox enkripcija;
    private javax.swing.JTextField fajlSlanje;
    private javax.swing.JTextField fileName;
    private javax.swing.JRadioButton idea;
    private javax.swing.JTextField ime;
    private javax.swing.JLabel imeAutor;
    private javax.swing.JTextField inputFile;
    private javax.swing.JButton izaberiKljuc;
    private javax.swing.JButton izvezi;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel16;
    private javax.swing.JLabel jLabel17;
    private javax.swing.JLabel jLabel18;
    private javax.swing.JLabel jLabel19;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel20;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JList<String> jList1;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenu jMenu3;
    private javax.swing.JMenu jMenu4;
    private javax.swing.JMenu jMenu5;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JMenuItem jMenuItem2;
    private javax.swing.JMenuItem jMenuItem3;
    private javax.swing.JMenuItem jMenuItem4;
    private javax.swing.JMenuItem jMenuItem5;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPasswordField jPasswordField1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JList<String> javniKljuceviSlanje;
    private javax.swing.JTextArea kljucevi;
    private javax.swing.JList<String> kljuceviBrisanje;
    private javax.swing.JCheckBox kompresija;
    private javax.swing.JCheckBox konverzija;
    private javax.swing.JPasswordField lozinka;
    private javax.swing.JPasswordField lozinkaPrijem;
    private javax.swing.JPasswordField lozinkaSlanje;
    private javax.swing.JLabel mailAutora;
    private javax.swing.JTextField mejl;
    private javax.swing.JLabel neispravnaLozinka;
    private javax.swing.JButton obrisi;
    private javax.swing.JTextField outputFile;
    private javax.swing.JDialog passwordDialog;
    private javax.swing.JLabel pogresnaLozinka;
    private javax.swing.JCheckBox potpisivanje;
    private javax.swing.JButton potvrdaGenerisanje;
    private javax.swing.JButton potvrdaSlanje;
    private javax.swing.JList<String> privatniKljuceviSlanje;
    private javax.swing.JLabel proveraIntegriteta;
    private javax.swing.JRadioButton rsa1;
    private javax.swing.JRadioButton rsa2;
    private javax.swing.JRadioButton rsa3;
    private javax.swing.JButton uveziJavni;
    private javax.swing.JButton uveziPrivatni;
    // End of variables declaration//GEN-END:variables

    private void refreshList() {
        DefaultListModel<String> modelAddList = new DefaultListModel();

        Iterator<PGPPublicKeyRing> rIt = publicKeyCollection.getKeyRings();
        while (rIt.hasNext()) {
            PGPPublicKeyRing ring = rIt.next();
            modelAddList.addElement("" + ring.getPublicKey().getKeyID());
        }

        jList1.setModel(modelAddList);
    }

    private void showKeys() {
        String text = "";
        text += "*****PUBLIC KEYS*****\n";

        Iterator<PGPPublicKeyRing> rIt = publicKeyCollection.getKeyRings();
        while (rIt.hasNext()) {
            PGPPublicKeyRing ring = rIt.next();
            Iterator<String> it = ring.getPublicKey().getUserIDs();
            String id = it.next();
            String[] parts = id.split("/");
            String email = parts[0];
            String name = parts[1];
            long longId = ring.getPublicKey().getKeyID();
            int strength = ring.getPublicKey().getBitStrength();
            System.out.println(ring.getPublicKey().getBitStrength());
            text += (email + " " + name + " " + strength + "b " + longId + "\n");
        }

        text += "\n*****PRIVATE KEYS*****\n";

        Iterator<PGPSecretKeyRing> rIt2 = secretKeyCollection.getKeyRings();
        while (rIt2.hasNext()) {
            PGPSecretKeyRing ring = rIt2.next();
            Iterator<String> it = ring.getSecretKey().getUserIDs();
            String id = it.next();
            String[] parts = id.split("/");
            String email = parts[0];
            String name = parts[1];
            long longId = ring.getSecretKey().getKeyID();
            text += (email + " " + name + " " + longId + "\n");
        }

        kljucevi.setText(text);
    }

    private void saveKeyRings() {
        BufferedOutputStream pubout = null;
        try {
            pubout = new BufferedOutputStream(new FileOutputStream("dummy.pkr"));
            publicKeyCollection.encode(pubout);
            pubout.close();
            BufferedOutputStream secout = new BufferedOutputStream(new FileOutputStream("dummy.skr"));
            secretKeyCollection.encode(secout);
            secout.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                pubout.close();
            } catch (IOException ex) {
                Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    @SuppressWarnings("unchecked")
    public static void decryptFile(InputStream in, OutputStream out, PGPSecretKeyRingCollection secretKeyCollection, char[] passwd, PGPPublicKeyRingCollection publicKeyCollection)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
        PGPEncryptedDataList enc;

        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;

        while (sKey == null && it.hasNext()) {
            pbe = it.next();

            sKey = findPrivateKey(secretKeyCollection.getSecretKey(pbe.getKeyID()), passwd);
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

        Object message = plainFact.nextObject();
        if (message instanceof  PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(),new BcKeyFingerprintCalculator());
 
            message = pgpFact.nextObject();
        }
  
        if (message instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;

            InputStream unc = ld.getInputStream();
            int ch;

            while ((ch = unc.read()) >= 0) {
                out.write(ch);
            }
        } else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("Encrypted message contains a signed message - not literal data.");
        } else {
            throw new PGPException("Message is not a simple encrypted file - type unknown.");
        }

        if (pbe.isIntegrityProtected()) {
            if (!pbe.verify()) {
                throw new PGPException("Message failed integrity check");
            }
        }
    }

}
