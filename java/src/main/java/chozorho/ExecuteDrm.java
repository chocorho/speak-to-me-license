/* Copyright (c) 2024 chozorho
 * 
 * ExecuteDrm
 * A utility class for all the fundamental cryptographic methods used in my DRM scheme.
 * Sources of inspiration include the OpenPGP Examples provided in BouncyCastle repos:
 * https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/SignedFileProcessor.java
 * https://github.com/bcgit/bc-java/blob/main/pg/src/main/java/org/bouncycastle/openpgp/examples/RSAKeyPairGenerator.java
 *
 */

package chozorho;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;

import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;

import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;

import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.encoders.Hex;

import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

import org.bouncycastle.util.io.Streams;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Security;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidAlgorithmParameterException;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;


public class ExecuteDrm {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  /* Method Adapted From Gerald Joshua, under the Apache 2 License */
  public static PGPPrivateKey readSecretKey(String filePath, String pPhrase) throws IOException, PGPException {
    FileInputStream in = new FileInputStream(filePath);
    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
          PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());

    Iterator keyRingIter = pgpSec.getKeyRings();
    while (keyRingIter.hasNext())
    {
      PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();

      Iterator keyIter = keyRing.getSecretKeys();
      while (keyIter.hasNext())
      {
        PGPSecretKey key = (PGPSecretKey)keyIter.next();

        if (key.isSigningKey())
        {
          JcePBESecretKeyDecryptorBuilder decryptorInit = new JcePBESecretKeyDecryptorBuilder();
          PBESecretKeyDecryptor decryptor = decryptorInit/*.setProvider("BC")*/.build(pPhrase.toCharArray());
          return key.extractPrivateKey(decryptor);
//          Iterator userIdIter = key.getUserIDs();
//          while(userIdIter.hasNext()){
//            String userId = (String)userIdIter.next();
//            if (userId.equals("client A"))
//              return key.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("client".toCharArray()));
//          }
        }
      }
    }

    throw new IllegalArgumentException("Unable to find signing key in the given keyring!");
  }

  /**
   * readPublicKey
   * I am literally putting this utility here for testing purposes only, to
   * retrieve reasonable exponent and modulus values for a public PGP key; I do
   * not intend to include it in the final product;
   */
  public static PGPPublicKey readPublicKey(String filePath) throws IOException, PGPException {
    FileInputStream in = new FileInputStream(filePath);
    PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());

    Iterator keyRingIter = pgpRings.getKeyRings();
    while (keyRingIter.hasNext()) {
      PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

      Iterator keyIter = keyRing.getPublicKeys();
      while (keyIter.hasNext()) {
        PGPPublicKey key = (PGPPublicKey)keyIter.next();

        if (key.isEncryptionKey()) {
          return key;
        }
      }
    }
    return null;
  }

  /**
  * Generate an encapsulated signed file.
  *
  * @param fileName
  * 
  * @param out
  * @param pass
  * @param armor
  * @throws IOException
  * @throws NoSuchAlgorithmException
  * @throws NoSuchProviderException
  * @throws PGPException
  * @throws SignatureException
  */
  public static void signFile(
      String          fileName,
      //InputStream     keyIn,
      String          privKeyFileName,
      byte[]          iv,
      OutputStream    out,
      String          pass,
      boolean         armor)
      throws IOException, PGPException
  {
    if (armor)
    {
      out = new ArmoredOutputStream(out);
    }

    PGPPrivateKey pgpPrivKey = readSecretKey(privKeyFileName, pass);
    PGPPublicKey pgpPubKey = new PGPPublicKey(pgpPrivKey.getPublicKeyPacket(), new JcaKeyFingerprintCalculator());
    PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpPrivKey.getPublicKeyPacket().getAlgorithm(), PGPUtil.SHA1)/*.setProvider("BC")*/);

    sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

    Iterator it = pgpPubKey.getUserIDs();
    if (it.hasNext())
    {
      PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

      spGen.addSignerUserID(false, (String)it.next());
      sGen.setHashedSubpackets(spGen.generate());
    }

    PGPCompressedDataGenerator  cGen = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
    BCPGOutputStream            bOut = new BCPGOutputStream(cGen.open(out));
    sGen.generateOnePassVersion(false).encode(bOut);

    File                        file = new File(fileName);
    PGPLiteralDataGenerator     lGen = new PGPLiteralDataGenerator();
    OutputStream                lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
    FileInputStream             fIn = new FileInputStream(file);
    int                         ch;

    //for (int ind=0; ind < iv.length; ind ++) {
    //  System.out.println("[iv debug]    updating the signature generator with another \"character\" (digit): " + (char)iv[ind]);
    //  sGen.update(iv[ind]);
    //}
    while ((ch = fIn.read()) >= 0)
    {
      lOut.write(ch);
      sGen.update((byte)ch);
      System.out.println("[rd debug]    updating the signature generator with another character, " + (char)ch);
    }

    lGen.close();

    sGen.generate().encode(bOut);

    cGen.close();

    if (armor)
    {
      out.close();
    }
  }

  /**
   * testAes
   * "A simple example of AES in CBC mode with block aligned padding."
   * This example function is a mere test, to be removed later.
   * It comes directly from Java Cryptography: Tools and Techniques.
   */
  public static void testAes() throws Exception {
    byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");

    byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7"
                            + "a0a1a2a3a4a5a6a7a0");
    System.out.println("input : " + Hex.toHexString(input));

    byte[] iv = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3");
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

    byte[] output = cipher.doFinal(input);
    System.out.println("encrypted: " + Hex.toHexString(output));

    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

    byte[] finalOutput = new byte[cipher.getOutputSize(output.length)];
    int len = cipher.update(output, 0, output.length, finalOutput, 0);
    len += cipher.doFinal(finalOutput, len);
    System.out.println("decrypted: "
                       + Hex.toHexString(Arrays.copyOfRange(finalOutput, 0, len)));
  }

  /**
   * encryptPayload
   * This is something I wish to run at the END of every "Payload execution"
   * event.
   * There will be times when I need the program to "re-mangle" the Payload à la
   * WannaCry, in order to incentivize the user to Speak To Me again.
   * @param payloadPlaintext the bytes of the plaintext file, which I expect to
   *                         be a .class Java bytecode file extracted from the
   *                         very JAR file that is currently running (pretty
   *                         cool, huh?). However, in general, it could really
   *                         be any plaintext byte array you wish to feed to
   *                         the cipher.
   * @param rpgFlag the symmetric key to be used, which I expect to be a short
   *                sentence that the user uncovers individually as a reward for
   *                Speaking To Me.
   * @param initVector a secondary key that is needed in order for  CBC
   *                   (cipher-block-chaining) to work. I intend treat this as
   *                   another fun little password that is randomly-generated
   *                   and therefore beyond my control.
   */
  public static byte[] encryptPayload(byte[] payloadPlaintext, String rpgFlag, String initVector) throws Exception {
    byte[] keyBytes = Hex.decode(rpgFlag);
    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
    
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
    
    // TODO: consider generating a random Initialization Vector...
    // or use the one provided, which could come directly from themathjester server!
    byte[] iv = Hex.decode(initVector);
    
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
    return cipher.doFinal(payloadPlaintext);
  }

  /**
   * decryptPayload
   * This is something I wish to run at the START of any "Payload execution"
   * event.
   * The program needs to "unmangle" the Payload in order to run it!
   *
   * @param payloadPlaintext the bytes of the plaintext file, which I expect to
   *                         be a .class Java bytecode file extracted from the
   *                         very JAR file that is currently running (pretty
   *                         cool, huh?). However, in general, it could really
   *                         be any plaintext byte array you wish to feed to
   *                         the cipher.
   * @param rpgFlag the symmetric key to be used, which I expect to be a short
   *                sentence that the user uncovers individually as a reward for
   *                Speaking To Me.
   * @param initVector a secondary key that is needed in order for  CBC
   *                   (cipher-block-chaining) to work. I intend treat this as
   *                   another fun little password that is randomly-generated
   *                   and therefore beyond my control.
   */
  public static byte[] decryptPayload(byte[] payloadPlaintext, String rpgFlag, String initVector) throws Exception {
    byte[] keyBytes = Hex.decode(rpgFlag);
    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
    
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
    byte[] iv = Hex.decode(initVector);
    
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
    byte[] finalOutput = new byte[cipher.getOutputSize(payloadPlaintext.length)];
    int len = cipher.update(finalOutput, 0, finalOutput.length, finalOutput, 0);
    len += cipher.doFinal(finalOutput, len);
    
    return finalOutput;
  }

  /**
   * decryptUsingPrivateKey (since version 1.4)
   * a method that will do the "inner layer" step that decrypts a file (or byte
   * array) representing an encrypted Payload, before loading it through the
   * ClassLoader.
   *
   * The method is adapted from *Java Cryptography: Tools and Techniques*.
   * I hope that's not a copyright violation... well, the tweaks and comments
   * make it Fair Use!
   *
   * @param privateKey the PGPPrivateKey object having already been loaded (from
                       a file, with the right passphrase) by the I/O routines.
   * @param ciphertextBytes the bytes of the encrypted Payload
   */
  public static byte[] decryptDataUsingPrivateKey(PGPPrivateKey privateKey, byte[] ciphertextBytes)
    throws IOException {

    PGPObjectFactory ctWrapper = new JcaPGPObjectFactory(ciphertextBytes);

    // nextObject()?? Who would have guessed that was the method we want? What
    // a freaking vague method name
    PGPEncryptedDataList encList = (PGPEncryptedDataList) ctWrapper.nextObject();

    // it's counter-intuitive, but according to the book, we need to "find the
    // matching public key encrypted data packet."
    // presumably, this is a sanity check to confirm that we are applying the
    // right private Key for the given ciphertext block.
    PGPPublicKeyEncryptedData encData = null;
    for (PGPEncryptedData pgpEnc : encList) { // why use the general type?
      PGPPublicKeyEncryptedData pkEnc = (PGPPublicKeyEncryptedData) pgpEnc;
      if (pkEnc.getKeyID() == privateKey.getKeyID()) {
        encData = pkEnc;
        break;
      }
    }
    if (null == encData) {
      throw new IllegalArgumentException("Provided \"ciphertext\" does not correspond to the selected Private Key!");
    }

    // now for the good stuff. Using the Key to decrypt the byte array!
    PublicKeyDataDecryptorFactory dataDecryptor = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey);

    // plaintext Stream, as influenced by the encData and the "decryptor" that
    // wraps the Private Key.
    // who'd have thought this would be a method call on the
    // PGPPublicKeyEncryptedData??? It makes no sense!
    try {
      InputStream ptStream = encData.getDataStream(dataDecryptor);
      byte[] literalPacketBytes = Streams.readAll(ptStream);
      ptStream.close();

      // finally we "check [that the] data decrypts okay"
      if (encData.verify()) {
        // ...and "parse out literal data."
        PGPObjectFactory litFact = new JcaPGPObjectFactory(literalPacketBytes);
        PGPLiteralData litData = (PGPLiteralData) litFact.nextObject();
        byte[] ptBytes = Streams.readAll(litData.getInputStream());
        return ptBytes;
      }
    } catch (PGPException e) {
      System.out.println("Decryption stage failed!");
      e.printStackTrace();
    }
    throw new IllegalStateException("modification check failed");
  }

  /**
   * readRsaKey
   * A demo to help me extract exponent data in order to do Key Generation.
   * @param privateKeyFilename the filename of the Private Key, with which to
                               extract a Public Key.
   * @return data about the corresponding Public Key.
   */
  public static BigInteger readRsaKey(String publicKeyFilename/*, String pPhrase*/) {
    try {
      // FIXME this implementation has runtime errors!!!
      // the traditional way of getting the public key is as follows:
      //PGPPublicKey pgpPrivKey = readPublicKey(publicKeyFilename);
      // however, this OpenPGP type does not inherit from RSAPublicKey and thus does not provide
      // .getPublicExponent() or .getModulus()
      RSAPublicBCPGKey pk = new RSAPublicBCPGKey(new BCPGInputStream(new FileInputStream(publicKeyFilename)));
      System.out.println("Key exponent looks like " + pk.getPublicExponent() + "; modulus is " + pk.getModulus());
      return pk.getPublicExponent();
    } catch (FileNotFoundException exc) {
      System.out.println("Requested public key File cannot be found!");
      exc.printStackTrace();
    } catch (IOException exc) {
      System.out.println("IO exception... can we not read any files? Does the directory not exist?");
      exc.printStackTrace();
    }
    return null;
  }

  private static final int SIG_HASH = HashAlgorithmTags.SHA512;
  private static final int[] HASH_PREFERENCES = new int[]{
      HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA224
  };
  private static final int[] SYM_PREFERENCES = new int[]{
      SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128
  };
  private static final int[] COMP_PREFERENCES = new int[]{
      CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2, CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.UNCOMPRESSED
  };

  public static void generateAndExportKeyRing(
      OutputStream secretOut,
      OutputStream publicOut,
      String identity,
      char[] passPhrase,
      boolean armor)
      throws IOException, NoSuchProviderException, PGPException, NoSuchAlgorithmException
  {
    if (armor)
    {
      secretOut = new ArmoredOutputStream(secretOut);
    }

    PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

    PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, SIG_HASH).setProvider("BC");
    PBESecretKeyEncryptor secretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, sha1Calc).setProvider("BC")
        .build(passPhrase);

    Date now = new Date();

    kpg.initialize(3072);
    KeyPair primaryKP = kpg.generateKeyPair();
    PGPKeyPair primaryKey = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, primaryKP, now);
    PGPSignatureSubpacketGenerator primarySubpackets = new PGPSignatureSubpacketGenerator();
    primarySubpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER);
    primarySubpackets.setPreferredHashAlgorithms(false, HASH_PREFERENCES);
    primarySubpackets.setPreferredSymmetricAlgorithms(false, SYM_PREFERENCES);
    primarySubpackets.setPreferredCompressionAlgorithms(false, COMP_PREFERENCES);
    primarySubpackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
    primarySubpackets.setIssuerFingerprint(false, primaryKey.getPublicKey());

    kpg.initialize(3072);
    KeyPair signingKP = kpg.generateKeyPair();
    PGPKeyPair signingKey = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, signingKP, now);
    PGPSignatureSubpacketGenerator signingKeySubpacket = new PGPSignatureSubpacketGenerator();
    signingKeySubpacket.setKeyFlags(true, KeyFlags.SIGN_DATA);
    signingKeySubpacket.setIssuerFingerprint(false, primaryKey.getPublicKey());

    kpg.initialize(3072);
    KeyPair encryptionKP = kpg.generateKeyPair();
    PGPKeyPair encryptionKey = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, encryptionKP, now);
    PGPSignatureSubpacketGenerator encryptionKeySubpackets = new PGPSignatureSubpacketGenerator();
    encryptionKeySubpackets.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
    encryptionKeySubpackets.setIssuerFingerprint(false, primaryKey.getPublicKey());

    PGPKeyRingGenerator gen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, primaryKey, identity,
        sha1Calc, primarySubpackets.generate(), null, contentSignerBuilder, secretKeyEncryptor);
    gen.addSubKey(signingKey, signingKeySubpacket.generate(), null, contentSignerBuilder);
    gen.addSubKey(encryptionKey, encryptionKeySubpackets.generate(), null);

    PGPSecretKeyRing secretKeys = gen.generateSecretKeyRing();
    secretKeys.encode(secretOut);

    secretOut.close();

    if (armor)
    {
      publicOut = new ArmoredOutputStream(publicOut);
    }

    List<PGPPublicKey> publicKeyList = new ArrayList<PGPPublicKey>();
    Iterator<PGPPublicKey> it = secretKeys.getPublicKeys();
    while (it.hasNext())
    {
      publicKeyList.add(it.next());
    }

    PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(publicKeyList);
    publicKeys.encode(publicOut);
    publicOut.close();
  }

  /**
   * createNewRsaKey
   * The back-end implementation of Mode 0, the creation of a new valid RSA Key Pair.
   */
  public static KeyPair createNewRsaKey() {
    try {
      KeyPairGenerator k = KeyPairGenerator.getInstance("RSA", "BC");
      k.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
      return k.generateKeyPair();
    } catch (NoSuchProviderException exc) {
      System.out.println("Provider, presumably BouncyCastle, cannot be found!");
      exc.printStackTrace();
    } catch (NoSuchAlgorithmException exc) {
      System.out.println("Algorithm, presumably RSA, cannot be found!");
      exc.printStackTrace();
    } catch (InvalidAlgorithmParameterException exc2) {
      System.out.println("Algorithm Parameter, presumably the bit length or the exponent 65537, cannot be used!");
      exc2.printStackTrace();
    }
    return null;
  }

}
