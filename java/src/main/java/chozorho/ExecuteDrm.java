/*


https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/SignedFileProcessor.java

 */

package chozorho;


import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;

import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.util.Iterator;


public class ExecuteDrm {

  //static {
  //  Security.addProvider(new BouncyCastleProvider());
  //}

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

    throw new IllegalArgumentException("Can't find signing key in key ring.");
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

}
