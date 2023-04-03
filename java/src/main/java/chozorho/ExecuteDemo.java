/* 
 * The Finance Parser Program (FPP).
 * COPYRIGHT (c) 2023 chozorho A.K.A. chocorho
 * Yea, you read that right. It's copyrighted.
 * Adapted from the original program from 2016.
 */
package chozorho;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;

import org.bouncycastle.gpg.SExprParser;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentSigner;

import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;

import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import org.openqa.selenium.WebDriver;
/*import org.openqa.selenium.chrome.ChromeDriver;*/
import org.openqa.selenium.By;
/*import org.openqa.selenium.By.ById;
import org.openqa.selenium.By.ByTagName;*/
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.WebElement;
/*import org.openqa.selenium.remote.RemoteWebElement;*/

/* NEW IDEA *
 * use Selenium, since it has a simple api and also uses the Apache license!!! */

public class ExecuteDemo
{

  
  public static void main(String[] args)
  {
/*    HttpClientBuilder authenticatorBuilder = HttpClientBuilder.getInstance();*/
    
    FirefoxOptions customGeckoOpt = new FirefoxOptions();
    customGeckoOpt.addArguments("--headless");
    
    FirefoxDriver browser = new FirefoxDriver(customGeckoOpt);
    
    int codeval = 928258;
    browser.get("https://www.themathjester.com/speak-to-me-verification.php");
    List<WebElement> sources = browser.findElements(new By.ByTagName("input"));
    for (WebElement e : sources) {
      String name_val = e.getAttribute("name");
      if (name_val != null && name_val.equals("sixDigitCode")) {
        codeval = Integer.parseInt(e.getAttribute("value"));
      }
    }
    System.out.println(codeval);
    Calendar today_date = Calendar.getInstance();
    Date timestamp = today_date.getTime();
    Scanner input = new Scanner(System.in);
    System.out.println("Please enter the location of YOUR private key (this is secret!)");
    System.out.print("> ");
    String privateKeyFileName = input.nextLine();
    System.out.println("Please enter YOUR secret passphrase to uncover the key, or an empty string if not applicable.");
    System.out.print("> ");
    String passphrase = input.nextLine();
    System.out.println("Please enter YOUR username that you sent (or received) from the Lead Developer.");
    System.out.print("> ");
    String username = input.nextLine();
    boolean drmFails = true;
    
    /* step 3. init nested BouncyCastle PGP objects */
    
    try {
/*    if (phrase.equals("")) {
      //signed = loaded_key.sign(str(codeval));
      System.out.println("Today\'s date has been read as " + r);
      System.out.println("finished writing signed (binary) file.");
    } else { */
      //SExprParser keyDecrypter = new SExprParser(digestSelector);
      //File privKeyFileAttempt = new File(privateKeyFileName);
      //FileInputStream privKeyInputStream = new FileInputStream(privKeyFileAttempt);
      
/*      JcePBEProtectionRemoverFactory unlocker = new JcePBEProtectionRemoverFactory(passphrase.toCharArray());
      BcKeyFingerprintCalculator fingerprintCalc = new BcKeyFingerprintCalculator();
      PGPSecretKey decryptedSecretKey = keyDecrypter.parseSecretKey(privKeyInputStream, unlocker, fingerprintCalc);
      if (! decryptedSecretKey.isSigningKey()) {
        System.out.println("[WARNING]    Key not suitable for signing.");
      }
      
      BcPBESecretKeyDecryptorBuilder secretToPrivateConverterBuild = new BcPBESecretKeyDecryptorBuilder(digestSelector);
      PBESecretKeyDecryptor keyConverter = secretToPrivateConverterBuild.build(passphrase.toCharArray());*/
      
      /*
       *   - keyAlgCode (PGPPublicKey.RSA_GENERAL)
       *   - signatureCode (PGPSignature.BINARY_DOCUMENT)
       */
      BcPGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(PGPPublicKey.RSA_GENERAL, PGPUtil.SHA256);
/*      PGPPrivateKey originalPrivKeyReading = decryptedSecretKey.extractPrivateKey(keyConverter);
      PGPContentSigner originalSigner = signerBuilder.build(PGPSignature.BINARY_DOCUMENT, originalPrivKeyReading);
      byte[] result = originalSigner.getSignature();*/
      //PGPPrivateKey alternatePrivKeyReading = ExecuteDrm.readSecretKey(privateKeyFileName, passphrase);
      //PGPContentSigner alternateSigner = signerBuilder.build(PGPSignature.BINARY_DOCUMENT, alternatePrivKeyReading);
      
      /* Define all relevant outputstreams */
      //OutputStream plainTextMessenger = alternateSigner.getOutputStream();
      
/*    }*/
      String outputFileName = "signature"+timestamp.getTime();
      File outputFile = new File(outputFileName);

      /* Look, I would have **thought** that we needed to define this FileOutputStream
       * ahead of time, supply the reference as a parameter to future BCPGP constructors & methods,
       * and then write to the same exact FileOutputStream that we just supplied.
       * After all, Java passes objects by reference, so if the DataGenerator's open() function does some fancy
       * operations on the stream (presumably setting magic bytes and so forth), then we can still reuse
       * the same reference afterward in order to set its data!
       * 
       * Brilliant, right?
       * 
       * Well, apparently that's not good enough, because as of 2022-07-17, it appears that they want us to
       * pass in an OutputStream, while returning another OutputStream!
       * 
       * Q: Why the need for two different references -- if they're presumably going to point to the
       * exact same OutputStream object?
       * A: Beats me.
       * 
       * -VC, 2022-07-17
       */
      FileOutputStream plainTextMessenger = new FileOutputStream(outputFile);
      byte[] plainBytes = (new String(""+codeval)).getBytes();
      //outputFile.close();
      plainTextMessenger.write((new String(""+codeval)).getBytes());
      plainTextMessenger.close();
      plainTextMessenger = new FileOutputStream(outputFileName+".gpg");
      ExecuteDrm.signFile(outputFileName,
                          privateKeyFileName,
                          plainBytes,
                          plainTextMessenger,
                          passphrase,
                          false);
      
      PGPLiteralDataGenerator packetManager = new PGPLiteralDataGenerator();
      byte[] binarySignatureByteBuffer = new byte[4096];
      OutputStream packetMgrOutput = packetManager.open(plainTextMessenger,
                                                        PGPLiteralDataGenerator.BINARY,
                                                        outputFileName,
                                                        timestamp,
                                                        binarySignatureByteBuffer);
      packetMgrOutput.close();
      PGPOnePassSignature signBytes;
      
      System.out.println("finished writing signed (binary) file with decrypted key!");
      
      plainTextMessenger.close();
      
      // use Selenium to automate the task of uploading the file!
      WebElement fileWebUpload = browser.findElement(new By.ById("signedBinary"));
      outputFileName = "signature"+timestamp.getTime()+".gpg";
      outputFile = new File(outputFileName);
      fileWebUpload.sendKeys(outputFile.getAbsolutePath().toString());
      WebElement nameWebInput = browser.findElement(new By.ById("username"));
      nameWebInput.sendKeys(username);
      browser.findElement(new By.ById("submitBinary")).click();
      
      System.out.print(browser.getPageSource());
      
      List<WebElement> headings = browser.findElements(new By.ByTagName("h1"));
      for (WebElement e : headings) {
        if (e.getText().equalsIgnoreCase("ACCEPTED")) {
          System.out.println("DRM cracked!!");
          drmFails = false;
        }
      }
    } catch (FileNotFoundException noFileError) {
      System.out.println(noFileError.toString());
      noFileError.printStackTrace();
    } catch (IOException ioError) {
      System.out.println(ioError.toString());
      ioError.printStackTrace();
    } catch (PGPException e) {
      System.out.println("PGP Key exception... perhaps there was a problem with a wrong passphrase, incorrect file type, or inability to sign the given message.");
      System.out.println("Try again, and if it still fails, contact chocorho, attaching your username, public key, and any relevant details about your platform.");
      e.printStackTrace();
    }
    
    if (drmFails) {
      System.out.println("Fatal Error: DRM check failed!");
      System.out.println("");
      System.out.println("chozorho is sick and tired of people refusing to talk to him about technical topics.");
      System.out.println("Therefore, in order to run this software, you must abide by the attached Speak-To-Me License.");
      System.out.println("That is, you must contact chozorho directly ahead of time.");
      System.out.println("Send him your public key in order to become an authorized user!");
      browser.close();
      return;
    }
    browser.close();
    System.out.println("Program terminated.");
  }
}

