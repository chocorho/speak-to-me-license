/* Copyright (c) chozorho
 * 
 * A file to collect any and all JAR utilities that will be needed by the DRM
 * Client.
 * This will enable modifying the JAR file in preparation for the next time it
 * is run.
 */

package chozorho;

import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.zip.ZipException;
import java.io.IOException;

import java.lang.ClassNotFoundException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.SecurityException;

import io.github.micwan88.helperclass4j.ByteClassLoader;

import org.bouncycastle.openpgp.PGPPrivateKey;


public class JarUtils {

  /**
   * An initial utility that returns true if and only if the JAR file (with the
   * associated InputStream) is expected to contain any PGP-encrypted files.
   * This general approach was derived from the methods documented in the Oracle
   * documentation, but was confirmed by mkyong in his MIT-licensed method to
   * extract files from a ZIP archive. Sources:
   *
   * https://docs.oracle.com/javase/8/docs/api/java/util/jar/JarInputStream.html#getNextJarEntry--
   * https://mkyong.com/java/how-to-decompress-files-from-a-zip-file/
   *
   * @param stream
   * @return true if and only if the JAR contains a .gpg component
   */
  public static boolean containsEncryptedData(JarInputStream stream) {
    try {
      JarEntry nextE = stream.getNextJarEntry();
      while (null != nextE) {
        String jarElementName = nextE.getName();
        //System.out.println("now visiting "+jarElementName);
        if (nextE.isDirectory()) {
          nextE = stream.getNextJarEntry();
          continue;
        } else if (jarElementName.endsWith(".gpg")) {
          // attempt 1 failed.
          //int bufferSize = (int)nextE.getSize();
          //byte[] pt = new byte[bufferSize];
          //stream.read(pt, 0,  bufferSize);
          return true;
        }
        nextE = stream.getNextJarEntry();
      }
    } catch (ZipException error) {
      error.printStackTrace();
    } catch (IOException error) {
      error.printStackTrace();
    } catch (SecurityException error) {
      error.printStackTrace();
    }
    return false;
  }

  public static boolean extractEncryptZip(JarInputStream stream, String payloadFileName, PGPPrivateKey privKey) {
    boolean foundPayload = false;
    try {
      JarEntry nextE = stream.getNextJarEntry();
      while (null != nextE) {
        String jarElementName = nextE.getName();
        //System.out.println("now visiting "+jarElementName);
        if (nextE.isDirectory()) {
          nextE = stream.getNextJarEntry();
          continue;
        } else if (jarElementName.endsWith(payloadFileName)) {
          System.out.println("  MATCH FOUND! "+jarElementName+" indeed ends with "+payloadFileName);
          // attempt 1 failed.
          // size is unknown... we need to uncompress it first, I bet!
          int bufferSize = 99999999;
          byte[] pt = new byte[bufferSize];
          stream.read(pt, 0, bufferSize);
          if (jarElementName.endsWith(".gpg") && null != privKey) {
            // TODO decide what we're doing here for version 1.4+
            // Is it worth using AES, like we might do in the Real Deal Version
            // 2.0 DRM?
            // if so, how will we encrypt using AES and an init vector?
            // Can `gpg` do this, or do I need to add a "secret feature" for the
            // JAR to encrypt the payload with a rpgFlag and an initVector first?
            /*
             * The program needs to "unmangle" the Payload in order to run it!
             * But recall that the terminal utility `gpg` uses an IV of zeroes when doing
             * symmetric encryption and then wraps the result (or something?) using CFB
             * rather than CBC. Maybe we will not be able to use gpg specifically to
             * prepare our JAR files after all! We'll have to rely on other programs, like
             * these Java methods, or some server-side PHP scripts, instead. */
            // Otherwise, use regular PGP decyption ... one would think you can
            // find an Example for that in bc-java. But can we?
            System.out.println("encryption step was necessary after all.");
            pt = ExecuteDrm.decryptDataUsingPrivateKey(privKey, pt);
          } else {
            System.out.println("circumventing the decryption step!");
          }
          pickUpExternalClass(pt);
          foundPayload = true;
        }
        nextE = stream.getNextJarEntry();
      }
    } catch (ZipException error) {
      error.printStackTrace();
    } catch (IOException error) {
      error.printStackTrace();
    } catch (SecurityException error) {
      error.printStackTrace();
    }
    return foundPayload;
  }

  public static Class loadNewClass(String name) {
    return Double.class;
  }

  private static void pickUpExternalClass(byte[] ptBytes) {
    ByteClassLoader customLoader = new ByteClassLoader(ExecuteDemo.class.getClassLoader());
    customLoader.loadSingleFileDataInBytes(ptBytes, "com.themathjester.Computations");
    try {
      Class ptClass = customLoader.loadClass("com.themathjester.Computations", ptBytes, false);
      System.out.println("Just successfully called loadClass!");
      for (Method nextMethodCandidate : ptClass.getMethods()) {
        if (nextMethodCandidate.getName().equals("partialSum")) {
          Integer bound = new Integer(20000);
          Object output = nextMethodCandidate.invoke(null, bound);
          Double castOutput = Double.class.cast(output);
          System.out.println("output of god mode appears to be " + castOutput.toString());
        }
      }
    } catch (ClassNotFoundException ex) {
      ex.printStackTrace();
    } catch (IOException ex) {
      ex.printStackTrace();
    } catch (ClassCastException e) {
      System.out.println("scary stuff is happening. Return type is unexpected!");
    } catch (IllegalAccessException e) {
      System.out.println("Illegal Access... is the Payload's method public? Double check it.");
      e.printStackTrace();
    } catch (InvocationTargetException e) {
      System.out.println("Invocation Target Exception... what does this mean?");
      e.printStackTrace();
    }
    
  }

}

