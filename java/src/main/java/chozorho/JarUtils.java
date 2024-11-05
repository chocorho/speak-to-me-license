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
import java.lang.SecurityException;

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

}

