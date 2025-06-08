/* Copyright (c) 2024 */

package com.themathjester;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;

import java.util.ArrayList;
import java.util.Scanner;
import java.util.Arrays;

/* 
 * Checklist - ******FOR EXPORTING PROJECT & DELIVERING TO CLIENT******:
 * 1. Run `mvn package` and ensure everything compiles.
 * 2. Run any applicable tests on the Payload. (Do this step first, because it will be encrypted and you won't be able to debug it!)
 * 3. Move the JAR file to the appropriate directory/name necessary for JAR surgery.
 * 4. Patiently await your next customer's public Key submission.
 * 5. Using the aforementioned public Key, do the JAR surgery that encrypts the Payload.
 * 6. Zip it back up and ship it to that client!
 * 
 */
public class Computations {
  public static double partialSum(int ind) {
    double sum = 1.0;
    for (int term=1; term < ind; term ++) {
      if (term % 2 == 0) {
        sum += 1.0 / (2.0*term + 1);
      } else {
        sum -= 1.0 / (2.0*term + 1);
      }
    }
    return 4.0*sum;
  }
}

