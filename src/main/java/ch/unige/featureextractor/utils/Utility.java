/*
 * Copyright (c)  Benedetto Marco Serinelli
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package ch.unige.featureextractor.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tika.Tika;
import org.apache.tika.io.IOUtils;

import java.io.*;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class Utility {
  private static final Logger logger = LogManager.getLogger(Utility.class);

  public static boolean isPCAPFile(File file) {
    try {
      if (file == null) {
        logger.error("File null");
        return false;
      }
      String detection = new Tika().detect(file);
      if (detection.equalsIgnoreCase(ExtractorFeaturesModel.pcapTikaExtension)) {
        logger.debug("File is pcap");
        return true;
      }
    } catch (IOException e) {
      logger.error("Error to detect file", e);
    }
    logger.debug("File is not pcap");
    return false;
  }

  public static boolean copyAndLoadLib(String libName, File parentDir) {
    boolean success = false;
    InputStream is = ClassLoader.class.getResourceAsStream(String.format("/native/%s", libName));
    File file = null;
    try {
      file = new File(parentDir.getAbsolutePath() + File.separator + libName);
      file.createNewFile();
      OutputStream os = new FileOutputStream(file);
      byte[] buffer = new byte[1024];
      int length;
      while ((length = is.read(buffer)) != -1) {
        os.write(buffer, 0, length);
      }
      IOUtils.closeQuietly(is);
      IOUtils.closeQuietly(os);
      logger.debug(file.getAbsolutePath());
      System.load(file.getAbsolutePath());
      file.deleteOnExit();
      success = true;
    } catch (IOException e) {
      logger.error("Error to copy and load external lib [" + libName + "]", e);
    }
    return success;
  }

  /*public static void setZeroFieldInCVS(StringBuilder dump, int time) {
    for (int i = 0; i < time; i++) {
      dump.append(0).append(ExtractorFeaturesModel.SEPARATOR);
    }
  }*/

  public static String convertMilliseconds2String(long time, String format) {

    if (format == null) {
      format = "dd/MM/yyyy hh:mm:ss";
    }

    DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format);
    LocalDateTime ldt = LocalDateTime.ofInstant(Instant.ofEpochMilli(time), ZoneId.systemDefault());
    return ldt.format(formatter);
  }
}
