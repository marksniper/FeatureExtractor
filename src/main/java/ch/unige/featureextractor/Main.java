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
package ch.unige.featureextractor;

import ch.unige.featureextractor.utils.ExtractorFeaturesModel;
import ch.unige.featureextractor.utils.Utility;
import ch.unige.featureextractor.utils.file.FileRouterBuilder;
import org.apache.camel.CamelContext;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;

public class Main {
  private static final Logger logger = LogManager.getLogger(Main.class);
  public static CamelContext camelCtx = null;

  public static void main(String[] args) {
    logger.info("Start");
    /*
        prevent tika initializing warnings
        See https://stackoverflow.com/questions/48970160/how-do-i-configure-the-pom-xml-of-tika-to-stop-getting-all-the-license-dependenc
    */
    System.setProperty("tika.config", "tika-config.xml");
    // create runtime lib dir to copy and load native libraries
    File dirLib = new File("lib");
    dirLib.mkdirs();
    dirLib.deleteOnExit();
    // check OS
    if (SystemUtils.IS_OS_LINUX) {
      if (Utility.copyAndLoadLib("libjnetpcap.so", dirLib)) {
        logger.debug("libjnetpcap is loaded");
      } else {
        return;
      }
      if (Utility.copyAndLoadLib("libjnetpcap-pcap100.so", dirLib)) {
        logger.debug("libjnetpcap-pcap100 is loaded");
      } else {
        return;
      }
    } else if (SystemUtils.IS_OS_WINDOWS) {
      if (Utility.copyAndLoadLib("jnetpcap.dll", dirLib)) {
        logger.debug("jnetpcap is loaded");
      } else {
        return;
      }
      if (Utility.copyAndLoadLib("jnetpcap-pcap100.dll", dirLib)) {
        logger.debug("jnetpcap-pcap100 is loaded");
      } else {
        return;
      }
    } else {
      // further OS can be added, the libraries may be compatible
      logger.error("The OS is not supported");
      return;
    }
    /*
     * Loading pcap file from dir
     * Please to set pcap.files.dir in config.properties
     */
    try {
      String folderProp = ExtractorFeaturesModel.rb.getString("pcap.files.source.dir");
      if (StringUtils.isBlank(folderProp)) {
        logger.error("Please to set pcap.files.dir in config.properties");
        return;
      }
    } catch (NullPointerException e) {
      logger.error("Error to open dir", e);
      return;
    }
    camelCtx = new DefaultCamelContext();
    try {
      camelCtx.addRoutes(new FileRouterBuilder());
      camelCtx.start();
      Runtime.getRuntime()
              .addShutdownHook(
                      new Thread(
                              () -> {
                                if (camelCtx != null) {
                                  camelCtx.stop();
                                  logger.info("Stop apache camel");
                                }
                                logger.info("Kill Feature Extractor");
                              }));
      while (true) {
      }
    } catch (Exception e) {
      logger.error("Error to start camel context", e);
    }
  }
}
