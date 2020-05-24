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
package ch.unige.featureextractor.utils.packet;

import ch.unige.featureextractor.utils.ExtractorFeaturesModel;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tika.io.IOUtils;
import org.jnetpcap.PcapClosedException;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;
import java.nio.file.Paths;
import java.util.ResourceBundle;
import java.util.UUID;

public class PacketLoader {

  private static final Logger logger = LogManager.getLogger(PacketLoader.class);

  public static void extractorFeatures(File pcap) {
    String kindExtractor = ExtractorFeaturesModel.rb.getString("extractfeatures.kind.extractor");
    String[] extractors = kindExtractor.split(";");
    for (String extractor : extractors) {
      try {
        ResourceBundle rb = ResourceBundle.getBundle(extractor);
        extractorWorker(pcap, rb);
      } catch (Exception e) {
        logger.error("Error to load extractor [" + extractor + "]", e);
      }
    }
  }

  private static void extractorWorker(File pcap, ResourceBundle rb) {
    long flowTimeout = 120000000L;
    long activityTimeout = 5000000L;
    String folderProp = rb.getString("csv.output.dir");
    logger.debug("Set [" + folderProp + "]");
    if (StringUtils.isBlank(folderProp)) {
      logger.warn("Set correctly the \"pcap.files.dir\" properties");
      folderProp = Paths.get("").toAbsolutePath().toString();
      logger.warn("Set current dir [" + folderProp + "]");
    }
    String outFile =
            folderProp
                    + File.separator
                    + UUID.randomUUID().toString()
                    + ExtractorFeaturesModel.CSV_SUFFIX;
    File out = new File(outFile);
    out.getParentFile().mkdirs();
    if (!out.exists()) {
      try {
        out.createNewFile();
      } catch (IOException e) {
        logger.error("Error to create [" + outFile + "]", e);
      }
    }
    readPcapFile(pcap.getAbsolutePath(), out.getAbsolutePath(), flowTimeout, activityTimeout, rb);
  }

  private static void readPcapFile(
          String inputFile, String outPath, long flowTimeout, long activityTimeout, ResourceBundle rb) {

    FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
    boolean readIP6 = false;
    boolean readIP4 = true;
    PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);

    int nValid = 0;
    int nTotal = 0;
    int nDiscarded = 0;
    long start = System.currentTimeMillis();
    int i = 0;
    while (true) {
      try {
        BasicPacketInfo basicPacket = packetReader.nextPacket();
        nTotal++;
        if (basicPacket != null) {
          flowGen.addPacket(basicPacket);
          nValid++;
        } else {
          nDiscarded++;
        }
      } catch (PcapClosedException e) {
        break;
      }
      i++;
    }
    File saveFileFullPath = new File(outPath);
    flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader(rb), rb);
  }

  public static long countLines(String fileName) {
    File file = new File(fileName);
    int linenumber = 0;
    FileReader fr;
    LineNumberReader lnr = null;
    try {
      fr = new FileReader(file);
      lnr = new LineNumberReader(fr);

      while (lnr.readLine() != null) {
        linenumber++;
      }
    } catch (IOException e) {
      logger.error(e.getMessage());
    } finally {
      if (lnr != null) {
        IOUtils.closeQuietly(lnr);
      }
    }
    return linenumber;
  }
}
