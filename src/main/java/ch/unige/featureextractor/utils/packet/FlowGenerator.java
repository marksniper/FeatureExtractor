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

import ch.unige.featureextractor.Main;
import ch.unige.featureextractor.utils.ExtractorFeaturesModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tika.io.IOUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.ResourceBundle;

public class FlowGenerator {
  private static final Logger logger = LogManager.getLogger(Main.class);
  private final boolean bidirectional;
  private final long flowTimeOut;
  private final long flowActivityTimeOut;
  private HashMap<String, BasicFlow> currentFlows;
  private HashMap<Integer, BasicFlow> finishedFlows;
  private HashMap<String, ArrayList> IPAddresses;
  private int finishedFlowCount;

  public FlowGenerator(boolean bidirectional, long flowTimeout, long activityTimeout) {
    super();
    this.bidirectional = bidirectional;
    this.flowTimeOut = flowTimeout;
    this.flowActivityTimeOut = activityTimeout;
    init();
  }

  private void init() {
    currentFlows = new HashMap<>();
    finishedFlows = new HashMap<>();
    IPAddresses = new HashMap<>();
    finishedFlowCount = 0;
  }

  public void addPacket(BasicPacketInfo packet) {
    if (packet == null) {
      return;
    }

    BasicFlow flow;
    long currentTimestamp = packet.getTimeStamp();
    String id = "";

    if (this.currentFlows.containsKey(packet.fwdFlowId())
            || this.currentFlows.containsKey(packet.bwdFlowId())) {

      if (this.currentFlows.containsKey(packet.fwdFlowId())) {
        id = packet.fwdFlowId();
      } else {
        id = packet.bwdFlowId();
      }

      flow = currentFlows.get(id);
      if ((currentTimestamp - flow.getFlowStartTime()) > flowTimeOut) {
        currentFlows.remove(id);
        currentFlows.put(
                id,
                new BasicFlow(
                        bidirectional,
                        packet,
                        flow.getSrc(),
                        flow.getDst(),
                        flow.getSrcPort(),
                        flow.getDstPort()));

        int cfsize = currentFlows.size();
        if (cfsize % 50 == 0) {
          logger.debug("Timeout current has {} flow", cfsize);
        }

        // Flow finished due FIN flag (tcp only):
        // 1.- we add the packet-in-process to the flow (it is the last packet)
        // 2.- we move the flow to finished flow list
        // 3.- we eliminate the flow from the current flow list
      } else if (packet.hasFlagFIN()) {
        logger.debug("FlagFIN current has {} flow", currentFlows.size());
        flow.addPacket(packet);
        /*if (mListener != null) {
            mListener.onFlowGenerated(flow);
        } else {
            finishedFlows.put(getFlowCount(), flow);
        }*/
        currentFlows.remove(id);
      } else {
        flow.updateActiveIdleTime(currentTimestamp, this.flowActivityTimeOut);
        flow.addPacket(packet);
        currentFlows.put(id, flow);
      }
    } else {
      currentFlows.put(packet.fwdFlowId(), new BasicFlow(bidirectional, packet));
    }
  }

  public long dumpLabeledCurrentFlow(String fileFullPath, String header, ResourceBundle rb) {
    if (fileFullPath == null || header == null) {
      String ex = String.format("fullFilePath=%s,filename=%s", fileFullPath);
      throw new IllegalArgumentException(ex);
    }

    File file = new File(fileFullPath);
    FileOutputStream output = null;
    int total = 0;

    try {
      output = new FileOutputStream(file, true);
      output.write((header + ExtractorFeaturesModel.LINE_SEP).getBytes());

      for (BasicFlow flow : currentFlows.values()) {
        if (flow.packetCount() > 1) {
          output.write(
                  (flow.dumpFlowBasedFeaturesEx(rb) + ExtractorFeaturesModel.LINE_SEP).getBytes());
          total++;
        }
      }
    } catch (IOException e) {
      logger.debug(e.getMessage());
    } finally {
      try {
        if (output != null) {
          output.flush();
          IOUtils.closeQuietly(output);
        }
      } catch (IOException e) {
        logger.debug(e.getMessage());
      }
    }
    return total;
  }

  private int getFlowCount() {
    this.finishedFlowCount++;
    return this.finishedFlowCount;
  }
}
