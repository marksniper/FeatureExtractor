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
import ch.unige.featureextractor.utils.Utility;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.jnetpcap.packet.format.FormatUtils;

import java.util.*;

public class BasicFlow {
  private final boolean isBidirectional;
  private final long fbulkDuration = 0;
  private final long fbulkPacketCount = 0;
  private final long fbulkSizeTotal = 0;
  private final long fbulkStateCount = 0;
  private final long flastBulkTS = 0;
  private SummaryStatistics fwdPktStats = null;
  private SummaryStatistics bwdPktStats = null;
  private List<BasicPacketInfo> forward = null;
  private List<BasicPacketInfo> backward = null;
  private long forwardBytes;
  private long backwardBytes;
  private long fHeaderBytes;
  private long bHeaderBytes;
  private HashMap<String, MutableInt> flagCounts;
  private int fPSH_cnt;
  private int bPSH_cnt;
  private int fURG_cnt;
  private int bURG_cnt;
  private long Act_data_pkt_forward;
  private long min_seg_size_forward;
  private int Init_Win_bytes_forward = 0;
  private int Init_Win_bytes_backward = 0;
  private byte[] src;
  private byte[] dst;
  private int srcPort;
  private int dstPort;
  private int protocol;
  private long flowStartTime;
  private long startActiveTime;
  private long endActiveTime;
  private String flowId = null;
  private SummaryStatistics flowIAT = null;
  private SummaryStatistics forwardIAT = null;
  private SummaryStatistics backwardIAT = null;
  private SummaryStatistics flowLengthStats = null;
  private SummaryStatistics flowActive = null;
  private SummaryStatistics flowIdle = null;
  private long flowLastSeen;
  private long forwardLastSeen;
  private long backwardLastSeen;
  private long sfLastPacketTS = -1;
  private int sfCount = 0;
  private long bbulkDuration = 0;
  private long bbulkPacketCount = 0;
  private long bbulkSizeTotal = 0;
  private long bbulkStateCount = 0;
  private long bbulkPacketCountHelper = 0;
  private long bbulkStartHelper = 0;
  private long bbulkSizeHelper = 0;
  private long blastBulkTS = 0;

  public BasicFlow(
          boolean isBidirectional,
          BasicPacketInfo packet,
          byte[] flowSrc,
          byte[] flowDst,
          int flowSrcPort,
          int flowDstPort) {
    super();
    this.initParameters();
    this.isBidirectional = isBidirectional;
    this.firstPacket(packet);
    this.src = flowSrc;
    this.dst = flowDst;
    this.srcPort = flowSrcPort;
    this.dstPort = flowDstPort;
  }

  public BasicFlow(boolean isBidirectional, BasicPacketInfo packet) {
    super();
    this.initParameters();
    this.isBidirectional = isBidirectional;
    this.firstPacket(packet);
  }

  public void initParameters() {
    this.forward = new ArrayList<>();
    this.backward = new ArrayList<>();
    this.flowIAT = new SummaryStatistics();
    this.forwardIAT = new SummaryStatistics();
    this.backwardIAT = new SummaryStatistics();
    this.flowActive = new SummaryStatistics();
    this.flowIdle = new SummaryStatistics();
    this.flowLengthStats = new SummaryStatistics();
    this.fwdPktStats = new SummaryStatistics();
    this.bwdPktStats = new SummaryStatistics();
    this.flagCounts = new HashMap<>();
    initFlags();
    this.forwardBytes = 0L;
    this.backwardBytes = 0L;
    this.startActiveTime = 0L;
    this.endActiveTime = 0L;
    this.src = null;
    this.dst = null;
    this.fPSH_cnt = 0;
    this.bPSH_cnt = 0;
    this.fURG_cnt = 0;
    this.bURG_cnt = 0;
    this.fHeaderBytes = 0L;
    this.bHeaderBytes = 0L;
  }

  public void firstPacket(BasicPacketInfo packet) {
    updateFlowBulk(packet);
    detectUpdateSubflows(packet);
    checkFlags(packet);
    this.flowStartTime = packet.getTimeStamp();
    this.flowLastSeen = packet.getTimeStamp();
    this.startActiveTime = packet.getTimeStamp();
    this.endActiveTime = packet.getTimeStamp();
    this.flowLengthStats.addValue((double) packet.getPayloadBytes());

    if (this.src == null) {
      this.src = packet.getSrc();
      this.srcPort = packet.getSrcPort();
    }
    if (this.dst == null) {
      this.dst = packet.getDst();
      this.dstPort = packet.getDstPort();
    }
    if (Arrays.equals(this.src, packet.getSrc())) {
      this.min_seg_size_forward = packet.getHeaderBytes();
      Init_Win_bytes_forward = packet.getTCPWindow();
      this.flowLengthStats.addValue((double) packet.getPayloadBytes());
      this.fwdPktStats.addValue((double) packet.getPayloadBytes());
      this.fHeaderBytes = packet.getHeaderBytes();
      this.forwardLastSeen = packet.getTimeStamp();
      this.forwardBytes += packet.getPayloadBytes();
      this.forward.add(packet);
      if (packet.hasFlagPSH()) {
        this.fPSH_cnt++;
      }
      if (packet.hasFlagURG()) {
        this.fURG_cnt++;
      }
    } else {
      Init_Win_bytes_backward = packet.getTCPWindow();
      this.flowLengthStats.addValue((double) packet.getPayloadBytes());
      this.bwdPktStats.addValue((double) packet.getPayloadBytes());
      this.bHeaderBytes = packet.getHeaderBytes();
      this.backwardLastSeen = packet.getTimeStamp();
      this.backwardBytes += packet.getPayloadBytes();
      this.backward.add(packet);
      if (packet.hasFlagPSH()) {
        this.bPSH_cnt++;
      }
      if (packet.hasFlagURG()) {
        this.bURG_cnt++;
      }
    }
    this.protocol = packet.getProtocol();
    this.flowId = packet.getFlowId();
  }

  public void addPacket(BasicPacketInfo packet) {
    updateFlowBulk(packet);
    detectUpdateSubflows(packet);
    checkFlags(packet);
    long currentTimestamp = packet.getTimeStamp();
    if (isBidirectional) {
      this.flowLengthStats.addValue((double) packet.getPayloadBytes());

      if (Arrays.equals(this.src, packet.getSrc())) {
        if (packet.getPayloadBytes() >= 1) {
          this.Act_data_pkt_forward++;
        }
        this.fwdPktStats.addValue((double) packet.getPayloadBytes());
        this.fHeaderBytes += packet.getHeaderBytes();
        this.forward.add(packet);
        this.forwardBytes += packet.getPayloadBytes();
        if (this.forward.size() > 1)
          this.forwardIAT.addValue(currentTimestamp - this.forwardLastSeen);
        this.forwardLastSeen = currentTimestamp;
        this.min_seg_size_forward = Math.min(packet.getHeaderBytes(), this.min_seg_size_forward);

      } else {
        this.bwdPktStats.addValue((double) packet.getPayloadBytes());
        Init_Win_bytes_backward = packet.getTCPWindow();
        this.bHeaderBytes += packet.getHeaderBytes();
        this.backward.add(packet);
        this.backwardBytes += packet.getPayloadBytes();
        if (this.backward.size() > 1)
          this.backwardIAT.addValue(currentTimestamp - this.backwardLastSeen);
        this.backwardLastSeen = currentTimestamp;
      }
    } else {
      if (packet.getPayloadBytes() >= 1) {
        this.Act_data_pkt_forward++;
      }
      this.fwdPktStats.addValue((double) packet.getPayloadBytes());
      this.flowLengthStats.addValue((double) packet.getPayloadBytes());
      this.fHeaderBytes += packet.getHeaderBytes();
      this.forward.add(packet);
      this.forwardBytes += packet.getPayloadBytes();
      this.forwardIAT.addValue(currentTimestamp - this.forwardLastSeen);
      this.forwardLastSeen = currentTimestamp;
      this.min_seg_size_forward = Math.min(packet.getHeaderBytes(), this.min_seg_size_forward);
    }

    this.flowIAT.addValue(packet.getTimeStamp() - this.flowLastSeen);
    this.flowLastSeen = packet.getTimeStamp();
  }

  public double getfPktsPerSecond() {
    long duration = this.flowLastSeen - this.flowStartTime;
    if (duration > 0) {
      return (this.forward.size() / ((double) duration / 1000000L));
    } else return 0;
  }

  public double getbPktsPerSecond() {
    long duration = this.flowLastSeen - this.flowStartTime;
    if (duration > 0) {
      return (this.backward.size() / ((double) duration / 1000000L));
    } else return 0;
  }

  public double getDownUpRatio() {
    if (this.forward.size() > 0) {
      return (this.backward.size() * 1D / this.forward.size());
    }
    return 0;
  }

  public double getAvgPacketSize() {
    if (this.packetCount() > 0) {
      return (this.flowLengthStats.getSum() / this.packetCount());
    }
    return 0;
  }

  public double fAvgSegmentSize() {
    if (this.forward.size() != 0) return (this.fwdPktStats.getSum() / (double) this.forward.size());
    return 0;
  }

  public double bAvgSegmentSize() {
    if (this.backward.size() != 0)
      return (this.bwdPktStats.getSum() / (double) this.backward.size());
    return 0;
  }

  public void initFlags() {
    flagCounts.put("FIN", new MutableInt());
    flagCounts.put("SYN", new MutableInt());
    flagCounts.put("RST", new MutableInt());
    flagCounts.put("PSH", new MutableInt());
    flagCounts.put("ACK", new MutableInt());
    flagCounts.put("URG", new MutableInt());
    flagCounts.put("CWR", new MutableInt());
    flagCounts.put("ECE", new MutableInt());
  }

  public void checkFlags(BasicPacketInfo packet) {
    if (packet.hasFlagFIN()) {
      flagCounts.get("FIN").increment();
    }
    if (packet.hasFlagSYN()) {
      flagCounts.get("SYN").increment();
    }
    if (packet.hasFlagRST()) {
      flagCounts.get("RST").increment();
    }
    if (packet.hasFlagPSH()) {
      flagCounts.get("PSH").increment();
    }
    if (packet.hasFlagACK()) {
      flagCounts.get("ACK").increment();
    }
    if (packet.hasFlagURG()) {
      flagCounts.get("URG").increment();
    }
    if (packet.hasFlagCWR()) {
      flagCounts.get("CWR").increment();
    }
    if (packet.hasFlagECE()) {
      flagCounts.get("ECE").increment();
    }
  }

  public long getSflow_fbytes() {
    if (sfCount <= 0) return 0;
    return this.forwardBytes / sfCount;
  }

  public long getSflow_fpackets() {
    if (sfCount <= 0) return 0;
    return this.forward.size() / sfCount;
  }

  public long getSflow_bbytes() {
    if (sfCount <= 0) return 0;
    return this.backwardBytes / sfCount;
  }

  public long getSflow_bpackets() {
    if (sfCount <= 0) return 0;
    return this.backward.size() / sfCount;
  }

  void detectUpdateSubflows(BasicPacketInfo packet) {
    if (sfLastPacketTS == -1) {
      sfLastPacketTS = packet.getTimeStamp();
    }
    if ((packet.getTimeStamp() - (sfLastPacketTS) / (double) 1000000) > 1.0) {
      sfCount++;
      updateActiveIdleTime(packet.getTimeStamp() - sfLastPacketTS, 5000000L);
    }

    sfLastPacketTS = packet.getTimeStamp();
  }

  public void updateFlowBulk(BasicPacketInfo packet) {
    if (this.src == packet.getSrc()) {
      // update forward Bulk
      updateBulk(packet, blastBulkTS);
    } else {
      // update backward Bulk
      updateBulk(packet, flastBulkTS);
    }
  }

  public void updateBulk(BasicPacketInfo packet, long tsOflastBulkInOther) {
    /*bAvgBytesPerBulk =0;
    bbulkSizeTotal=0;
    bbulkStateCount=0;*/
    long size = packet.getPayloadBytes();
    if (tsOflastBulkInOther > bbulkStartHelper) bbulkStartHelper = 0;
    if (size <= 0) return;

    packet.getPayloadPacket();

    if (bbulkStartHelper == 0) {
      bbulkStartHelper = packet.getTimeStamp();
      bbulkPacketCountHelper = 1;
      bbulkSizeHelper = size;
      blastBulkTS = packet.getTimeStamp();
    } // possible bulk
    else {
      // Too much idle time?
      if (((packet.getTimeStamp() - blastBulkTS) / (double) 1000000) > 1.0) {
        bbulkStartHelper = packet.getTimeStamp();
        blastBulkTS = packet.getTimeStamp();
        bbulkPacketCountHelper = 1;
        bbulkSizeHelper = size;
      } // Add to bulk
      else {
        bbulkPacketCountHelper += 1;
        bbulkSizeHelper += size;
        // New bulk
        if (bbulkPacketCountHelper == 4) {
          bbulkStateCount += 1;
          bbulkPacketCount += bbulkPacketCountHelper;
          bbulkSizeTotal += bbulkSizeHelper;
          bbulkDuration += packet.getTimeStamp() - bbulkStartHelper;
        } // Continuation of existing bulk
        else if (bbulkPacketCountHelper > 4) {
          bbulkPacketCount += 1;
          bbulkSizeTotal += size;
          bbulkDuration += packet.getTimeStamp() - blastBulkTS;
        }
        blastBulkTS = packet.getTimeStamp();
      }
    }
  }

  public long fbulkStateCount() {
    return fbulkStateCount;
  }

  public long fbulkSizeTotal() {
    return fbulkSizeTotal;
  }

  public long fbulkPacketCount() {
    return fbulkPacketCount;
  }

  public long fbulkDuration() {
    return fbulkDuration;
  }

  public double fbulkDurationInSecond() {
    return fbulkDuration / (double) 1000000;
  }

  // Client average bytes per bulk
  public long fAvgBytesPerBulk() {
    if (this.fbulkStateCount() != 0) return (this.fbulkSizeTotal() / this.fbulkStateCount());
    return 0;
  }

  // Client average packets per bulk
  public long fAvgPacketsPerBulk() {
    if (this.fbulkStateCount() != 0) return (this.fbulkPacketCount() / this.fbulkStateCount());
    return 0;
  }

  // Client average bulk rate
  public long fAvgBulkRate() {
    if (this.fbulkDuration() != 0)
      return (long) (this.fbulkSizeTotal() / this.fbulkDurationInSecond());
    return 0;
  }

  // new features server
  public long bbulkPacketCount() {
    return bbulkPacketCount;
  }

  public long bbulkStateCount() {
    return bbulkStateCount;
  }

  public long bbulkSizeTotal() {
    return bbulkSizeTotal;
  }

  public long bbulkDuration() {
    return bbulkDuration;
  }

  public double bbulkDurationInSecond() {
    return bbulkDuration / (double) 1000000;
  }

  // Server average packets per bulk
  public long bAvgPacketsPerBulk() {
    if (this.bbulkStateCount() != 0) return (this.bbulkPacketCount() / this.bbulkStateCount());
    return 0;
  }

  // Server average bulk rate
  public long bAvgBulkRate() {
    if (this.bbulkDuration() != 0)
      return (long) (this.bbulkSizeTotal() / this.bbulkDurationInSecond());
    return 0;
  }

  public void updateActiveIdleTime(long currentTime, long threshold) {
    if ((currentTime - this.endActiveTime) > threshold) {
      if ((this.endActiveTime - this.startActiveTime) > 0) {
        this.flowActive.addValue(this.endActiveTime - this.startActiveTime);
      }
      this.flowIdle.addValue(currentTime - this.endActiveTime);
      this.startActiveTime = currentTime;
    }
    this.endActiveTime = currentTime;
  }

  public int packetCount() {
    if (isBidirectional) {
      return (this.forward.size() + this.backward.size());
    } else {
      return this.forward.size();
    }
  }

  public byte[] getSrc() {
    return Arrays.copyOf(src, src.length);
  }

  public byte[] getDst() {
    return Arrays.copyOf(dst, dst.length);
  }

  public int getSrcPort() {
    return srcPort;
  }

  public int getDstPort() {
    return dstPort;
  }

  public int getProtocol() {
    return protocol;
  }

  public void setProtocol(int protocol) {
    this.protocol = protocol;
  }

  public long getFlowStartTime() {
    return flowStartTime;
  }

  public String dumpFlowBasedFeaturesEx(ResourceBundle rb) {
    StringBuilder dump = new StringBuilder();
    if (rb.containsKey(FlowFeature.fid.getCvsField())) {
      dump.append(flowId).append(ExtractorFeaturesModel.SEPARATOR); // 1
    }
    if (rb.containsKey(FlowFeature.src_ip.getCvsField())) {
      dump.append(FormatUtils.ip(src)).append(ExtractorFeaturesModel.SEPARATOR); // 2
    }

    if (rb.containsKey(FlowFeature.src_port.getCvsField())) {
      dump.append(getSrcPort()).append(ExtractorFeaturesModel.SEPARATOR); // 3
    }

    if (rb.containsKey(FlowFeature.dst_ip.getCvsField())) {
      dump.append(FormatUtils.ip(dst)).append(ExtractorFeaturesModel.SEPARATOR); // 4
    }

    if (rb.containsKey(FlowFeature.dst_ip.getCvsField())) {
      dump.append(FormatUtils.ip(dst)).append(ExtractorFeaturesModel.SEPARATOR); // 4
    }

    if (rb.containsKey(FlowFeature.dst_pot.getCvsField())) {
      dump.append(getDstPort()).append(ExtractorFeaturesModel.SEPARATOR); // 5
    }
    if (rb.containsKey(FlowFeature.prot.getCvsField())) {
      dump.append(getProtocol()).append(ExtractorFeaturesModel.SEPARATOR); // 6
    }
    String starttime =
            Utility.convertMilliseconds2String(flowStartTime / 1000L, "dd/MM/yyyy hh:mm:ss a");
    if (rb.containsKey(FlowFeature.tstp.getCvsField())) {
      dump.append(starttime).append(ExtractorFeaturesModel.SEPARATOR); // 7
    }
    long flowDuration = flowLastSeen - flowStartTime;
    if (rb.containsKey(FlowFeature.fl_dur.getCvsField())) {
      dump.append(flowDuration).append(ExtractorFeaturesModel.SEPARATOR); // 8
    }

    if (rb.containsKey(FlowFeature.tot_fw_pkt.getCvsField())) {
      dump.append(fwdPktStats.getN()).append(ExtractorFeaturesModel.SEPARATOR); // 9
    }

    if (rb.containsKey(FlowFeature.tot_bw_pkt.getCvsField())) {
      dump.append(bwdPktStats.getN()).append(ExtractorFeaturesModel.SEPARATOR); // 10
    }

    if (rb.containsKey(FlowFeature.tot_l_fw_pkt.getCvsField())) {
      dump.append(fwdPktStats.getSum()).append(ExtractorFeaturesModel.SEPARATOR); // 11
    }

    if (rb.containsKey(FlowFeature.tot_l_bw_pkt.getCvsField())) {
      dump.append(bwdPktStats.getSum()).append(ExtractorFeaturesModel.SEPARATOR); // 12
    }

    if (fwdPktStats.getN() > 0L) {
      if (rb.containsKey(FlowFeature.fw_pkt_l_max.getCvsField())) {
        dump.append(fwdPktStats.getMax()).append(ExtractorFeaturesModel.SEPARATOR); // 13
      }
      if (rb.containsKey(FlowFeature.fw_pkt_l_min.getCvsField())) {
        dump.append(fwdPktStats.getMin()).append(ExtractorFeaturesModel.SEPARATOR); // 14
      }
      if (rb.containsKey(FlowFeature.fw_pkt_l_avg.getCvsField())) {
        dump.append(fwdPktStats.getMean()).append(ExtractorFeaturesModel.SEPARATOR); // 15
      }
      if (rb.containsKey(FlowFeature.fw_pkt_l_std.getCvsField())) {
        dump.append(fwdPktStats.getStandardDeviation()).append(ExtractorFeaturesModel.SEPARATOR); // 16
      }
    } else {
      if (rb.containsKey(FlowFeature.fw_pkt_l_max.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 13
      }
      if (rb.containsKey(FlowFeature.fw_pkt_l_min.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 14
      }
      if (rb.containsKey(FlowFeature.fw_pkt_l_avg.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 15
      }
      if (rb.containsKey(FlowFeature.fw_pkt_l_std.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 16
      }
    }
    if (bwdPktStats.getN() > 0L) {
      if (rb.containsKey(FlowFeature.bw_pkt_l_max.getCvsField())) {
        dump.append(fwdPktStats.getMax()).append(ExtractorFeaturesModel.SEPARATOR); // 17
      }
      if (rb.containsKey(FlowFeature.bw_pkt_l_min.getCvsField())) {
        dump.append(fwdPktStats.getMin()).append(ExtractorFeaturesModel.SEPARATOR); // 18
      }
      if (rb.containsKey(FlowFeature.bw_pkt_l_avg.getCvsField())) {
        dump.append(fwdPktStats.getMean()).append(ExtractorFeaturesModel.SEPARATOR); // 19
      }
      if (rb.containsKey(FlowFeature.bw_pkt_l_std.getCvsField())) {
        dump.append(fwdPktStats.getStandardDeviation()).append(ExtractorFeaturesModel.SEPARATOR); // 20
      }
    } else {
      if (rb.containsKey(FlowFeature.bw_pkt_l_max.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 17
      }
      if (rb.containsKey(FlowFeature.bw_pkt_l_min.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 18
      }
      if (rb.containsKey(FlowFeature.bw_pkt_l_avg.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 19
      }
      if (rb.containsKey(FlowFeature.bw_pkt_l_std.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 20
      }
    }

    if (rb.containsKey(FlowFeature.fl_byt_s.getCvsField())) {
      dump.append(((double) (forwardBytes + backwardBytes)) / ((double) flowDuration / 1000000L))
              .append(ExtractorFeaturesModel.SEPARATOR); // 21
    }

    if (rb.containsKey(FlowFeature.fl_pkt_s.getCvsField())) {
      dump.append(((double) packetCount()) / ((double) flowDuration / 1000000L))
              .append(ExtractorFeaturesModel.SEPARATOR); // 22
    }
    if (rb.containsKey(FlowFeature.fl_iat_avg.getCvsField())) {
      dump.append(flowIAT.getMean()).append(ExtractorFeaturesModel.SEPARATOR); // 23
    }
    if (rb.containsKey(FlowFeature.fl_iat_std.getCvsField())) {
      dump.append(flowIAT.getStandardDeviation()).append(ExtractorFeaturesModel.SEPARATOR); // 24
    }
    if (rb.containsKey(FlowFeature.fl_iat_max.getCvsField())) {
      dump.append(flowIAT.getMax()).append(ExtractorFeaturesModel.SEPARATOR); // 25
    }
    if (rb.containsKey(FlowFeature.fl_iat_min.getCvsField())) {
      dump.append(flowIAT.getMin()).append(ExtractorFeaturesModel.SEPARATOR); // 26
    }
    if (this.forward.size() > 1) {
      if (rb.containsKey(FlowFeature.fw_iat_tot.getCvsField())) {
        dump.append(forwardIAT.getSum()).append(ExtractorFeaturesModel.SEPARATOR); // 27
      }
      if (rb.containsKey(FlowFeature.fw_iat_avg.getCvsField())) {
        dump.append(forwardIAT.getMean()).append(ExtractorFeaturesModel.SEPARATOR); // 28
      }
      if (rb.containsKey(FlowFeature.fw_iat_std.getCvsField())) {
        dump.append(forwardIAT.getStandardDeviation()).append(ExtractorFeaturesModel.SEPARATOR); // 29
      }
      if (rb.containsKey(FlowFeature.fw_iat_max.getCvsField())) {
        dump.append(forwardIAT.getMax()).append(ExtractorFeaturesModel.SEPARATOR); // 30
      }
      if (rb.containsKey(FlowFeature.fw_iat_min.getCvsField())) {
        dump.append(forwardIAT.getMin()).append(ExtractorFeaturesModel.SEPARATOR); // 31
      }
    } else {
      if (rb.containsKey(FlowFeature.fw_iat_tot.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 27
      }
      if (rb.containsKey(FlowFeature.fw_iat_avg.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 28
      }
      if (rb.containsKey(FlowFeature.fw_iat_std.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 29
      }
      if (rb.containsKey(FlowFeature.fw_iat_max.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 30
      }
      if (rb.containsKey(FlowFeature.fw_iat_min.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 31
      }
    }
    if (this.backward.size() > 1) {
      if (rb.containsKey(FlowFeature.bw_iat_tot.getCvsField())) {
        dump.append(backwardIAT.getSum()).append(ExtractorFeaturesModel.SEPARATOR); // 32
      }
      if (rb.containsKey(FlowFeature.bw_iat_avg.getCvsField())) {
        dump.append(backwardIAT.getMean()).append(ExtractorFeaturesModel.SEPARATOR); // 33
      }
      if (rb.containsKey(FlowFeature.bw_iat_std.getCvsField())) {
        dump.append(backwardIAT.getStandardDeviation()).append(ExtractorFeaturesModel.SEPARATOR); // 34
      }
      if (rb.containsKey(FlowFeature.bw_iat_max.getCvsField())) {
        dump.append(backwardIAT.getMax()).append(ExtractorFeaturesModel.SEPARATOR); // 35
      }
      if (rb.containsKey(FlowFeature.bw_iat_min.getCvsField())) {
        dump.append(backwardIAT.getMin()).append(ExtractorFeaturesModel.SEPARATOR); // 36
      }
    } else {
      if (rb.containsKey(FlowFeature.bw_iat_tot.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 32
      }
      if (rb.containsKey(FlowFeature.bw_iat_avg.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 33
      }
      if (rb.containsKey(FlowFeature.bw_iat_std.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 34
      }
      if (rb.containsKey(FlowFeature.bw_iat_max.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 35
      }
      if (rb.containsKey(FlowFeature.bw_iat_min.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 36
      }
    }
    if (rb.containsKey(FlowFeature.fw_psh_flag.getCvsField())) {
      dump.append(fPSH_cnt).append(ExtractorFeaturesModel.SEPARATOR); // 37
    }
    if (rb.containsKey(FlowFeature.bw_psh_flag.getCvsField())) {
      dump.append(bPSH_cnt).append(ExtractorFeaturesModel.SEPARATOR); // 38
    }
    if (rb.containsKey(FlowFeature.fw_urg_flag.getCvsField())) {
      dump.append(fURG_cnt).append(ExtractorFeaturesModel.SEPARATOR); // 39
    }
    if (rb.containsKey(FlowFeature.bw_urg_flag.getCvsField())) {
      dump.append(bURG_cnt).append(ExtractorFeaturesModel.SEPARATOR); // 40
    }
    if (rb.containsKey(FlowFeature.fw_hdr_len.getCvsField())) {
      dump.append(fHeaderBytes).append(ExtractorFeaturesModel.SEPARATOR); // 41
    }
    if (rb.containsKey(FlowFeature.bw_hdr_len.getCvsField())) {
      dump.append(bHeaderBytes).append(ExtractorFeaturesModel.SEPARATOR); // 42
    }
    if (rb.containsKey(FlowFeature.fw_pkt_s.getCvsField())) {
      dump.append(getfPktsPerSecond()).append(ExtractorFeaturesModel.SEPARATOR); // 43
    }
    if (rb.containsKey(FlowFeature.bw_pkt_s.getCvsField())) {
      dump.append(getbPktsPerSecond()).append(ExtractorFeaturesModel.SEPARATOR); // 44
    }

    if (this.forward.size() > 0 || this.backward.size() > 0) {
      if (rb.containsKey(FlowFeature.pkt_len_min.getCvsField())) {
        dump.append(flowLengthStats.getMin()).append(ExtractorFeaturesModel.SEPARATOR); // 45
      }
      if (rb.containsKey(FlowFeature.pkt_len_max.getCvsField())) {
        dump.append(flowLengthStats.getMax()).append(ExtractorFeaturesModel.SEPARATOR); // 46
      }
      if (rb.containsKey(FlowFeature.pkt_len_avg.getCvsField())) {
        dump.append(flowLengthStats.getMean()).append(ExtractorFeaturesModel.SEPARATOR); // 47
      }
      if (rb.containsKey(FlowFeature.pkt_len_std.getCvsField())) {
        dump.append(flowLengthStats.getStandardDeviation()).append(ExtractorFeaturesModel.SEPARATOR); // 48
      }
      if (rb.containsKey(FlowFeature.pkt_len_var.getCvsField())) {
        dump.append(flowLengthStats.getVariance()).append(ExtractorFeaturesModel.SEPARATOR); // 49
      }
    } else {
      if (rb.containsKey(FlowFeature.pkt_len_min.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 45
      }
      if (rb.containsKey(FlowFeature.pkt_len_max.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 46
      }
      if (rb.containsKey(FlowFeature.pkt_len_avg.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 47
      }
      if (rb.containsKey(FlowFeature.pkt_len_std.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 48
      }
      if (rb.containsKey(FlowFeature.pkt_len_var.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 49
      }
    }

    if (rb.containsKey(FlowFeature.fin_cnt.getCvsField())) {
      dump.append(flagCounts.get("FIN").value).append(ExtractorFeaturesModel.SEPARATOR); // 50
    }
    if (rb.containsKey(FlowFeature.syn_cnt.getCvsField())) {
      dump.append(flagCounts.get("SYN").value).append(ExtractorFeaturesModel.SEPARATOR); // 51
    }
    if (rb.containsKey(FlowFeature.rst_cnt.getCvsField())) {
      dump.append(flagCounts.get("RST").value).append(ExtractorFeaturesModel.SEPARATOR); // 52
    }
    if (rb.containsKey(FlowFeature.pst_cnt.getCvsField())) {
      dump.append(flagCounts.get("PSH").value).append(ExtractorFeaturesModel.SEPARATOR); // 53
    }
    if (rb.containsKey(FlowFeature.ack_cnt.getCvsField())) {
      dump.append(flagCounts.get("ACK").value).append(ExtractorFeaturesModel.SEPARATOR); // 54
    }
    if (rb.containsKey(FlowFeature.urg_cnt.getCvsField())) {
      dump.append(flagCounts.get("URG").value).append(ExtractorFeaturesModel.SEPARATOR); // 55
    }
    if (rb.containsKey(FlowFeature.cwr_cnt.getCvsField())) {
      dump.append(flagCounts.get("CWR").value).append(ExtractorFeaturesModel.SEPARATOR); // 56
    }
    if (rb.containsKey(FlowFeature.ece_cnt.getCvsField())) {
      dump.append(flagCounts.get("ECE").value).append(ExtractorFeaturesModel.SEPARATOR); // 57
    }
    if (rb.containsKey(FlowFeature.down_up_ratio.getCvsField())) {
      dump.append(getDownUpRatio()).append(ExtractorFeaturesModel.SEPARATOR); // 58
    }
    if (rb.containsKey(FlowFeature.pkt_size_avg.getCvsField())) {
      dump.append(getAvgPacketSize()).append(ExtractorFeaturesModel.SEPARATOR); // 59
    }
    if (rb.containsKey(FlowFeature.fw_seg_avg.getCvsField())) {
      dump.append(fAvgSegmentSize()).append(ExtractorFeaturesModel.SEPARATOR); // 60
    }
    if (rb.containsKey(FlowFeature.bw_seg_avg.getCvsField())) {
      dump.append(bAvgSegmentSize()).append(ExtractorFeaturesModel.SEPARATOR); // 61
    }
    if (rb.containsKey(FlowFeature.fw_byt_blk_avg.getCvsField())) {
      dump.append(fAvgBytesPerBulk()).append(ExtractorFeaturesModel.SEPARATOR); // 63
    }
    if (rb.containsKey(FlowFeature.fw_pkt_blk_avg.getCvsField())) {
      dump.append(fAvgPacketsPerBulk()).append(ExtractorFeaturesModel.SEPARATOR); // 64
    }
    if (rb.containsKey(FlowFeature.fw_blk_rate_avg.getCvsField())) {
      dump.append(fAvgBulkRate()).append(ExtractorFeaturesModel.SEPARATOR); // 65
    }
    if (rb.containsKey(FlowFeature.bw_byt_blk_avg.getCvsField())) {
      dump.append(fAvgBytesPerBulk()).append(ExtractorFeaturesModel.SEPARATOR); // 66
    }
    if (rb.containsKey(FlowFeature.bw_pkt_blk_avg.getCvsField())) {
      dump.append(bAvgPacketsPerBulk()).append(ExtractorFeaturesModel.SEPARATOR); // 67
    }
    if (rb.containsKey(FlowFeature.bw_blk_rate_avg.getCvsField())) {
      dump.append(bAvgBulkRate()).append(ExtractorFeaturesModel.SEPARATOR); // 68
    }
    if (rb.containsKey(FlowFeature.subfl_fw_pkt.getCvsField())) {
      dump.append(getSflow_fpackets()).append(ExtractorFeaturesModel.SEPARATOR); // 69
    }
    if (rb.containsKey(FlowFeature.subfl_fw_byt.getCvsField())) {
      dump.append(getSflow_fbytes()).append(ExtractorFeaturesModel.SEPARATOR); // 70
    }
    if (rb.containsKey(FlowFeature.subfl_bw_pkt.getCvsField())) {
      dump.append(getSflow_bpackets()).append(ExtractorFeaturesModel.SEPARATOR); // 71
    }
    if (rb.containsKey(FlowFeature.subfl_bw_byt.getCvsField())) {
      dump.append(getSflow_bbytes()).append(ExtractorFeaturesModel.SEPARATOR); // 72
    }
    if (rb.containsKey(FlowFeature.fw_win_byt.getCvsField())) {
      dump.append(Init_Win_bytes_forward).append(ExtractorFeaturesModel.SEPARATOR); // 73
    }
    if (rb.containsKey(FlowFeature.bw_win_byt.getCvsField())) {
      dump.append(Init_Win_bytes_backward).append(ExtractorFeaturesModel.SEPARATOR); // 74
    }
    if (rb.containsKey(FlowFeature.Fw_act_pkt.getCvsField())) {
      dump.append(Act_data_pkt_forward).append(ExtractorFeaturesModel.SEPARATOR); // 75
    }
    if (rb.containsKey(FlowFeature.fw_seg_min.getCvsField())) {
      dump.append(min_seg_size_forward).append(ExtractorFeaturesModel.SEPARATOR); // 76
    }
    if (this.flowActive.getN() > 0) {
      if (rb.containsKey(FlowFeature.atv_avg.getCvsField())) {
        dump.append(flowActive.getMean()).append(ExtractorFeaturesModel.SEPARATOR); // 77
      }
      if (rb.containsKey(FlowFeature.atv_std.getCvsField())) {
        dump.append(flowActive.getStandardDeviation()).append(ExtractorFeaturesModel.SEPARATOR); // 78
      }
      if (rb.containsKey(FlowFeature.atv_max.getCvsField())) {
        dump.append(flowActive.getMax()).append(ExtractorFeaturesModel.SEPARATOR); // 79
      }
      if (rb.containsKey(FlowFeature.atv_min.getCvsField())) {
        dump.append(flowActive.getMin()).append(ExtractorFeaturesModel.SEPARATOR); // 80
      }
    } else {
      if (rb.containsKey(FlowFeature.atv_avg.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 77
      }
      if (rb.containsKey(FlowFeature.atv_std.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 78
      }
      if (rb.containsKey(FlowFeature.atv_max.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 79
      }
      if (rb.containsKey(FlowFeature.atv_min.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 80
      }
    }

    if (this.flowIdle.getN() > 0) {
      if (rb.containsKey(FlowFeature.idl_avg.getCvsField())) {
        dump.append(flowIdle.getMean()).append(ExtractorFeaturesModel.SEPARATOR); // 81
      }
      if (rb.containsKey(FlowFeature.idl_std.getCvsField())) {
        dump.append(flowIdle.getStandardDeviation()).append(ExtractorFeaturesModel.SEPARATOR); // 82
      }
      if (rb.containsKey(FlowFeature.idl_max.getCvsField())) {
        dump.append(flowIdle.getMax()).append(ExtractorFeaturesModel.SEPARATOR); // 83
      }
      if (rb.containsKey(FlowFeature.idl_min.getCvsField())) {
        dump.append(flowIdle.getMin()).append(ExtractorFeaturesModel.SEPARATOR); // 84
      }
    } else {
      if (rb.containsKey(FlowFeature.idl_avg.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 81
      }
      if (rb.containsKey(FlowFeature.idl_std.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 82
      }
      if (rb.containsKey(FlowFeature.idl_max.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 83
      }
      if (rb.containsKey(FlowFeature.idl_min.getCvsField())) {
        dump.append(0).append(ExtractorFeaturesModel.SEPARATOR); // 84
      }
    }
    if (rb.containsKey(FlowFeature.Label.getCvsField())) {
      dump.append("label"); // -> final CVS value (attack or benign) 85
    }
    return dump.toString();
  }
}

class MutableInt {
  int value = 0;

  public void increment() {
    ++value;
  }

  public int get() {
    return value;
  }
}
