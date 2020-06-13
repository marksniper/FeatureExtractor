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

import org.apache.commons.lang3.math.NumberUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

public enum FlowFeature {
  fid("Flow ID", "FID", "Flow_ID", false), // 1 this index is for feature not for ordinal
  src_ip("Src IP", "SIP", "Src_IP", false), // 2
  src_port("Src Port", "SPT", "Src_Port"), // 3
  dst_ip("Dst IP", "DIP", "Dst_IP", false), // 4
  dst_pot("Dst Port", "DPT", "Dst_Port"), // 5
  prot("Protocol", "PROT", "Protocol"), // 6
  tstp("Timestamp", "TSTP", "Timestamp", false), // 7
  fl_dur("Flow Duration", "DUR", "Flow_Duration"), // 8
  tot_fw_pkt("Tot Fwd Pkts", "TFwP", "Tot_Fwd_Pkts"), // 9
  tot_bw_pkt("Tot Bwd Pkts", "TBwP", "Tot_Bwd_Pkts"), // 10
  tot_l_fw_pkt("TotLen Fwd Pkts", "TLFwP", "TotLen_Fwd_Pkts"), // 11
  tot_l_bw_pkt("TotLen Bwd Pkts", "TLBwP", "TotLen_Bwd_Pkts"), // 12
  fw_pkt_l_max("Fwd Pkt Len Max", "FwPLMA", "Fwd_Pkt_Len_Max"), // 13
  fw_pkt_l_min("Fwd Pkt Len Min", "FwPLMI", "Fwd_Pkt_Len_Min"), // 14
  fw_pkt_l_avg("Fwd Pkt Len Mean", "FwPLAG", "Fwd_Pkt_Len_Mean"), // 15
  fw_pkt_l_std("Fwd Pkt Len Std", "FwPLSD", "Fwd_Pkt_Len_Std"), // 16
  bw_pkt_l_max("Bwd Pkt Len Max", "BwPLMA", "Bwd_Pkt_Len_Max"), // 17
  bw_pkt_l_min("Bwd Pkt Len Min", "BwPLMI", "Bwd_Pkt_Len_Min"), // 18
  bw_pkt_l_avg("Bwd Pkt Len Mean", "BwPLAG", "Bwd_Pkt_Len_Mean"), // 19
  bw_pkt_l_std("Bwd Pkt Len Std", "BwPLSD", "Bwd_Pkt_Len_Std"), // 20
  fl_byt_s("Flow Byts/s", "FB/s", "Flow_Byts_s"), // 21
  fl_pkt_s("Flow Pkts/s", "FP/s", "Flow_Pkts_s"), // 22
  fl_iat_avg("Flow IAT Mean", "FLIATAG", "Flow_IAT_Mean"), // 23
  fl_iat_std("Flow IAT Std", "FLIATSD", "Flow_IAT_Std"), // 24
  fl_iat_max("Flow IAT Max", "FLIATMA", "Flow_IAT_Max"), // 25
  fl_iat_min("Flow IAT Min", "FLIATMI", "Flow_IAT_Min"), // 26
  fw_iat_tot("Fwd IAT Tot", "FwIATTO", "Fwd_IAT_Tot"), // 27
  fw_iat_avg("Fwd IAT Mean", "FwIATAG", "Fwd_IAT_Mean"), // 28
  fw_iat_std("Fwd IAT Std", "FwIATSD", "Fwd_IAT_Std"), // 29
  fw_iat_max("Fwd IAT Max", "FwIATMA", "Fwd_IAT_Max"), // 30
  fw_iat_min("Fwd IAT Min", "FwIATMI", "Fwd_IAT_Min"), // 31
  bw_iat_tot("Bwd IAT Tot", "BwIATTO", "Bwd_IAT_Tot"), // 32
  bw_iat_avg("Bwd IAT Mean", "BwIATAG", "Bwd_IAT_Mean"), // 33
  bw_iat_std("Bwd IAT Std", "BwIATSD", "Bwd_IAT_Std"), // 34
  bw_iat_max("Bwd IAT Max", "BwIATMA", "Bwd_IAT_Maxv"), // 35
  bw_iat_min("Bwd IAT Min", "BwIATMI", "Bwd_IAT_Min"), // 36
  fw_psh_flag("Fwd PSH Flags", "FwPSH", "Fwd_PSH_Flags"), // 37
  bw_psh_flag("Bwd PSH Flags", "BwPSH", "Bwd_PSH_Flags"), // 38
  fw_urg_flag("Fwd URG Flags", "FwURG", "Fwd_URG_Flags"), // 39
  bw_urg_flag("Bwd URG Flags", "BwURG", "Bwd_URG_Flags"), // 40
  fw_hdr_len("Fwd Header Len", "FwHL", "Fwd_Header_Len"), // 41
  bw_hdr_len("Bwd Header Len", "BwHL", "Bwd_Header_Len"), // 42
  fw_pkt_s("Fwd Pkts/s", "FwP/s", "Fwd_Pkts_s"), // 43
  bw_pkt_s("Bwd Pkts/s", "Bwp/s", "Bwd_Pkts_s"), // 44
  pkt_len_min("Pkt Len Min", "PLMI", "Pkt_Len_Min"), // 45
  pkt_len_max("Pkt Len Max", "PLMA", "Pkt_Len_Max"), // 46
  pkt_len_avg("Pkt Len Mean", "PLAG", "Pkt_Len_Mean"), // 47
  pkt_len_std("Pkt Len Std", "PLSD", "Pkt_Len_Std"), // 48
  pkt_len_var("Pkt Len Var", "PLVA", "Pkt_Len_Var"), // 49
  fin_cnt("FIN Flag Cnt", "FINCT", "FIN_Flag_Cnt"), // 50
  syn_cnt("SYN Flag Cnt", "SYNCT", "SYN_Flag_Cnt"), // 51
  rst_cnt("RST Flag Cnt", "RSTCT", "RST_Flag_Cnt"), // 52
  pst_cnt("PSH Flag Cnt", "PSHCT", "PSH_Flag_Cnt"), // 53
  ack_cnt("ACK Flag Cnt", "ACKCT", "ACK_Flag_Cnt"), // 54
  urg_cnt("URG Flag Cnt", "URGCT", "URG_Flag_Cnt"), // 55
  cwr_cnt("CWR Flag Count", "CWRCT", "CWR_Flag_Count"), // 56
  ece_cnt("ECE Flag Cnt", "ECECT", "ECE_Flag_Cnt"), // 57
  down_up_ratio("Down/Up Ratio", "D/URO", "Down_Up_Ratio"), // 58
  pkt_size_avg("Pkt Size Avg", "PSAG", "Pkt_Size_Avg"), // 59
  fw_seg_avg("Fwd Seg Size Avg", "FwSgAG", "Fwd_Seg_Size_Avg"), // 60
  bw_seg_avg("Bwd Seg Size Avg", "BwSgAG", "Bwd_Seg_Size_Avg"), // 61
  fw_byt_blk_avg("Fwd Byts/b Avg", "FwB/BAG", "Fwd_Byts_b_Avg"), // 63   62 is duplicated with 41,so has been deleted
  fw_pkt_blk_avg("Fwd Pkts/b Avg", "FwP/BAG", "Fwd_Pkts_b_Avg"), // 64
  fw_blk_rate_avg("Fwd Blk Rate Avg", "FwBRAG", "Fwd_Blk_Rate_Avg"), // 65
  bw_byt_blk_avg("Bwd Byts/b Avg", "BwB/BAG", "Bwd_Byts_b_Avg"), // 66
  bw_pkt_blk_avg("Bwd Pkts/b Avg", "BwP/BAG", "Bwd_Pkts_b_Avg"), // 67
  bw_blk_rate_avg("Bwd Blk Rate Avg", "BwBRAG", "Bwd_Blk_Rate_Avg"), // 68
  subfl_fw_pkt("Subflow Fwd Pkts", "SFFwP", "Subflow_Fwd_Pkts"), // 69
  subfl_fw_byt("Subflow Fwd Byts", "SFFwB", "Subflow_Fwd_Byts"), // 70
  subfl_bw_pkt("Subflow Bwd Pkts", "SFBwP", "Subflow_Bwd_Pkts"), // 71
  subfl_bw_byt("Subflow Bwd Byts", "SFBwB", "Subflow_Bwd_Byts"), // 72
  fw_win_byt("Init Fwd Win Byts", "FwWB", "Init_Fwd_Win_Byts"), // 73
  bw_win_byt("Init Bwd Win Byts", "BwWB", "Init_Bwd_Win_Byts"), // 74
  Fw_act_pkt("Fwd Act Data Pkts", "FwAP", "Fwd_Act_Data_Pkts"), // 75
  fw_seg_min("Fwd Seg Size Min", "FwSgMI", "Fwd_Seg_Size_Min"), // 76
  atv_avg("Active Mean", "AcAG", "Active_Mean"), // 77
  atv_std("Active Std", "AcSD", "Active_Std"), // 78
  atv_max("Active Max", "AcMA", "Active_Max"), // 79
  atv_min("Active Min", "AcMI", "Active_Min"), // 80
  idl_avg("Idle Mean", "IlAG", "Idle_Mean"), // 81
  idl_std("Idle Std", "IlSD", "Idle_Std"), // 82
  idl_max("Idle Max", "IlMA", "Idle_Max"), // 83
  idl_min("Idle Min", "IlMI", "Idle_Min"), // 84

  Label("Label", "LBL", "Label", new String[]{"CIC"}); // 85

  private static final Logger logger = LogManager.getLogger(FlowFeature.class);
  private final String name;
  private final String abbr;
  private final String cvsField;
  private final boolean isNumeric;
  private String[] values;

  FlowFeature(String name, String abbr, String cvsField, boolean numeric) {
    this.name = name;
    this.abbr = abbr;
    this.cvsField = cvsField;
    isNumeric = numeric;
  }

  FlowFeature(String name, String abbr, String cvsField) {
    this.name = name;
    this.abbr = abbr;
    this.cvsField = cvsField;
    isNumeric = true;
  }

  FlowFeature(String name, String abbr, String cvsField, String[] values) {
    this.name = name;
    this.abbr = abbr;
    this.values = values;
    this.cvsField = cvsField;
    isNumeric = false;
  }

  public static FlowFeature getByName(String name) {
    for (FlowFeature feature : FlowFeature.values()) {
      if (feature.getName().equals(name)) {
        return feature;
      }
    }
    return null;
  }

  public static String getHeader(ResourceBundle rb) {
    logger.error("Rb " + rb.getBaseBundleName());
    StringBuilder header = new StringBuilder();

    for (FlowFeature feature : FlowFeature.values()) {
      String csvFeatureField = feature.getCvsField();
      if (rb.containsKey(csvFeatureField)) {
        logger.debug("csvFeatureField " + csvFeatureField);
        header.append(feature.getName()).append(",");
      }
    }
    header.deleteCharAt(header.length() - 1);
    return header.toString();
  }

  public static List<FlowFeature> getFeatureList() {
    List<FlowFeature> features = new ArrayList<>();
    features.add(prot);
    for (int i = fl_dur.ordinal(); i <= idl_min.ordinal(); i++) {
      features.add(FlowFeature.values()[i]);
    }
    return features;
  }

  public static List<FlowFeature> getLengthFeature() {
    List<FlowFeature> features = new ArrayList<>();
    features.add(tot_l_fw_pkt);
    features.add(tot_l_bw_pkt);
    features.add(fl_byt_s);
    features.add(fl_pkt_s);
    features.add(fw_hdr_len);
    features.add(bw_hdr_len);
    features.add(fw_pkt_s);
    features.add(bw_pkt_s);
    features.add(pkt_size_avg);
    features.add(fw_seg_avg);
    features.add(bw_seg_avg);
    return features;
  }

  // Keep for mapping between TCP int values and TCO string values
  public static String featureValue2String(FlowFeature feature, String value) {
    String ret = value;

    switch (feature) {
      case prot:
        try {
          int number = NumberUtils.createNumber(value).intValue();
          if (number == 6) {
            ret = "TCP";

          } else if (number == 17) {
            ret = "UDP";

          } else {
            ret = "Others";
          }
        } catch (NumberFormatException e) {
          logger.info("NumberFormatException {} value is {}", e.getMessage(), value);
          ret = "Others";
        }
        break;
    }

    return ret;
  }

  public String getName() {
    return name;
  }

  public String getAbbr() {
    return abbr;
  }

  public boolean isNumeric() {
    return isNumeric;
  }

  public String getCvsField() {
    return cvsField;
  }

  @Override
  public String toString() {
    return name;
  }
}
