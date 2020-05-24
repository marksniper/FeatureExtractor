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

import org.jnetpcap.packet.format.FormatUtils;

import java.util.Arrays;

public class BasicPacketInfo {
    private long id;
    private String flowId = null;

    /*  Basic Info to generate flows from packets  	*/
    private byte[] src;
    private byte[] dst;
    private int srcPort;
    private int dstPort;
    private int protocol;
    private long timeStamp;
    private long payloadBytes;
    private boolean flagFIN = false;
    private boolean flagPSH = false;
    private boolean flagURG = false;
    private boolean flagECE = false;
    private boolean flagSYN = false;
    private boolean flagACK = false;
    private boolean flagCWR = false;
    private boolean flagRST = false;
    private int TCPWindow = 0;
    private long headerBytes;
    private int payloadPacket = 0;

    public BasicPacketInfo() {
    }

    public int getPayloadPacket() {
        return payloadPacket += 1;
    }

    public byte[] getSrc() {
        return Arrays.copyOf(src, src.length);
    }

    public void setSrc(byte[] src) {
        this.src = src;
    }

    public byte[] getDst() {
        return Arrays.copyOf(dst, dst.length);
    }

    public void setDst(byte[] dst) {
        this.dst = dst;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public long getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(long timeStamp) {
        this.timeStamp = timeStamp;
    }

    public long getPayloadBytes() {
        return payloadBytes;
    }

    public void setPayloadBytes(long payloadBytes) {
        this.payloadBytes = payloadBytes;
    }

    public long getHeaderBytes() {
        return headerBytes;
    }

    public void setHeaderBytes(long headerBytes) {
        this.headerBytes = headerBytes;
    }

    public boolean hasFlagFIN() {
        return flagFIN;
    }

    public void setFlagFIN(boolean flagFIN) {
        this.flagFIN = flagFIN;
    }

    public boolean hasFlagPSH() {
        return flagPSH;
    }

    public void setFlagPSH(boolean flagPSH) {
        this.flagPSH = flagPSH;
    }

    public boolean hasFlagURG() {
        return flagURG;
    }

    public void setFlagURG(boolean flagURG) {
        this.flagURG = flagURG;
    }

    public boolean hasFlagECE() {
        return flagECE;
    }

    public void setFlagECE(boolean flagECE) {
        this.flagECE = flagECE;
    }

    public boolean hasFlagSYN() {
        return flagSYN;
    }

    public void setFlagSYN(boolean flagSYN) {
        this.flagSYN = flagSYN;
    }

    public boolean hasFlagACK() {
        return flagACK;
    }

    public void setFlagACK(boolean flagACK) {
        this.flagACK = flagACK;
    }

    public boolean hasFlagCWR() {
        return flagCWR;
    }

    public void setFlagCWR(boolean flagCWR) {
        this.flagCWR = flagCWR;
    }

    public boolean hasFlagRST() {
        return flagRST;
    }

    public void setFlagRST(boolean flagRST) {
        this.flagRST = flagRST;
    }

    public int getTCPWindow() {
        return TCPWindow;
    }

    public void setTCPWindow(int TCPWindow) {
        this.TCPWindow = TCPWindow;
    }

    public String getFlowId() {
        return this.flowId != null ? this.flowId : generateFlowId();
    }

    public String generateFlowId() {
        boolean forward = true;

        for (int i = 0; i < this.src.length; i++) {
            if (((Byte) (this.src[i])).intValue() != ((Byte) (this.dst[i])).intValue()) {
                if (((Byte) (this.src[i])).intValue() > ((Byte) (this.dst[i])).intValue()) {
                    forward = false;
                }
                i = this.src.length;
            }
        }

        if (forward) {
            this.flowId =
                    this.getSourceIP()
                            + "-"
                            + this.getDestinationIP()
                            + "-"
                            + this.srcPort
                            + "-"
                            + this.dstPort
                            + "-"
                            + this.protocol;
        } else {
            this.flowId =
                    this.getDestinationIP()
                            + "-"
                            + this.getSourceIP()
                            + "-"
                            + this.dstPort
                            + "-"
                            + this.srcPort
                            + "-"
                            + this.protocol;
        }
        return this.flowId;
    }

    public String getSourceIP() {
        return FormatUtils.ip(this.src);
    }

    public String getDestinationIP() {
        return FormatUtils.ip(this.dst);
    }

    public String fwdFlowId() {
        this.flowId =
                this.getSourceIP()
                        + "-"
                        + this.getDestinationIP()
                        + "-"
                        + this.srcPort
                        + "-"
                        + this.dstPort
                        + "-"
                        + this.protocol;
        return this.flowId;
    }

    public String bwdFlowId() {
        this.flowId =
                this.getDestinationIP()
                        + "-"
                        + this.getSourceIP()
                        + "-"
                        + this.dstPort
                        + "-"
                        + this.srcPort
                        + "-"
                        + this.protocol;
        return this.flowId;
    }
}
