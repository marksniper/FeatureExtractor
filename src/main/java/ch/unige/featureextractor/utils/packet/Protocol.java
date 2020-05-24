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

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.vpn.L2TP;

public class Protocol {

  private final Tcp tcp;
  private final Udp udp;
  private final Ip4 ipv4;
  private final Ip6 ipv6;
  private final L2TP l2tp;

  public Protocol() {
    super();
    tcp = new Tcp();
    udp = new Udp();
    ipv4 = new Ip4();
    ipv6 = new Ip6();
    l2tp = new L2TP();
  }

  public Tcp getTcp() {
    return tcp;
  }

  public Udp getUdp() {
    return udp;
  }

  public Ip4 getIpv4() {
    return ipv4;
  }

  public Ip6 getIpv6() {
    return ipv6;
  }

  public L2TP getL2tp() {
    return l2tp;
  }
}
