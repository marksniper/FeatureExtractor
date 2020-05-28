# Feature Extractor

The **FeautureExtractor project** aims to release a self-contained jar that allows to generate a CVS file from pcap files.
The code is based on [CICFlowmeter-V4.0](https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter) and [jNetPcap](https://github.com/ruedigergad/clj-net-pcap/tree/master/jnetpcap).

## Improvement 

- Use _Apache Camel_ for file consuming
- Manage the output values can be saved into CVS through **.properties** files. As the following table shows, two different dataset are created

| Value | UCI-IDS-2018 |test|KDD data set and NSL-KDD data set|
|-------|-----------------------------|--------|--------|
Flow ID | no| | no|
Src IP | no| | no |
Src Port | | | land (1 if connection is opened with the same host/port, otherwise 0) |
Dst IP| no | | no |
Dst Port| | | land (1 if connection is opened with the same host/port, otherwise 0) |
Protocol| | | protocol\_type |
Flow Duration | | | Duration | 
Tot Fwd Pkts| | | src_bytes |
Tot Bwd Pkts| | | dst_bytes |
TotLen Fwd Pkts| | no|
TotLen Bwd Pkts| | no|
Fwd Pkt Len Max| | no|
Fwd Pkt Len Min| | no|
Fwd Pkt Len Mean| | no|
Fwd Pkt Len Std| | no|
Bwd Pkt Len Max| | no|
Bwd Pkt Len Min| | no|
Bwd Pkt Len Mean| | no|
Bwd Pkt Len Std| | no|
Flow Byts/s| | no|
Flow Pkts/s   | | |  no| 
Flow IAT Mean  | | | no|
Flow IAT Std| | no|
Flow IAT Max| | no|
Flow IAT Min| | no|
Fwd IAT Tot| | no|
Fwd IAT Mean| | no|
Fwd IAT Std| | no|
Fwd IAT Max| | no|
Fwd IAT Min| | no|
Bwd IAT Tot| | no|
Bwd IAT Mean| | no|
Bwd IAT Std| | no|
Bwd IAT Max| | | no|
Bwd IAT Min| | |no|
Fwd PSH Flags| | |no|
Bwd PSH Flags| | |no|
Fwd URG Flags| | |no|
Bwd URG Flags| | |no|
Fwd Header Len| | |no|
Bwd Header Len| | |no|
Fwd Pkts/s| | |no|
Bwd Pkts/s  | | | no|     
Pkt Len Min   | | | no|
Pkt Len Max| | |no|
Pkt Len Mean| | |no|
Pkt Len Std    | | |   
Pkt Len Var      | | |no|
FIN Flag Cnt      | | |no|
SYN Flag Cnt| | |no|
RST Flag Cnt| | |no|
PSH Flag Cnt| | |no|
ACK Flag Cnt| | |no|
URG Flag Cnt| | |urgent|
CWR Flag Count| | |no|
ECE Flag Cnt| | |no|
Down/Up Ratio| | |no|
Pkt Size Avg| | |no|
Fwd Seg Size Avg| | |no|
Bwd Seg Size Avg| | |no|
Fwd Byts/b Avg| | |no|
Fwd Pkts/b Avg| | |no|
Fwd Blk Rate Avg| | |no|
Bwd Byts/b Avg| | |no|
Bwd Pkts/b Avg| | |no|
Bwd Blk Rate Avg| | |no|
Subflow Fwd Pkts| | |no|
Subflow Fwd Byts| | |no|
Subflow Bwd Pkts| | |no|
Subflow Bwd Byts| | |no|
Init Fwd Win Byts| | |no|
Init Bwd Win Byts| | |no|
Fwd Act Data Pkts| | |no|
Fwd Seg Size Min| | |no|
Active Mean| | |no|
Active Std| | |no|
Active Max| | |no|
Active Min| | |no|
Idle Mean| | |no|
Idle Std| | |no|
Idle Max| | |no|
Idle Min| | |no|
Label| no | | no|

- Create personal data set using  **.properties**. Comment, with _#_, the not desired columns in file CVS
- Rename columns: the _CWR Flag Count_ is correct and **not** **CWE Flag Count**. Considering [wiki](https://en.wikipedia.org/wiki/Transmission_Control_Protocol), it defines the CWR (1 bit): Congestion window reduced (CWR) flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism. You can also convalidate its, navigating into the code (_Protocol.java_ the Tcp -> decompiling org.jnetpcap.protocol.tcpip.Tcp the attribute CWR flag is declared as private static final int FLAG_CWR = 128;)
- Self libraries' extraction in runtime 
- Set **pcap.files.source.dir**
- Set **csv.output.dir**
- Install g++ and libpcap-dev

## Run

- Install maven artifact
```mvn
mvn install:install-file -Dfile=jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
```

- Create artifact
```mvn
mvn clean package
```

- Run jar
```bash
java -jar FeatureExtractor-1.0-SNAPSHOT-jar-with-dependencies.jar 
```

## Debug

- Run jar appending the remote debug
```bash 
java -jar -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005  FeatureExtractor-1.0-SNAPSHOT-jar-with-dependencies.jar
```

- Configure in Intellij remote debug

## Test

The code was tested only on UNIX-based machine (Fedora 31).