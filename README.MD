#Feature Extractor
The **FeautureExtractor project** aims to release a self-contained jar that allows to generate a CVS file from pcap files.
The code is based on [CICFlowmeter-V4.0](https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter).

##Improvement 
- Use _Apache Camel_ for file consuming
- Manage the output values can be saved into CVS through **.properties** files. As the following table shows, two different dataset are created

| Value | UCI-IDS-2018 |test|
|-------|-----------------------------|--------|
Flow ID | no| |
Src IP | no| |
Src Port | | |
Dst IP| no | |
Dst Port| | |
Protocol| | |
Flow Duration | | |
Tot Fwd Pkts| | |
Tot Bwd Pkts| | |
TotLen Fwd Pkts| | |
TotLen Bwd Pkts| | |
Fwd Pkt Len Max| | |
Fwd Pkt Len Min| | |
Fwd Pkt Len Mean| | |
Fwd Pkt Len Std| | |
Bwd Pkt Len Max| | |
Bwd Pkt Len Min| | |
Bwd Pkt Len Mean| | |
Bwd Pkt Len Std| | |
Flow Byts/s| | |
Flow Pkts/s   | | |   
Flow IAT Mean  | | | 
Flow IAT Std| | |
Flow IAT Max| | |
Flow IAT Min| | |
Fwd IAT Tot| | |
Fwd IAT Mean| | |
Fwd IAT Std| | |
Fwd IAT Max| | |
Fwd IAT Min| | |
Bwd IAT Tot| | |
Bwd IAT Mean| | |
Bwd IAT Std| | |
Bwd IAT Max| | |
Bwd IAT Min| | |
Fwd PSH Flags| | |
Bwd PSH Flags| | |
Fwd URG Flags| | |
Bwd URG Flags| | |
Fwd Header Len| | |
Bwd Header Len| | |
Fwd Pkts/s| | |
Bwd Pkts/s  | | |     
Pkt Len Min   | | |   
Pkt Len Max| | |
Pkt Len Mean| | |
Pkt Len Std    | | |   
Pkt Len Var      | | |
FIN Flag Cnt      | | |
SYN Flag Cnt| | |
RST Flag Cnt| | |
PSH Flag Cnt| | |
ACK Flag Cnt| | |
URG Flag Cnt| | |
CWR Flag Count| | |
ECE Flag Cnt| | |
Down/Up Ratio| | |
Pkt Size Avg| | |
Fwd Seg Size Avg| | |
Bwd Seg Size Avg| | |
Fwd Byts/b Avg| | |
Fwd Pkts/b Avg| | |
Fwd Blk Rate Avg| | |
Bwd Byts/b Avg| | |
Bwd Pkts/b Avg| | |
Bwd Blk Rate Avg| | |
Subflow Fwd Pkts| | |
Subflow Fwd Byts| | |
Subflow Bwd Pkts| | |
Subflow Bwd Byts| | |
Init Fwd Win Byts| | |
Init Bwd Win Byts| | |
Fwd Act Data Pkts| | |
Fwd Seg Size Min| | |
Active Mean| | |
Active Std| | |
Active Max| | |
Active Min| | |
Idle Mean| | |
Idle Std| | |
Idle Max| | |
Idle Min| | |
Label| no | |

- Create personal data set using  **.properties**. Comment, with _#_, the not desired columns in file CVS
- Rename columns: the _CWR Flag Count_ is correct and **not** **CWE Flag Count**. Considering [wiki](https://en.wikipedia.org/wiki/Transmission_Control_Protocol), it defines the CWR (1 bit): Congestion window reduced (CWR) flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism. You can also convalidate its, navigating into the code (_Protocol.java_ the Tcp -> decompiling org.jnetpcap.protocol.tcpip.Tcp the attribute CWR flag is declared as private static final int FLAG_CWR = 128;)
- Self libraries' extraction in runtime 
- Set **pcap.files.source.dir**
- Set **csv.output.dir**

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