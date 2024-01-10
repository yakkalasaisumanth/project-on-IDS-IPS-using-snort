# Project on IDS & IPS.

# IDS(Intrusion Detection System).

- An intrusion detection system (IDS) refers to a network security software or device to identify malicious activities and threats and alerts and logs them.

- Features of IDS.
   - Alerts(Detects)
   - Log(event tracker)

- We often listen NIDS & HIDS Means NIDS(Network Intrusion Detection System) which monitors the entire network including the subnets also. HIDS(Host Intrusion Detection System). which monitors only the Hosts or it traffics the network on single end point.

- the features of the NIDS & HIDS are the same as IDS.

# Intrusion Prevention System(IPS).

- An intrusion prevention system (IPS) refers to a network security software or device to identify malicious activities and threats and prevent them.Since it works for both detection and prevention, it’s also called the Identity Detection and Prevention System (IDPS).

- Features of IPS.
   - Alerts(Detects)
   - Log(Event tracker)
   - Drop(Detected packet)
   - Rejects(Entire Traffic)

- We often listen NIDS & HIDS Means NIPS(Network Intrusion Prevention System) which monitors the entire network including the subnets also. HIpS(Host Intrusion Prevention System). which monitors only the Hosts or it traffics the network on single end point.

- the features of the NIPS & HIPS are the same as IPS.

## How IDS & IPS Works.

- there are set of **RULES**

- If the traffic pattern matches the rules then the IDS detects and alerts us.

- If the traffic pattern matches the rules then the IPS detects and alerts and also Drops Or Rejects the Traffic as prescribed by the rule.

- Type Of the rules.

 1. Signatures.

   - signatures are the rules or the technique relayed on the known malicious behavior.

   - for example antivirus, defenders,etc,.

 2. Behavior Based.

   - In this we train the software with the normal behavior and abnormal behavior. which is useful to identify the malicious traffic.

   - for example normal behavior means HTTPS, tcp, udp and abnormal behavior means like ftp, ssh, tenet, smtpd, etc,.

 3. Policy Based.
 
   -  it is a security and system configuration based.

   - windows group policy, license, etc,.

# Snort.

- it is an IDS and IPS Tool.

- it can analyses the live traffic and triggers the alerts and logs and drops and rejects lively.

- it can log packets for later analysis.

- it can sniff the packets.

- snort needs some rules to run.

1. snort config
  
  - it contains the path to rules.

  - it contains the plugins and connects them to config file.

  - it contains some variables example source net(source network) and also the external network.(any).

  - path = /etc/snort/snort.config

  - rules path = /etc/snort/local.rules

2. Snort modes
  1. sniffer mode
  2. packet logger
  3. NIDS/NIPS

## We Can Understand The Snort In Better ways By THe Following TryHackme machine.

- i realty appreciate the team of TryHackme who really helping others to train in cyber security.

- lets talk about the machine.

- machine name :- snort 

- you can access the machine by clicking the link bellow.

- link :- [snort](https://tryhackme.com/room/snort)

## task 1 consists of the general information.

- i highly recommend to read that because there is a lot of useful  information.

- please click the start attack box to start the virtual machine and click the split button to split the screen.

- ![tryhackme snort](https://github.com/yakkalasaisumanth/project-on-IDS-IPS-using-snort/blob/main/images/snort%201.png)

## task 2 consists of general information regarding the snort 2.

1. Navigate to the Task-Exercises folder and run the command "./.easy.sh" and write the output
```
sudo ./.easy.sh
```

- ![tryhackme snort1](https://github.com/yakkalasaisumanth/project-on-IDS-IPS-using-snort/blob/main/images/first%20answer.png)

- use the above command to answer the question.

## task 3 consists of the IDS, IPS, HIDS, HIPS, NIPS & NIDS. and the modes of the snort nad the rules based, etc,.

1. Which snort mode can help you stop the threats on a local machine?

- answer
```
HIPS
```

2. Which snort mode can help you detect threats on a local network?

- answer
```
NIDS
```

3. Which snort mode can help you detect the threats on a local machine?

- answer
```
HIDS
```

4. Which snort mode can help you stop the threats on a local network?

- answer
```
NIPS
```

5. Which snort mode works similar to NIPS mode?

- answer
```
NBA
```

6. According to the official description of the snort, what kind of NIPS is it?

- answer
```
full-blown
```
- this is a tricky question which requires you to read documentation carefully 

- link :- [documentation](https://www.snort.org/)

7. NBA training period is also known as ...

- answer
```
baselining
```

## task 4 first interaction with snort this task consists of how to start snort 2

1. Run the Snort instance and check the build number.

- command
```
sudo snort -V
sudo snort -version
```
- use the following command to get the answer

- answer
```
149
```

- ![tryhackme snort20](https://github.com/yakkalasaisumanth/project-on-IDS-IPS-using-snort/blob/main/images/snort%20version.png)

2. Test the current instance with "/etc/snort/snort.conf" file and check how many rules are loaded with the current build.

- command
```
sudo snort -c /etc/snort/snort.conf -T
```

- answer
```
4151
```

- ![snort rules](https://github.com/yakkalasaisumanth/project-on-IDS-IPS-using-snort/blob/main/images/snort%20rules.png)

- ![snort commands](https://github.com/yakkalasaisumanth/project-on-IDS-IPS-using-snort/blob/main/images/snort%20basic%20commands.png)

3. Test the current instance with "/etc/snort/snortv2.conf" file and check how many rules are loaded with the current build.

- command
```
sudo snort -c /etc/snort/snortv2.conf -T
```

- answer
```
1
```

- ![snort2 rule](https://github.com/yakkalasaisumanth/project-on-IDS-IPS-using-snort/blob/main/images/snort%20rules%201.png)

## Task 5 Operation mode 1. sniffer mode.

-  this task defines the first operation mode of snort which is sniffer mode.

-  as the name sugessts this mode is used sniff the data and log the data.

- to run the sniffer mode in the snort there are some options.

1. |Parameter       |    Description |
1. |-v              | Verbose Display the TCP/IP output in the console.|
2. |-d              |Display the packet data (payload).|
3. |-e              |Display the link-layer (TCP/IP/UDP/ICMP) headers.| 
4. |-X              |Display the full packet details in HEX.|
5. |-i              |This parameter helps to define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff. |



- Note that you can use the parameters both in combined and separated form as follows;
```
    snort -v
    snort -vd
    snort -de
    snort -v -d -e
    snort -X
```

- now just select the completed.

## task 6 operation mode 2. packet logger mode.

- this task consists of snort running  in the logger mode which helps to collect all the traffics and saves them in a log file.


- parameters of the snort 2 in logger mode.

1. |Parameter   | Description              |
2. |-l          |   Logger mode, target log and alert output directory. Default output folder is /var/log/snort|

3. |-l          |The default action is to dump as tcpdump format in /var/log/snort|
4. |-K          |ASCII  Log packets in ASCII format.|
5. |-r          |Reading option, read the dumped logs in Snort.|
6. |-n          |Specify the number of packets that will process.|

- you might require log file ownership or root privileges, so please make sure of that.

- some of the snort 2 logging commands.
```
sudo snort -r logname.log -X
sudo snort -r logname.log icmp
sudo snort -r logname.log tcp
sudo snort -r logname.log 'udp and port 53'
```

- ![snort vmimg](https://github.com/yakkalasaisumanth/project-on-IDS-IPS-using-snort/blob/main/images/snort%20vm%20and%20folder.png)

1. Investigate the traffic with the default configuration file with ASCII mode.

- on the desktop you will find the task-exersises folder

- open the folder and right click on it and select open in terminal.

- now paste the following command.
```
sudo ./traffic-generator.sh
```

- now select the task 6 and wait util the scan is complete.

- now open the task 6 folder in the exersise folder and right click and open in terminal.

- now type the following command.
```
sudo snort -dev -K ASCII -l .
```
or you can use 
```
sudo   snort -dev -k ASCII -l . | grep 145.254.160.237
```

- answer
```
3009
```
2.  Read the snort.log file with Snort; what is the IP ID of the 10th packet?

- command
```
snort -r snort.log.1640048004 -n 10
```

- answer
```
49313
```

3. Read the "snort.log.1640048004" file with Snort; what is the referrer of the 4th packet?

- command
```
sudo snort -r snort.log.1640048004 -x -n4
```

- answer
```
http://www.ethereal.com/development.html
```

- ![snort reffer](https://github.com/yakkalasaisumanth/project-on-IDS-IPS-using-snort/blob/main/images/snort%20referer.png)

4. Read the "snort.log.1640048004" file with Snort; what is the Ack number of the 8th packet?

- command
```
sudo snort -r snort.log.1640048004 -n 8
```
or
```
sudo   snort -r snort.log.1640048004 -n 8 | grep ack
```
- answer
```
0x38AFFFF3
```

5. Read the "snort.log.1640048004" file with Snort; what is the number of the "TCP port 80" packets?

- command
```
sudo snort -r snort.log.1640048004 tcp
```

- answer
```
41
```

## task 7 operation mode 3. IDS/IPS

- in this task we see how we can detect the unusual traffic using the pre defined rules and we are going to create our own rules as well.

- some commands

1. |Parameter    |  Description |
2. | -c          | Defining the configuration file.|
3. |-T           |Testing the configuration file.|
4. |-N           |Disable logging.|
5. |-D           |Background mode.|
6. | -A          | full: Full alert mode, providing all possible information about the alert. This one also is the default mode; once you use -A and don't specify any mode, snort uses this mode.|
7. | -A          | fast:  Fast mode shows the alert message, times|
8. | -A          |console: Provides fast style alerts on the console|
9. | -A          |cmg: CMG style, basic header details with payload|
10. | -A         | none: Disabling alerting|

- ![snort rule1](https://github.com/yakkalasaisumanth/project-on-IDS-IPS-using-snort/blob/main/images/snort%20rules%20description.png)

- Basic snort rule of blocking the ICMP traffic example of snort rule.
```
alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)
```

- you can access the rules from the path
```
/etc/snort/rules/local.rules
```

1. What is the number of the detected HTTP GET methods?

- first open the task exersise folder and right click and open in the terminal.

- now run
```
sudo ./traffic-generator.sh
```

- and select the task 7 option and wait until it scans.

- now open the task 7 folder and right click and open in terminal.

- command
```
sudo snort -c /etc/snort/snort.conf -A full -l . | grep HTTP
```

- answer
```
2
```

2.  You can practice the rest of the parameters by using the traffic-generator script.

- answer
  - simply press completed.


## task 8 operation mode 4. PCAP Investigation.

- common options of a PCAP file.

1. |Parameter   |  Description  | 
2. |-r / --pcap-single=| Read a single pcap|
3. |--pcap-list=""|  Read pcaps provided in command (space separated).|
4. |--pcap-show |Show pcap name on console during processing.|


- example command
```
sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -A console -n 10
```

1. Investigate the mx-1.pcap file with the default configuration file.

- open the task exersise -> exersise-file -> task 8

- now right click and open in the terminal.

- command
```
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap | grep alerts
```

-  answer
```
170
```

2. Keep reading the output. How many TCP Segments are Queued?

- command
```
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap | grep tcp
```

- answer
```
18
```

3. Keep reading the output.How many "HTTP response headers" were extracted?

- command
```
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap | grep HTTP response headers
```

- answer
```
3
```

4. Investigate the mx-1.pcap file with the second configuration file.

- command
```
sudo snort -c /etc/snort/snortv2.conf -A full -l . -r mx-1.pcap | grep alerts
```

- answer
```
68
```

5. Investigate the mx-2.pcap file with the default configuration file.

- command
```
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap | grep alerts
```

- answer
```
340
```

6. Keep reading the output. What is the number of the detected TCP packets?

- command
```
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap | grep tcp
```

- answer
```
82
```

7. Investigate the mx-2.pcap and mx-3.pcap files with the default configuration file.What is the number of the generated alerts?

- command
```
sudo snort -c /etc/snort/snort.conf -A full -l . --pcap-list="mx-2.pcap mx-3.pcap" | grep aletrs
```

- answer
```1020```

## task 9 snort rule structure.

- this task consists of the rule format it describes how we can create our own rules.

1. Write a rule to filter IP ID "35369" and run it against the given pcap file. What is the request name of the detected packet?

- open the task-exersises -> exersise-files -> task 9

- now right click and open in the terminal.

- command
```
snort -c local.rules -A full -l . -r task9.pcap | grep 35369
```

2. Create a rule to filter packets with Syn flag and run it against the given pcap file. What is the number of detected packets?

- rule command
```
alert -S any any <> any any (msg:"syn packet found";sid:10000001;rev:1;)
```

- add the following command to the newly created rules file

- path of the rules file
```
custom.rules
```

- in terminal follow the commands.
```
nano /etc/snort/rules/local.rules
```
- paste the above specified rule command

- command
```
snort -c custom.rules -r task9.pcap
```

- answer
```
1
```

3. Write a rule to filter packets with Push-Ack flags and run it against the given pcap file. What is the number of detected packets?

- we can use the above procedure but make sure to comment out the old rule

- rule command
```
alert -PA any any <> any any (msg:"push and ack packet found";sid:10000002;rev:2;)
```

- command
```
snort -c custom.rules -r task9.pcap
```

- answer
```
216
```



- Clear the previous log and alarm files and deactivate/comment out the old rule.

4. Create a rule to filter packets with the same source and destination IP and run it against the given pcap file. What is the number of packets that show the same source and destination address?


- answer
```
7
```

5. Case Example - An analyst modified an existing rule successfully. Which rule option must the analyst change after the implementation?

- answer
```
rev
```

 ## task 10 snort 2 operation logic: points to be remembered.

 - this task helps you with the point which you must keep in mind while working with the snort.

 - please don't skip and read the given documentation it is very useful .

 - task 10 conclusion.

 - it concludes the overall traffic and you can also download the snort 2 commands from there.


### Thank you so much for spending your valuable time.