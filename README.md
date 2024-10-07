FIREWALL IMPLEMENTATION AND TESTING IN P4
1. OVERVIEW 
In this project, we propose the implementation of firewall using P4 within a SDN environment. The primary aim of this project is to leverage P4’s protocol-independent packet processing capabilities to create flexible efficient firewall that can dynamically handle security threats such as Denials of Service attacks, and enforce custom security policies.
2. GOAL
Learn how to implement SDNs firewalls
Gain a experience with P4 and understand its key features in programing network devices. 
Develop and enforce customized security policies within simulated network environment. 
Implement P4-based firewall capable of detecting and mitigating DoS attacks
Evaluate the performance and effectiveness of the implemented firewall solution.
3. EQUIPMENT 
Nothing 
4. EXPERIMENTAL ENVIRONMENT
Network Simulations:
-Mininet topology to simulate network with multiple hosts and switches.
	-Topology will include at least couple of switches and similar number of hosts.
	-Topology is going to be linear
P4 Runtime:
	-Deployed BMv2 switches programmed with custom P4 code.
	-Employed P4Runtime API for dynamic control over the switches behavior 
Other:
	-Use scapy, hping3 and iperf to see impact on network working with firewall
	-Implement robust logging in P4 and capture data with Wireshark

5. FUNCTIONALITY 
DoS Attack Mitigation:
Detect and block traffic patterns characteristic of DoS attacks, such as high-rate SYN packets or ICMP floods.
Implement rate-limiting/blocking for certain types of traffic to prevent resource exhaustion.
Custom Security Policies:
Allow or deny traffic based on IP addresses, port numbers, and protocols.
Support for both whitelist and blacklist approaches for traffic filtering.

Logging and Alerting:
Record details of blocked packets for auditing and analysis.
Generate alerts when specific thresholds or patterns indicative of an attack are detected.

Protocol Support:
Parse and inspect headers for Ethernet, IPv4, TCP, UDP, and ICMP protocols.
Extendable to support additional protocols if required.
6. APPROACH	
Phase 1: Environment Setup
Install necessary software including Mininet, P4 compiler, and BMv2.
Validate the setup with a simple P4 program to ensure correct installation.
Phase 2: P4 Program Development
Define custom headers and metadata needed for firewall functionality.
Implement parsing logic for required protocols.
Phase 3: Basic Firewall Rules Implementation
Create tables and actions for basic packet filtering based on predefined rules.
Test packet forwarding and dropping based on simple ACLs.
Phase 4: DoS Detection Mechanisms
Incorporate counters and meters to monitor traffic flow rates.
Implement logic to identify abnormal traffic patterns indicative of DoS attacks.
Develop actions to block or rate-limit offending traffic.
Phase 5: Testing and Validation
Simulate normal and attack traffic to evaluate firewall performance.
Measure metrics such as packet loss, latency, and throughput under different scenarios.
Phase 6: Documentation and Reporting
Document the development process, challenges faced, and solutions implemented.
Compile results and analyses into the final report.
7. REPORT
The report should present a detailed specification of all the implemented components, project options, network architecture and details on the interconnection of all equipment as well as the description of the modules developed. It should, in particular, complement the specifications given in this document with all the deployment options taken during the development.
The report should include the results of the validation tests of the implemented architecture.
A justified reflection on the system characterization will be considered as a factor of merit.
8. BIBLIOGRAPHY
https://ieeexplore.ieee.org/document/8599726 
https://p4.org/p4-spec/docs/P4-16-v1.0.0-spec.html
https://github.com/p4lang/tutorials
