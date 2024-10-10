# Firewall Implementation and Testing in P4

## 1. Overview
In this project, we propose the implementation of a firewall using P4 within an SDN environment. The primary aim is to leverage P4’s protocol-independent packet processing capabilities to create a flexible and efficient firewall that can dynamically handle security threats such as Denial of Service (DoS) attacks and enforce custom security policies.

## 2. Goal
- Learn how to implement SDN-based firewalls.
- Gain experience with P4 and understand its key features for programming network devices.
- Develop and enforce customized security policies within a simulated network environment.
-
-
-
- Implement a P4-based firewall capable of detecting and mitigating DoS attacks.
- Evaluate the performance and effectiveness of the implemented firewall solution.

## 3. Equipment
- None required.

## 4. Experimental Environment
**Network Simulations:**
- Use Mininet topology to simulate a network with multiple hosts and switches.
- The topology will include at least a couple of switches and a similar number of hosts.
- The topology will be linear.

**P4 Runtime:**
- Deploy BMv2 switches programmed with custom P4 code.
- Use the P4Runtime API for dynamic control over the switches’ behavior.

**Other Tools:**
- Use `scapy`, `hping3`, and `iperf` to assess the impact of the firewall on network traffic.
- Implement robust logging in P4 and capture data with Wireshark.

## 5. Functionality

### DoS Attack Mitigation:
- Detect and block traffic patterns characteristic of DoS attacks (e.g., high-rate SYN packets, ICMP floods).
- Implement rate-limiting/blocking for specific traffic types to prevent resource exhaustion.

### Custom Security Policies:
- Allow or deny traffic based on IP addresses, port numbers, and protocols.
- Support both whitelist and blacklist approaches for traffic filtering.

### Logging and Alerting:
- Record details of blocked packets for auditing and analysis.
- Generate alerts when thresholds or patterns indicative of an attack are detected.

### Protocol Support:
- Parse and inspect headers for Ethernet, IPv4, TCP, UDP, and ICMP protocols.
- Extend to support additional protocols if required.

## 6. Approach

**Phase 1: Environment Setup**
- Install necessary software, including Mininet, the P4 compiler, and BMv2.
- Validate the setup with a simple P4 program to ensure correct installation.

**Phase 2: P4 Program Development**
- Define custom headers and metadata needed for firewall functionality.
- Implement parsing logic for required protocols.

**Phase 3: Basic Firewall Rules Implementation**
- Create tables and actions for basic packet filtering based on predefined rules.
- Test packet forwarding and dropping based on simple ACLs.

**Phase 4: DoS Detection Mechanisms**
- Incorporate counters and meters to monitor traffic flow rates.
- Implement logic to identify abnormal traffic patterns indicative of DoS attacks.
- Develop actions to block or rate-limit offending traffic.

**Phase 5: Testing and Validation**
- Simulate normal and attack traffic to evaluate firewall performance.
- Measure metrics such as packet loss, latency, and throughput under different scenarios.

**Phase 6: Documentation and Reporting**
- Document the development process, challenges faced, and solutions implemented.
- Compile results and analyses into the final report.

## 7. Report
The report should present detailed specifications of all the implemented components, project options, network architecture, and details on the interconnection of all equipment, as well as a description of the developed modules. It should complement the specifications provided in this document with deployment options taken during development.

The report should include validation test results of the implemented architecture and a reflection on system characterization for merit evaluation.

## 8. Bibliography
- [Firewall Implementation Reference](https://ieeexplore.ieee.org/document/8599726)
- [P4 Specification Documentation](https://p4.org/p4-spec/docs/P4-16-v1.0.0-spec.html)
- [P4 Tutorials GitHub Repository](https://github.com/p4lang/tutorials)

---

**PROGRAMMABLE NETWORKS – MEEC/METI**

_Last updated: 07/10/24_
