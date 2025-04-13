# **Project Description**
This project implements the dataplane of a router as part of a networking assignment. The goal is to handle **IPv4 routing**, **ARP protocol**, and **ICMP functionality**. The implementation was tested using tools like `ping`, `traceroute`, and `Wireshark` to ensure correctness. Below, I describe the solution and the sub-requirements that were implemented.

---

# ** Implemented Features**

## **1. IPv4 Routing (30p)**
### ** Implementation Details**
- Decremented **TTL** and recalculated the checksum.
- Checked if the packet is destined for the router or needs to be forwarded.
- Forwarded packets to the next hop based on the routing table.
- Used a **static ARP table** for initial testing.
- Lifted certain functions and calls from lab4.

### **✅ Verification**
- Verified functionality using `ping` and `Wireshark`.

---

## **2. Longest Prefix Match (16p)**
### **️ Implementation Details**
- Replaced the linear search for routing table entries with a **trie-based LPM** implementation.
- The trie efficiently matches the longest prefix for the destination IP address.
- This optimization improves performance for large routing tables.

---

## **3. ARP Protocol (33p)**
### **Implementation Details**
- Implemented dynamic ARP functionality:
    - Sent **ARP requests** for unknown MAC addresses.
    - Cached **ARP replies** in the ARP table for future use.
    - Forwarded packets after receiving ARP replies.
- Implemented a **queue** to store packets while waiting for ARP replies.

### **✅ Verification**
- Verified functionality using **Wireshark**.

### **Notes**
- The ARP table entries are **initialized** and **permanent** for simplicity during each run.

---

## **4. ICMP Protocol (21p)**
### **Implementation Details**
- Implemented ICMP functionality:
    - Responded to **ICMP Echo Requests** (ping).
    - Sent **ICMP Time Exceeded** messages for packets with TTL ≤ 1.
    - Sent **ICMP Destination Unreachable** messages for packets with no matching route.

### **✅ Verification**
- Verified functionality using `ping -t 1` and `ping -c 1 h1`.

---

# **Testing and Debugging**

## **Tools Used**
- **`ping`**  for testing ICMP functionality.
- **Wireshark** for packet inspection and debugging.

## **Static ARP Table**
- Used for initial testing but replaced with dynamic ARP implementation.

---

# **📊 Sub-requirements Summary**

| **Sub-requirement**            | **Status**       |
|--------------------------------|------------------|
| **IPv4 Routing**               | ✅ Implemented   |
| **Longest Prefix Match (Trie)**| ✅ Implemented   |
| **ARP Protocol (Dynamic + Queue)** | ✅ Implemented |
| **ICMP Protocol**              | ✅ Implemented   |

---
-