# Netlog (New) - Network Traffic Logger

Netlog --- network traffic logger built with C++17. It captures network packets from a live interface or PCAP file and streams them as JSON to Apache Kafka.

---

## ✨ Features

- Capture from **PCAP files** or **live interfaces**
- Supports **Berkeley Packet Filters (BPF)** for traffic filtering
- Stream packets to:
  - **Apache Kafka** (via `librdkafka`)
- Optimized Kafka sender for **lower latency** and **higher throughput**

---

## ⚙️ Build Instructions

Most of the dependencies are handled during the build process, but some may require prior preparation if not installed.
For this purpose, a configuration script is provided for both Windows and \*NIX based systems.
Do note the possibility of this script failing and requiring manual intervention depending on platform.
Covered ones are: Windows, MacOS, Linux (may fail depending on your package manager, see setup/setup.sh).

### Linux/macOS

```bash
git clone https://github.com/NetLog-IDS/netlog-new.git
cd netlog-new
./configure.sh
make debug
```

### Windows

In order to build on Windows, WinPcap or Npcap is required, along with the WinPcap development pack.
The configuration script tries to provide these using the chocolatey package manager by installing
WinPcap and fetching the development pack automatically.

```bash
git clone https://github.com/NetLog-IDS/netlog-new.git
cd netlog-new
configure.bat
make debug
```

If manually:

- Install WinPcap or Npcap (Npcap is recommended)
- Get [WinPcap developer pack](https://www.winpcap.org/devel.htm) and place it in the `spoofy\ext` folder.
- Run `make debug`

---

## 🧪 Approaches

### 🔁 Approach 1: Replay from PCAP File (Offline Mode)

📘 **For Chapter 4: Netlog Performance Improvements**

Test Netlog's **throughput performance** by using recorded `.pcap` files.  
This mode **simulates heavy traffic** by sniffing and storing packets first, then **replaying them in an infinite loop** to Kafka.

#### ✅ Local

```bash
sudo ./build/bin/spoofy \
  -i ./utils/pcap/dos_first_100k.pcap \
  -f 'tcp or udp' \
  --sender kafka \
  --broker localhost:19092 \
  --topic network-traffic \
  --replay
```

#### ✅ Docker

```bash
sudo docker run \
  --rm \
  -it \
  --name netlog \
  --hostname netlog \
  -v ./first_10k.pcap:/test.pcap \
  -v "$(pwd)/utils/eval/throughput:/app/utils/eval/throughput" \
  --network host \
  --entrypoint bash \
  recedivies09/bab4-netlog-new:latest \
  -c "/usr/local/bin/spoofy \
      -i /test.pcap \
      -f 'tcp or udp' \
      --sender kafka \
      --broker 54.167.250.209:19092 \
      --topic network-traffic \
      --replay"
```

### 🌐 Approach 2: Real-Time (Live Mode)

📘 **For Chapter 6: End-to-End Scenario**

Test Netlog in a real-world environment by capturing live network packets and streaming them directly to Kafka in near real-time.
Netlog uses concurrent threading to capture and send packets in parallel.

#### ✅ Local

```bash
sudo ./build/bin/spoofy \
  -i wlo1 \
  --live \
  -f 'tcp or udp' \
  --sender kafka \
  --broker localhost:19092 \
  --topic network-traffic
```

#### ✅ Docker

```bash
sudo docker run \
  -d \
  -it \
  --rm \
  --name netlog \
  --hostname netlog \
  --network host \
  --entrypoint bash \
  recedivies09/netlog-new:latest \
  -c "/usr/local/bin/spoofy \
      -i lo \
      --live \
      -f 'tcp or udp' \
      --sender kafka \
      --broker 44.220.147.84:19092 \
      --topic network-traffic"
```

## 🧾 Command-Line Flags

| Flag       | Description                                   |
| ---------- | --------------------------------------------- |
| `-i`       | Interface name or PCAP file path              |
| `-f`       | BPF filter expression (e.g., `'tcp or udp'`)  |
| `--live`   | Capture packets from a live network interface |
| `--sender` | Output mode: `kafka`                          |
| `--broker` | Kafka broker address                          |
| `--topic`  | Kafka topic to stream data                    |
| `--replay` | Enable infinite loop streaming                |

## 🛠️ Dependencies

- [libpcap](https://www.tcpdump.org/)
- [librdkafka](https://github.com/confluentinc/librdkafka)
- [cmake](https://cmake.org/)
- [libtins](https://github.com/mfontanini/libtins)
- [catch2](https://github.com/catchorg/Catch2)
- [cclap](https://github.com/adriancostin6/cclap)
