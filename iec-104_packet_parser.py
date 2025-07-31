import pyshark
from pymongo import MongoClient

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
collection = client["iec104_db"]["packets"]
print("MongoDB connected.")

# PCAP file path variable
pcap_file = "C:/Users/rahuld/Desktop/pcap_files/IEC61855/iec104.pcap"

# Load and parse packets
cap = pyshark.FileCapture(pcap_file)

for packet in cap:
    if not hasattr(packet, 'iec104'):
        continue

    try:
        iec = packet.iec104
        data = {
            'timestamp': packet.sniff_time.isoformat(),
            'type_id': getattr(iec, 'typeid', None),
            'cause': getattr(iec, 'cause', None),
            'asdu_address': getattr(iec, 'asdu_address', None),
            'ioa': getattr(iec, 'ioa', None),
            'value': getattr(iec, 'value', None),
            'quality': getattr(iec, 'quality', None),
            'tx_seq': getattr(iec, 'tx', None),
            'rx_seq': getattr(iec, 'rx', None),
            'frame_type': getattr(iec, 'iec104_frame_type', None)
        }
        print(data)
        collection.insert_one(data)
    except Exception as e:
        print(f"Error: {e}")

cap.close()
print("Done.")
