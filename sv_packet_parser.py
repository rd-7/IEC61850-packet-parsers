import pyshark
from pymongo import MongoClient
from datetime import datetime

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["sv_db"]
collection = db["sv_packets"]
print("MongoDB connected.")

# PCAP file path
pcap_file = "C:/Users/rahuld/Desktop/pcap_files/IEC61855/sv.pcap"  # Change this to your file path
print(f"Reading file: {pcap_file}")

def parse_sv_packet(packet):
    try:
        if not hasattr(packet, 'sv'):
            return None

        sv_layer = packet.sv

        parsed_data = {
            "timestamp": str(packet.sniff_time),
            "source_mac": packet.eth.src,
            "destination_mac": packet.eth.dst,
            "appid": sv_layer.get("appid", None),
            "sample_count": sv_layer.get("savPdu.seqASDU.smpCnt", None),
            "conf_rev": sv_layer.get("savPdu.seqASDU.confRev", None),
            "ref_time": sv_layer.get("savPdu.seqASDU.refrTm", None),
            "sample_data_raw": sv_layer.get("savPdu.seqASDU.data", None)
        }

        return parsed_data

    except AttributeError:
        return None

def capture_and_store(pcap_path):
    cap = pyshark.FileCapture(pcap_path, display_filter='sv')

    for packet in cap:
        sv_data = parse_sv_packet(packet)
        if sv_data:
            collection.insert_one(sv_data)
            print(f"Packet stored at {sv_data['timestamp']}")
    cap.close()
    print("🎯 Capture complete.")

# Run the parser
capture_and_store(pcap_file)
