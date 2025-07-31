import pyshark
from pymongo import MongoClient

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["ot_ids"]
collection = db["mms_packets"]
print("MongoDB connection done.")

def parse_mms_packet(packet):
    try:
        if not hasattr(packet, 'mms'):
            return None

        mms_layer = packet.mms

        parsed_data = {
            "timestamp": str(packet.sniff_time),
            "src_ip": packet.ip.src if hasattr(packet, 'ip') else None,
            "dst_ip": packet.ip.dst if hasattr(packet, 'ip') else None,
            "operation": mms_layer.get_field("mms.service") or None,
            "invoke_id": mms_layer.get_field("mms.invoke_id") or None,
            "variable_list_name": mms_layer.get_field("mms.variablelistname") or None,
            "access_result": mms_layer.get_field("mms.access_result") or None
        }

        return parsed_data

    except Exception as e:
        print("Error parsing packet:", e)
        return None

def capture_and_store_mms(pcap_file):
    print(f"Reading MMS packets from: {pcap_file}")
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="mms")
    except Exception as e:
        print(f"Error loading pcap: {e}")
        return

    for packet in capture:
        parsed = parse_mms_packet(packet)
        if parsed:
            try:
                collection.insert_one(parsed)
                print(parsed)
                print("MongoDB update done.")
            except Exception as db_err:
                print("MongoDB insert error:", db_err)

    capture.close()

# Just set your file path below and run the script
pcap_file_path = "/home/rahuld/pcap_files/IEC61850/mms.pcap"
capture_and_store_mms(pcap_file_path)
