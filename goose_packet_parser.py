import pyshark
from pymongo import MongoClient
from datetime import datetime

# MongoDB Setup
client = MongoClient("mongodb://localhost:27017/")
db = client["goose_db"]
collection = db["packets"]
print("MongoDB connected.")

def parse_goose_packet(pkt, pcap_file):
    try:
        return {
            "timestamp": pkt.sniff_time,
            "frame_number": int(pkt.number),
            "eth_src": getattr(pkt.eth, "src", None),
            "eth_dst": getattr(pkt.eth, "dst", None),
            "gocbRef": getattr(pkt.goose, "gocbref", None),
            "goID": getattr(pkt.goose, "goid", None),
            "datSet": getattr(pkt.goose, "dataset", None),
            "stNum": int(getattr(pkt.goose, "stnum", 0)),
            "sqNum": int(getattr(pkt.goose, "sqnum", 0)),
            "confRev": int(getattr(pkt.goose, "confrev", 0)),
            "timeAllowedtoLive": int(getattr(pkt.goose, "timealiv", 0)),
            "numDatSetEntries": int(getattr(pkt.goose, "numdatsetentries", 0)),
            "test_flag": getattr(pkt.goose, "test", None),
            "ndsCom_flag": getattr(pkt.goose, "ndscom", None),
            "allData_raw": getattr(pkt.goose, "all_data", None),
            "file_name": pcap_file.split("/")[-1]
        }
    except AttributeError as e:
        print(f"[!] Skipping malformed packet: {e}")
        return None


def capture_and_store(pcap_file):
    print(f"Reading GOOSE packets from: {pcap_file}")
    cap = pyshark.FileCapture(pcap_file)  # temporarily no filter
    packet_count = 0

    for pkt in cap:
        print(f"Processing packet: {pkt.number}")
        result = parse_goose_packet(pkt, pcap_file)
        print(f"Parsed result: {result}")

        if result:
            try:
                collection.insert_one(result)
                packet_count += 1
                print(f"Inserted packet: {result['frame_number']}")
            except Exception as e:
                print(f"[!] Failed to insert: {e}")

    cap.close()
    print(f"\nDone. Total packets inserted: {packet_count}")


# Import pcap file
pcap_file = 'C:/Users/rahuld/Desktop/pcap_files/IEC61855/GOOSE.pcap'
capture_and_store(pcap_file)