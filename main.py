import socket
from utils import ethernet_head, arp_head, get_local_ip, get_ip_from_mac
import threading
import json
import atexit
import os
import logging
from datetime import datetime, timedelta
import subprocess

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)

dct = {}
lock = threading.Lock()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
ARP_REPLY_THRESHOLD = 5  
TIMEOUT_SECONDS = 60  # 5 minutes timeout
BLOCK_THRESHOLD = 10  # Threshold for blocking

blocked_ips = set()  # Maintain a set of blocked IPs

def block_ip(ip_address):
    try:
        #  Command to block the IP
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
        logger.warning(f"Blocked traffic from suspected IP: {ip_address}")
        blocked_ips.add(ip_address)  # Add the IP to the set of blocked IPs
    except Exception as e:
        logger.error(f"Error blocking IP: {e}")

def update_dict(arp, local_ip):
    with lock:
        sender_ip = arp[6]
        sender_mac = arp[5]
        target_ip = arp[8]
        arp_operation = arp[4]

        # Check if the sender is not my local IP and not blocked
        if sender_ip != local_ip and sender_ip not in blocked_ips:
            # Initialize or retrieve the entry for the sender IP
            entry = dct.setdefault(sender_ip, {"mac": sender_mac, "reply_count": 0, "last_reply_time": None})

            # Check if the target IP is my local IP
            if target_ip == local_ip:
                if arp_operation == "ARP Reply":
                    # Increment the ARP reply count for the sender
                    entry["reply_count"] += 1
                    # Check if the last reply was received more than TIMEOUT_SECONDS ago
                    if entry["last_reply_time"] is None or (datetime.now() - entry["last_reply_time"]).total_seconds() > TIMEOUT_SECONDS:
                        entry["reply_count"] = 1
                    else:
                        entry["reply_count"] += 1

                    # Check if the reply count exceeds the threshold
                    if entry["reply_count"] > ARP_REPLY_THRESHOLD:
                        logger.warning(f"Possible ARP spoofing detected! Received {entry['reply_count']} ARP replies from IP: {sender_ip}.")

                        # Check if the block threshold is reached
                        if entry["reply_count"] > BLOCK_THRESHOLD:
                            block_ip(sender_ip)

                        # Attempt to retrieve the IP associated with the MAC address
                        ip_address = get_ip_from_mac(sender_mac)
                        if ip_address:
                            logger.warning(f"The MAC address {sender_mac} is associated with the IP address {ip_address}.")

                    # Update the last reply time
                    entry["last_reply_time"] = datetime.now()


def initiate_dict():
    try:
        with open("arp_dict.json", "r") as json_file:
            loaded_dict = json.load(json_file)
            # Convert string representations of datetime to actual datetime objects
            for ip, entry in loaded_dict.items():
                if entry["last_reply_time"] is not None:
                    entry["last_reply_time"] = datetime.fromisoformat(entry["last_reply_time"])
            return loaded_dict
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        logger.error("Error decoding JSON. Using an empty dictionary.")
        return {}


def save_dict_to_json():
    with lock:
        try:
            with open("arp_dict.json", "w") as json_file:
                json.dump(dct, json_file, cls=DateTimeEncoder)
            logger.info("ARP dictionary saved to arp_dict.json.")
        except Exception as e:
            logger.error(f"Error saving dictionary to JSON: {e}")

def main():
    global dct
    try:
        local_ip = get_local_ip()
        if os.path.exists(f"{os.getcwd()}/arp_dict.json"):
            dct = initiate_dict()
            logger.info(f"Loaded ARP dictionary: {dct}")
        atexit.register(save_dict_to_json)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while True:
            raw_data, addr = s.recvfrom(65535)
            eth = ethernet_head(raw_data)
            if eth[2] == 1544:  # ARP
                arp = arp_head(eth[3])
                logger.debug('\t - ARP Packet:')
                logger.debug('\t\t - Hardware Type: {}, Protocol Type: {}'.format(arp[0], arp[1]))
                logger.debug('\t\t - Hardware Size: {}, Protocol Size: {}'.format(arp[2], arp[3]))
                logger.debug('\t\t - Operation: {}'.format(arp[4]))
                logger.debug('\t\t - Sender MAC: {}, Sender IP: {}'.format(arp[5], arp[6]))
                logger.debug('\t\t - Target MAC: {}, Target IP: {}'.format(arp[7], arp[8]))

                threading.Thread(target=update_dict, args=(arp, local_ip)).start()

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt: Exiting program.")
        save_dict_to_json()

if __name__ == "__main__":
    main()
