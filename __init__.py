import sys
import datetime
import certstream
from french_bank_keywords import KEYWORDS as bank_keywords


def all_cert_update_domains(message):
    if message['message_type'] != "certificate_update":
        return
    yield from message['data']['leaf_cert']['all_domains']

def print_callback(message, context):
    for domain in all_cert_update_domains(message):
        for keyword in bank_keywords:
            if keyword in domain:
                sys.stdout.write(u"{} ==== [{}] {} (SAN: {})\n".format(keyword, datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
                sys.stdout.flush()

certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')








# find all new certificates with certstream

# filter them all based on the if they have keywords in the list, and are not known to be safe.

# return result, as a file for example.
