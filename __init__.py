import logging
import sys
import datetime
import certstream


def all_cert_update_domains(message):
    if message['message_type'] != "certificate_update":
        return
    yield from message['data']['leaf_cert']['all_domains']

def print_callback(message, context):
    logging.debug("Message -> {}".format(message))
    for domain in all_cert_update_domains(message):
        for keyword in ['bank']:
            if keyword in domain:
                sys.stdout.write(u"[{}] {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
                sys.stdout.flush()

logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')








# find all new certificates with certstream

# filter them all based on the if they have keywords in the list, and are not known to be safe.

# return result, as a file for example.
