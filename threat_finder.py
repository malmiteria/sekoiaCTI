import csv
import sys
import datetime
import certstream
from french_bank_keywords import KEYWORDS as bank_keywords


with open('top-1m.csv') as top1m:
    reader = csv.reader(top1m, delimiter=',')
    known_safe_domain = [domain_name for _ , domain_name in reader]

def all_cert_update_domains(message):
    if message['message_type'] == "certificate_update":
        yield from message['data']['leaf_cert']['all_domains']

def all_keywords_in_domain(domain):
    for keyword in bank_keywords:
        if keyword in domain:
            yield keyword

def all_cert_with_keyword(message):
    for domain in all_cert_update_domains(message):
        if len(keywords := list(all_keywords_in_domain(domain))):
            yield domain, keywords

def print_callback(message, context):
    for domain, keywords in all_cert_with_keyword(message):
        if domain not in known_safe_domain:
            sys.stdout.write(", ".join(keywords) + "=====" + domain + '\n')
            #sys.stdout.write(u"{} ==== [{}] {} (SAN: {})\n".format(keyword, datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])))
            sys.stdout.flush()

certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')








# find all new certificates with certstream

# filter them all based on the if they have keywords in the list, and are not known to be safe.

# return result, as a file for example.
