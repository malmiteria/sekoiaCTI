import csv
import getopt
import io
import os
import sys
import zipfile

import certstream
import requests

from french_bank_keywords import KEYWORDS as bank_keywords

class ThreatFinder:

    def __init__(self, output_filename, no_file, verbose):
        self.output_filename = output_filename
        self.no_file = no_file
        self.verbose = verbose
        
        self.download_safe_domains()

    def download_safe_domains(self):
        print('download safe domains, and write them in top-1m.csv file')
        r = requests.get('http://s3.amazonaws.com/alexa-static/top-1m.csv.zip') # redownload safe domains from the source to be sure to be up to date.
        z = zipfile.ZipFile(io.BytesIO(r.content))
        f = z.read('top-1m.csv').decode('utf-8')
        reader = csv.reader(io.StringIO(f), delimiter=',')
        self.known_safe_domain = [domain_name for _ , domain_name in reader]
        z.extractall() # keep it in a file, so we can check it after execution.
        z.close()
        print('done downloading safe domains')

    def all_cert_update_domains(self, message):
        if message['message_type'] == "certificate_update":
            yield from message['data']['leaf_cert']['all_domains']

    def all_keywords_in_domain(self, domain):
        for keyword in bank_keywords:
            if keyword in domain:
                yield keyword

    def all_cert_with_keywords(self, message):
        for domain in self.all_cert_update_domains(message):
            if len(keywords := list(self.all_keywords_in_domain(domain))):
                yield domain, keywords

    def threat_reports(self, domain, keywords):
        keywords_list = ", ".join(keywords)
        if self.verbose:
            sys.stdout.write(keywords_list + "=====" + domain + '\n')
            sys.stdout.flush()
        if self.no_file:
            return
        with open(self.threats_file(), 'a') as f:
            csv_file = csv.writer(f, delimiter=';')
            csv_file.writerow([domain, keywords_list])

    def threats_file(self):
        threats_dir = 'threats'
        if not os.path.exists(threats_dir):
            os.makedirs(threats_dir)
        return '{}/{}.csv'.format(threats_dir, self.output_filename)

    def report_all_threats(self, message, context):
        for domain, keywords in self.all_cert_with_keywords(message):
            if domain not in self.known_safe_domain:
                self.threat_reports(domain, keywords)

def parse_command(argv):
    output_file = "identified_threats"
    verbose = False
    no_file = False
    opts, args = getopt.getopt(argv, 'vnf:', ['verbose', 'no-file', 'filename'])
    for opt, arg in opts:
        if opt in ['-v', '--verbose']:
            verbose = True
        if opt in ['-n', '--no-file']:
            no_file = True
        if opt in ['-f', '--filename']:
            output_file = arg
    return output_file, no_file, verbose

if __name__ == "__main__":
    tf = ThreatFinder(*parse_command(sys.argv[1:]))
    certstream.listen_for_events(tf.report_all_threats, url='wss://certstream.calidog.io/')
