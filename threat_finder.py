import csv
import sys
import getopt
import certstream
from french_bank_keywords import KEYWORDS as bank_keywords

class ThreatFinder:

    def __init__(self, output_filename, no_file, verbose):
        self.output_filename = output_filename
        self.no_file = no_file
        self.verbose = verbose
        with open('top-1m.csv') as top1m:
            reader = csv.reader(top1m, delimiter=',')
            self.known_safe_domain = [domain_name for _ , domain_name in reader]

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
        with open('threats/{}.csv'.format(self.output_filename), 'a') as f:
            csv_file = csv.writer(f, delimiter=';')
            csv_file.writerow([domain, keywords_list])

    def print_callback(self, message, context):
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
    certstream.listen_for_events(tf.print_callback, url='wss://certstream.calidog.io/')
