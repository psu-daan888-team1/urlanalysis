from cymruwhois import Client
import dns.resolver
import datetime
import ipaddress
from numpy import dtype
import os
import pandas as pd
import re
import requests
import string
import tldextract
from urllib.parse import urlparse, parse_qs
import whois


def count_chars(s):
    return {c:s.count(c) for c in list(string.printable)}


def build_counts(char_dict, t):
    d = dict()
    d['qty_dot_'+t] = char_dict['.']
    d['qty_hyphen_'+t] = char_dict['-']
    d['qty_underline_'+t] = char_dict['_']
    d['qty_slash_'+t] = char_dict['/']
    d['qty_questionmark_'+t] = char_dict['?']
    d['qty_equal_'+t] = char_dict['=']
    d['qty_at_'+t] = char_dict['@']
    d['qty_and_'+t] = char_dict['&']
    d['qty_exclamation_'+t] = char_dict['!']
    d['qty_space_'+t] = char_dict[' ']
    d['qty_tilde_'+t] = char_dict['~']
    d['qty_comma_'+t] = char_dict[',']
    d['qty_plus_'+t] = char_dict['+']
    d['qty_asterisk_'+t] = char_dict['*']
    d['qty_hashtag_'+t] = char_dict['#']
    d['qty_dollar_'+t] = char_dict['$']
    d['qty_percent_'+t] = char_dict['%']
    return d


def table_1_features(full_url, counts):
    # https://pypi.org/project/tldextract/
    counts['qty_tld_url'] = len(tldextract.extract(full_url).suffix)
    counts['length_url'] = len(full_url)
    # https://stackoverflow.com/questions/17681670/extract-email-sub-strings-from-large-document
    exp = r'(?:\.?)([\w\-_+#~!$&\'\.]+(?<!\.)(@|[ ]?\(?[ ]?(at|AT)[ ]?\)?[ ]?)(?<!\.)[\w]+[\w\-\.]*\.[a-zA-Z-]{2,3})(?:[^\w])'
    counts['email_in_url'] = bool(re.search(exp, full_url))
    
    return counts


def table_2_features(full_url, counts):
    d = tldextract.extract(full_url).domain
    counts['qty_vowels_domain'] = len([v for v in d.lower() if v in list('aeiou')])
    counts['domain_length'] = len(d)
    try:
        # https://docs.python.org/3/library/ipaddress.html
        ipaddress.ip_address(d)
        counts['domain_in_ip'] = True
    except ValueError:
        counts['domain_in_ip'] = False
    counts['server_client_domain'] = ('server' in d) or ('client' in d)
    return counts


def table_3_features(full_url, counts):
    # https://docs.python.org/3/library/urllib.parse.html
    d = os.path.split(urlparse(full_url).path)[0].lstrip('/')
    counts['directory_length'] = len(d)
    if len(d)==0:
        counts = {a: -1 for a in counts}
    return counts


def table_4_features(full_url, counts):
    f = os.path.split(urlparse(full_url).path)[1]
    counts['file_length'] = len(f)
    if len(f)==0:
        counts = {a: -1 for a in counts}
    return counts


def table_5_features(full_url, counts):
    q = urlparse(full_url).query
    counts['params_length'] = len(q)
    counts['tld_present_params'] = True if tldextract.extract(q).suffix else False
    counts['qty_params'] = len(parse_qs(q))
    if len(q)==0:
        counts = {a: -1 for a in counts}
    return counts


def table_6_features(full_url):
    # https://www.dnspython.org/examples.html
    # TODO: -1 if these tests do not resolve
    u = tldextract.extract(full_url)
    d = u.domain + '.' + u.suffix
    who = whois.whois(d)
    resp = requests.get('http://' + d)
    features = dict()
    features['time_response'] = dns.resolver.resolve(d).response.time * 1000
    # https://support.mailessentials.gfi.com/hc/en-us/articles/360015116520-How-to-check-and-read-a-Sender-Policy-Framework-record-for-a-domain
    features['domain_spf'] = 'spf' in str(dns.resolver.resolve(d, 'TXT').rrset)
    # https://github.com/JustinAzoff/python-cymruwhois
    cli=Client()
    res=cli.lookup(dns.resolver.resolve(d)[0].to_text())
    features['asn_ip'] = res.asn
    features['time_domain_activation'] = (datetime.datetime.now() - who['creation_date'][0]).days
    features['time_domain_expiration'] = (who['expiration_date'][0] - datetime.datetime.now()).days
    features['qty_ip_resolved'] = len(dns.resolver.resolve(d, 'A'))
    features['qty_nameservers'] = len(dns.resolver.resolve(d, 'NS'))
    features['qty_mx_servers'] = len(dns.resolver.resolve(d, 'MX'))
    features['ttl_hostname'] = dns.resolver.resolve(d).rrset.ttl
    # https://www.geeksforgeeks.org/ssl-certificate-verification-python-requests/
    try:
        requests.get('https://' + d)
        features['tls_ssl_certificate'] = True
    except SSLCertVerificationError:
        features['tls_ssl_certificate'] = False
    features['qty_redirects'] = sum([True if h.status_code in [301, 302] else False for h in resp.history])
    features['url_google_index'] = 0 # TODO
    features['domain_google_index'] = 0 # TODO
    features['url_shortened'] = d.lower() in ['tinyurl.com', 'bit.ly', 't.co'] # TODO: add more URL shortening services
    return features


def build_inference(url):
    dtypes = {'qty_dot_url': dtype('int64'),
 'qty_hyphen_url': dtype('int64'),
 'qty_underline_url': dtype('int64'),
 'qty_slash_url': dtype('int64'),
 'qty_questionmark_url': dtype('int64'),
 'qty_equal_url': dtype('int64'),
 'qty_at_url': dtype('int64'),
 'qty_and_url': dtype('int64'),
 'qty_exclamation_url': dtype('int64'),
 'qty_space_url': dtype('int64'),
 'qty_tilde_url': dtype('int64'),
 'qty_comma_url': dtype('int64'),
 'qty_plus_url': dtype('int64'),
 'qty_asterisk_url': dtype('int64'),
 'qty_hashtag_url': dtype('int64'),
 'qty_dollar_url': dtype('int64'),
 'qty_percent_url': dtype('int64'),
 'qty_tld_url': dtype('int64'),
 'length_url': dtype('int64'),
 'qty_dot_domain': dtype('int64'),
 'qty_hyphen_domain': dtype('int64'),
 'qty_underline_domain': dtype('int64'),
 'qty_slash_domain': dtype('int64'),
 'qty_questionmark_domain': dtype('int64'),
 'qty_equal_domain': dtype('int64'),
 'qty_at_domain': dtype('int64'),
 'qty_and_domain': dtype('int64'),
 'qty_exclamation_domain': dtype('int64'),
 'qty_space_domain': dtype('int64'),
 'qty_tilde_domain': dtype('int64'),
 'qty_comma_domain': dtype('int64'),
 'qty_plus_domain': dtype('int64'),
 'qty_asterisk_domain': dtype('int64'),
 'qty_hashtag_domain': dtype('int64'),
 'qty_dollar_domain': dtype('int64'),
 'qty_percent_domain': dtype('int64'),
 'qty_vowels_domain': dtype('int64'),
 'domain_length': dtype('int64'),
 'domain_in_ip': dtype('int64'),
 'server_client_domain': dtype('int64'),
 'qty_dot_directory': dtype('int64'),
 'qty_hyphen_directory': dtype('int64'),
 'qty_underline_directory': dtype('int64'),
 'qty_slash_directory': dtype('int64'),
 'qty_questionmark_directory': dtype('int64'),
 'qty_equal_directory': dtype('int64'),
 'qty_at_directory': dtype('int64'),
 'qty_and_directory': dtype('int64'),
 'qty_exclamation_directory': dtype('int64'),
 'qty_space_directory': dtype('int64'),
 'qty_tilde_directory': dtype('int64'),
 'qty_comma_directory': dtype('int64'),
 'qty_plus_directory': dtype('int64'),
 'qty_asterisk_directory': dtype('int64'),
 'qty_hashtag_directory': dtype('int64'),
 'qty_dollar_directory': dtype('int64'),
 'qty_percent_directory': dtype('int64'),
 'directory_length': dtype('int64'),
 'qty_dot_file': dtype('int64'),
 'qty_hyphen_file': dtype('int64'),
 'qty_underline_file': dtype('int64'),
 'qty_slash_file': dtype('int64'),
 'qty_questionmark_file': dtype('int64'),
 'qty_equal_file': dtype('int64'),
 'qty_at_file': dtype('int64'),
 'qty_and_file': dtype('int64'),
 'qty_exclamation_file': dtype('int64'),
 'qty_space_file': dtype('int64'),
 'qty_tilde_file': dtype('int64'),
 'qty_comma_file': dtype('int64'),
 'qty_plus_file': dtype('int64'),
 'qty_asterisk_file': dtype('int64'),
 'qty_hashtag_file': dtype('int64'),
 'qty_dollar_file': dtype('int64'),
 'qty_percent_file': dtype('int64'),
 'file_length': dtype('int64'),
 'qty_dot_params': dtype('int64'),
 'qty_hyphen_params': dtype('int64'),
 'qty_underline_params': dtype('int64'),
 'qty_slash_params': dtype('int64'),
 'qty_questionmark_params': dtype('int64'),
 'qty_equal_params': dtype('int64'),
 'qty_at_params': dtype('int64'),
 'qty_and_params': dtype('int64'),
 'qty_exclamation_params': dtype('int64'),
 'qty_space_params': dtype('int64'),
 'qty_tilde_params': dtype('int64'),
 'qty_comma_params': dtype('int64'),
 'qty_plus_params': dtype('int64'),
 'qty_asterisk_params': dtype('int64'),
 'qty_hashtag_params': dtype('int64'),
 'qty_dollar_params': dtype('int64'),
 'qty_percent_params': dtype('int64'),
 'params_length': dtype('int64'),
 'tld_present_params': dtype('int64'),
 'qty_params': dtype('int64'),
 'email_in_url': dtype('int64'),
 'time_response': dtype('float64'),
 'domain_spf': dtype('int64'),
 'asn_ip': dtype('int64'),
 'time_domain_activation': dtype('int64'),
 'time_domain_expiration': dtype('int64'),
 'qty_ip_resolved': dtype('int64'),
 'qty_nameservers': dtype('int64'),
 'qty_mx_servers': dtype('int64'),
 'ttl_hostname': dtype('int64'),
 'tls_ssl_certificate': dtype('int64'),
 'qty_redirects': dtype('int64'),
 'url_google_index': dtype('int64'),
 'domain_google_index': dtype('int64'),
 'url_shortened': dtype('int64')}
    t1_counts = build_counts(count_chars(url), 'url')
    table_1 = table_1_features(url, t1_counts)
    t2_counts = build_counts(count_chars(tldextract.extract(url).domain), 'domain')
    table_2 = table_2_features(url, t2_counts)
    t3_counts = build_counts(count_chars(os.path.split(urlparse(url).path)[0].lstrip('/')), 'directory')
    table_3 = table_3_features(url, t3_counts)
    t4_counts = build_counts(count_chars(os.path.split(urlparse(url).path)[1]), 'file')
    table_4 = table_4_features(url, t4_counts)
    t5_counts = build_counts(count_chars(urlparse(url).query), 'params')
    table_5 = table_5_features(url, t5_counts)
    table_6 = table_6_features(url)
    s = pd.Series(table_1 | table_2 | table_3 | table_4 | table_5 | table_6)
    df = pd.DataFrame(s).transpose().astype(dtypes)
    return df
