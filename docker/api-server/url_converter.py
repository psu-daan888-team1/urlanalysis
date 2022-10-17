from bs4 import BeautifulSoup
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
from urllib.parse import parse_qs, urlencode, urlparse
from urllib3.exceptions import SSLError
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


# adapted from: https://searchengineland.com/check-urls-indexed-google-using-python-259773
# this may break if Google changes their search formatting
# it may also break if Google starts to deny requests due to frequency
def check_google_index(url):
    agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
    h = {'User-Agent': agent}
    q = {'q': 'info:' + url}
    g = "https://www.google.com/search?" + urlencode(q)
    resp = requests.get(g, headers=h)
    resp.encoding='ISO-8859-1'
    s = BeautifulSoup(str(resp.content), "html.parser")
    try:
        check = s.find(id="rso").find("div").find("div").find("div").find("div").find("div").find("a")
        href = check['href']
        return True
    except (AttributeError, TypeError):
        return False


def table_6_features(full_url):
    # https://www.dnspython.org/examples.html
    u = tldextract.extract(full_url)
    d = u.domain + '.' + u.suffix
    features = dict()
    try:
        features['time_response'] = dns.resolver.resolve(d).response.time * 100
    except dns.exception.DNSException:
        features['time_response'] = -1
    # https://support.mailessentials.gfi.com/hc/en-us/articles/360015116520-How-to-check-and-read-a-Sender-Policy-Framework-record-for-a-domain
    try:
        features['domain_spf'] = 'spf' in str(dns.resolver.resolve(d, 'TXT').rrset)
    except dns.exception.DNSException:
        features['domain_spf'] = -1
    # https://github.com/JustinAzoff/python-cymruwhois
    try:
        cli=Client()
        res=cli.lookup(dns.resolver.resolve(d)[0].to_text())
        features['asn_ip'] = res.asn
    except dns.exception.DNSException:
        features['asn_ip'] = -1
    try:
        who = whois.whois(d)
        if type(who['creation_date']) == list:
            features['time_domain_activation'] = (datetime.datetime.now() - who['creation_date'][0]).days
            features['time_domain_expiration'] = (who['expiration_date'][0] - datetime.datetime.now()).days
        else:
            features['time_domain_activation'] = (datetime.datetime.now() - who['creation_date']).days
            features['time_domain_expiration'] = (who['expiration_date'] - datetime.datetime.now()).days
    except whois.parser.PywhoisError:
        features['time_domain_activation'] = -1
        features['time_domain_expiration'] = -1
    try:
        features['qty_ip_resolved'] = len(dns.resolver.resolve(d, 'A'))
    except dns.exception.DNSException:
        features['qty_ip_resolved'] = -1
    try:
        features['qty_nameservers'] = len(dns.resolver.resolve(d, 'NS'))
    except dns.exception.DNSException:
        features['qty_nameservers'] = -1
    try:
        features['qty_mx_servers'] = len(dns.resolver.resolve(d, 'MX'))
    except dns.exception.DNSException:
        features['qty_mx_servers'] = -1
    try:
        features['ttl_hostname'] = dns.resolver.resolve(d).rrset.ttl
    except dns.exception.DNSException:
        features['ttl_hostname'] = -1
    # https://www.geeksforgeeks.org/ssl-certificate-verification-python-requests/
    try:
        requests.get('https://' + d)
        features['tls_ssl_certificate'] = True
    except requests.exceptions.ConnectionError:
        features['tls_ssl_certificate'] = False
    try:
        resp = requests.get('http://' + d)
        features['qty_redirects'] = sum([True if h.status_code in [301, 302] else False for h in resp.history])
    except requests.exceptions.ConnectionError:
        features['qty_redirects'] = -1
    features['url_google_index'] = check_google_index(full_url)
    features['domain_google_index'] = check_google_index(d)
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
    df.drop(['qty_slash_domain',
 'qty_questionmark_domain',
 'qty_equal_domain',
 'qty_and_domain',
 'qty_exclamation_domain',
 'qty_space_domain',
 'qty_tilde_domain',
 'qty_comma_domain',
 'qty_plus_domain',
 'qty_asterisk_domain',
 'qty_hashtag_domain',
 'qty_dollar_domain',
 'qty_percent_domain'], axis=1, inplace=True)
    return df
