import re

import socket
import requests
import tldextract
import urllib

from ..models import KnownBrand, PhishingHint, SuspiciousTLD


# TODO: Maybe persist this


def extract_features(url):

    KNOWN_BRANDS = [knownbrand.name for knownbrand in KnownBrand.objects.all()]

    PHISHING_HINTS = [phishinghint.value for phishinghint in PhishingHint.objects.all()]

    SUSPICIOUS_TLDS = [suspicioustld.value for suspicioustld in SuspiciousTLD.objects.all()]

    def extract_raw_words(domain, subdomain, path):
        w_domain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", domain.lower())
        w_subdomain = re.split(
            "\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", subdomain.lower())
        w_path = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", path.lower())
        raw_words = w_domain + w_path + w_subdomain
        w_host = w_domain + w_subdomain
        raw_words = list(filter(None, raw_words))
        return raw_words, list(filter(None, w_host)), list(filter(None, w_path))

    def ratio_digits(text):
        return len(re.sub("[^0-9]", "", text)) / len(text)

    def char_repeat(raw_words):

        def __all_same(items):
            return all(x == items[0] for x in items)

        repeat = {'2': 0, '3': 0, '4': 0, '5': 0}
        part = [2, 3, 4, 5]

        for word in raw_words:
            for char_repeat_count in part:
                for i in range(len(word) - char_repeat_count + 1):
                    sub_word = word[i:i + char_repeat_count]
                    if __all_same(sub_word):
                        repeat[str(char_repeat_count)] = repeat[str(
                            char_repeat_count)] + 1
        return sum(list(repeat.values()))

    def visit_page(url):
        page = None
        try:
            page = requests.get(url, timeout=15)
        except:
            parsed = urllib.parse.urlparse(url)
            url = parsed.scheme + '://' + parsed.netloc
            if not parsed.netloc.startswith('www'):
                url = parsed.scheme+'://www.'+parsed.netloc
                try:
                    page = requests.get(url, timeout=5)
                except:
                    page = None
                    pass
        return page

    def statistical_report(url, domain):
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        try:
            ip_address = socket.gethostbyname(domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                 '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                 '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                 '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                 '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                 '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match or ip_match:
                return 1
            else:
                return 0
        except:
            return 2

    # Parse URL and extract useful objects
    url_obj = urllib.parse.urlsplit(url)
    hostname = url_obj.hostname
    domain_obj = tldextract.extract(url)
    domain = domain_obj.domain
    subdomain = domain_obj.subdomain
    tld = domain_obj.suffix
    tmp = url[url.find(domain_obj.suffix):len(url)]
    pth = tmp.partition("/")
    path = pth[1] + pth[2]
    raw_words, raw_words_host, raw_words_path = extract_raw_words(
        domain, subdomain, pth[2])

    # Double Slash / redirections
    redirections = [x.start(0) for x in re.finditer('//', url)]
    redirection = 1 if redirections[len(redirections)-1] > 6 else 0

    page = visit_page(url)
    # Count external redirections (redirection to other domains)
    external_redirections = 0
    if page:
        for i, response in enumerate(page.history, 1):
            if domain.lower() not in response.url.lower():
                external_redirections += 1

    return {
        'length_url': len(url),
        'length_hostname': len(url_obj.hostname),
        'ip': 1 if bool(re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                                  '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                                  '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                                  '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                                  '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.'
                                  # IPv4 in hexadecimal
                                  '(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'
                                  '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
                                  '[0-9a-fA-F]{7}', url)) else 0,
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': url.count('|'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'nb_colon': url.count(':'),
        'nb_comma': url.count(','),
        'nb_semicolon': url.count(';'),
        'nb_dollar': url.count('$'),
        'nb_space': url.count(' ') + url.count('%20'),
        'nb_www': sum([1 if 'www' in word else 0 for word in raw_words]),
        'nb_com': sum([1 if 'com' in word else 0 for word in raw_words]),
        'nb_dslash': redirection,
        'http_in_path': path.count('http'),
        'https_token': 0 if url_obj.scheme == 'https' else 1,
        'ratio_digits_url': ratio_digits(url),
        'ratio_digits_host': ratio_digits(hostname),
        'punycode': 1 if url.startswith('http://xn--') or url.startswith('https://xn--')
        else 0,
        'port': 1 if re.search("^[a-z][a-z0-9+\-.]*://([a-z0-9\-._~%!$&'()*+,;=]+@)?"
                               "([a-z0-9\-._~%]+|\[[a-z0-9\-._~%!$&'()*+,;=:]+\]):([0-9]+)", url)
        else 0,
        'tld_in_path': 1 if path.lower().count(tld) > 0 else 0,
        'tld_in_subdomain': 1 if subdomain.count(tld) > 0 else 0,
        'abnormal_subdomain': 1 if re.search('(http[s]?://(w[w]?|\d))([w]?(\d|-))', url) else 0,
        'nb_subdomain': min(len(re.findall('\.', url)), 3),
        'prefix_suffix': 1 if re.findall(r"https?://[^\-]+-[^\-]+/", url) else 0,
        'shortening_service': 1 if re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                                             'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                                             'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                                             'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                                             'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                                             'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                                             'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                                             'tr\.im|link\.zip\.net',
                                             url) else 0,
        'path_extension': 1 if url.endswith('.txt') else 0,
        'nb_redirection': len(page.history) if page else 0,
        'nb_external_redirection': external_redirections,
        'length_words_raw': len(raw_words),
        'char_repeat': char_repeat(raw_words),
        # TODO: Optimize this if needed
        'shortest_words_raw': min([len(word) for word in raw_words]) if raw_words else 0,
        'shortest_word_host': min([len(word) for word in raw_words_host]) if raw_words_host else 0,
        'shortest_word_path': min([len(word) for word in raw_words_path]) if raw_words_path else 0,
        'longest_words_raw': max([len(word) for word in raw_words]) if raw_words else 0,
        'longest_word_host': max([len(word) for word in raw_words_host]) if raw_words_host else 0,
        'longest_word_path': max([len(word) for word in raw_words_path]) if raw_words_path else 0,
        'avg_words_raw': sum([len(word) for word in raw_words]) / len(raw_words) if raw_words else 0,
        'avg_word_host': sum([len(word) for word in raw_words_host]) / len(raw_words_host) if raw_words_host else 0,
        'avg_word_path': sum([len(word) for word in raw_words_path]) / len(raw_words_path) if raw_words_path else 0,
        'phish_hints': sum([url.lower().count(hint) for hint in PHISHING_HINTS]),
        'domain_in_brand': 1 if domain in KNOWN_BRANDS else 0,
        'brand_in_subdomain': 1 if subdomain in KNOWN_BRANDS else 0,
        'brand_in_path': max([1 if '.' + BRAND + '.' in path and BRAND not in domain else 0
                              for BRAND in KNOWN_BRANDS]),
        'suspicious_tld': 1 if tld in SUSPICIOUS_TLDS else 0,
        'statistical_report': statistical_report(url, domain)
    }
