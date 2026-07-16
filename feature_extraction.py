import re

def extract_features(url):

    features = []

    # LongURL
    features.append(1 if len(url) > 54 else 0)

    # UsingIP
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    features.append(1 if re.search(ip_pattern, url) else -1)

    # Symbol@
    features.append(1 if "@" in url else -1)

    # PrefixSuffix-
    features.append(1 if "-" in url else -1)

    # SubDomains
    dots = url.count(".")
    if dots <= 1:
        features.append(-1)
    elif dots == 2:
        features.append(0)
    else:
        features.append(1)

    # HTTPS
    features.append(1 if url.startswith("https") else -1)

    # ShortURL
    shorteners = [
        "bit.ly",
        "tinyurl",
        "goo.gl",
        "t.co",
        "is.gd"
    ]

    if any(site in url for site in shorteners):
        features.append(1)
    else:
        features.append(-1)

    # Redirecting//
    if url[8:].find("//") != -1:
        features.append(1)
    else:
        features.append(-1)

    return features
     