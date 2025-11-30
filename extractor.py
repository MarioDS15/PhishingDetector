import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
import pandas as pd
import time
import re

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options


##########################################
# 1. SELENIUM SETUP (WINDOWS FRIENDLY)
##########################################
def init_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--log-level=3")

    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=chrome_options
    )
    return driver


##########################################
# 2. BASIC PAGE FETCHING (STATIC + DYNAMIC)
##########################################
def get_page_static(url):
    try:
        response = requests.get(url, timeout=10)
        return response.text, response.url, response.status_code
    except:
        return None, url, None


##########################################
# 3. FEATURE FUNCTIONS
##########################################
def get_line_of_code(html):
    return len(html.split("\n")) if html else 0


def get_largest_line_length(html):
    return max(len(line) for line in html.split("\n")) if html else 0


def has_title(soup):
    return 1 if soup and soup.find("title") else 0


def get_title(soup):
    tag = soup.find("title") if soup else None
    return tag.text.strip() if tag else ""


def domain_title_match_score(url, title):
    if not title:
        return 0
    domain = tldextract.extract(url).domain.lower()
    title = title.lower()
    if domain in title:
        return 1
    elif domain[:3] in title:
        return 0.5
    return 0


def url_title_match_score(url, title):
    if not title:
        return 0
    parsed = urlparse(url)
    path = parsed.path.lower()
    words = title.lower().split()
    matches = sum(1 for w in words if w in path)
    return matches / len(words) if words else 0


def has_favicon(soup):
    if not soup:
        return 0
    return 1 if soup.find("link", rel=lambda x: x and "icon" in x.lower()) else 0


def has_robots_txt(url):
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        r = requests.get(robots_url, timeout=5)
        return 1 if r.status_code == 200 else 0
    except:
        return 0


def is_responsive(soup):
    if not soup:
        return 0
    return 1 if soup.find("meta", attrs={"name": "viewport"}) else 0


def count_iframes(soup):
    return len(soup.find_all("iframe")) if soup else 0


def count_popups(html):
    return sum(html.count(k) for k in ["alert(", "prompt(", "confirm("]) if html else 0


def has_social_links(soup):
    if not soup:
        return 0
    socials = ["facebook.com", "twitter.com", "instagram.com", "linkedin.com", "youtube.com"]
    links = [a.get("href", "") for a in soup.find_all("a")]
    return 1 if any(any(s in str(link) for s in socials) for link in links) else 0


def get_description(soup):
    if not soup:
        return ""
    tag = soup.find("meta", attrs={"name": "description"})
    if tag and tag.get("content"):
        return tag.get("content").strip()
    tag = soup.find("meta", attrs={"property": "og:description"})
    if tag and tag.get("content"):
        return tag.get("content").strip()
    return ""


def analyze_forms(soup, final_domain):
    has_submit = has_hidden = has_password = has_external = 0
    if not soup:
        return has_submit, has_hidden, has_password, has_external

    forms = soup.find_all("form")
    for f in forms:
        if f.find("input", {"type": "submit"}) or f.find("button"):
            has_submit = 1
        if f.find("input", {"type": "hidden"}):
            has_hidden = 1
        if f.find("input", {"type": "password"}):
            has_password = 1

        action = f.get("action", "")
        if action.startswith("http"):
            if urlparse(action).netloc and urlparse(action).netloc != final_domain:
                has_external = 1

    return has_submit, has_hidden, has_password, has_external


def count_images(soup):
    return len(soup.find_all("img")) if soup else 0


def count_css(soup):
    if not soup:
        return 0
    count = 0
    for link in soup.find_all("link"):
        rel = link.get("rel") or []
        typ = link.get("type", "")
        if "stylesheet" in " ".join(rel).lower() or "text/css" in typ.lower():
            count += 1
    return count


def count_js(soup):
    if not soup:
        return 0
    return len([s for s in soup.find_all("script") if s.get("src")])


def count_link_types(soup, domain):
    if not soup:
        return 0, 0, 0

    anchors = soup.find_all("a")
    self_ref = empty_ref = external_ref = 0

    for a in anchors:
        href = a.get("href", "")
        if not href or href == "#" or href.lower().startswith("javascript:"):
            empty_ref += 1
            continue

        parsed = urlparse(href)
        if parsed.netloc == "" or parsed.netloc == domain:
            self_ref += 1
        else:
            external_ref += 1

    return self_ref, empty_ref, external_ref


def keyword_flag(soup, title, html, keywords):
    title = title.lower() if title else ""
    if any(k in title for k in keywords):
        return 1
    desc = get_description(soup).lower() if soup else ""
    if any(k in desc for k in keywords):
        return 1
    text = soup.get_text(" ").lower() if soup else ""
    if any(k in text for k in keywords):
        return 1
    raw = html.lower() if html else ""
    if any(k in raw for k in keywords):
        return 1
    return 0


def has_copyright(soup, html):
    text = soup.get_text(" ").lower() if soup else ""
    raw = html.lower() if html else ""
    keywords = ["©", "copyright", "all rights reserved"]
    return 1 if any(k in text or k in raw for k in keywords) else 0


def count_redirects(url):
    try:
        session = requests.Session()
        r = session.get(url, timeout=10, allow_redirects=True)
        redirects = r.history
        final_domain = urlparse(url).netloc
        self_redirects = sum(
            1 for h in redirects
            if urlparse(h.headers.get("Location", "")).netloc == final_domain
        )
        return len(redirects), self_redirects
    except:
        return 0, 0


##########################################
# 4. MAIN FEATURE EXTRACTION FUNCTION
##########################################
def extract_features(url, driver):
    static_html, final_url, status = get_page_static(url)
    soup = BeautifulSoup(static_html, "lxml") if static_html else None

    parsed_final = urlparse(final_url)
    final_domain = parsed_final.netloc
    title_text = get_title(soup) if soup else ""
    desc_text = get_description(soup)

    submit, hidden, passwd, ext_submit = analyze_forms(soup, final_domain)
    self_ref, empty_ref, external_ref = count_link_types(soup, final_domain)

    features = {
        "URL": url,
        "label": "",

        "LineOfCode": get_line_of_code(static_html),
        "LargestLineLength": get_largest_line_length(static_html),
        "HasTitle": has_title(soup),
        "Title": title_text,

        "DomainTitleMatchScore": domain_title_match_score(url, title_text),
        "URLTitleMatchScore": url_title_match_score(url, title_text),
        "HasFavicon": has_favicon(soup),

        "Robots": has_robots_txt(url),
        "IsResponsive": is_responsive(soup),

        "NoOfURLRedirect": count_redirects(url)[0],
        "NoOfSelfRedirect": count_redirects(url)[1],

        "HasDescription": 1 if desc_text else 0,
        "NoOfPopup": count_popups(static_html),
        "NoOfiFrame": count_iframes(soup),

        "HasExternalFormSubmit": ext_submit,
        "HasSocialNet": has_social_links(soup),

        "HasSubmitButton": submit,
        "HasHiddenFields": hidden,
        "HasPasswordField": passwd,

        "Bank": keyword_flag(soup, title_text, static_html, ["bank", "online banking", "account", "login"]),
        "Pay": keyword_flag(soup, title_text, static_html, ["pay", "payment", "checkout", "billing"]),
        "Crypto": keyword_flag(soup, title_text, static_html, ["bitcoin", "crypto", "ethereum", "wallet", "btc", "eth"]),

        "HasCopyrightInfo": has_copyright(soup, static_html),

        "NoOfImage": count_images(soup),
        "NoOfCSS": count_css(soup),
        "NoOfJS": count_js(soup),

        "NoOfSelfRef": self_ref,
        "NoOfEmptyRef": empty_ref,
        "NoOfExternalRef": external_ref,
    }

    return features


##########################################
# 5. RUNNER — READ URLS.TXT & SAVE DATA
##########################################
if __name__ == "__main__":
    driver = init_driver()

    with open("urls.txt", "r") as f:
        urls = [x.strip() for x in f.readlines() if x.strip()]

    dataset = []

    for url in urls:
        print(f"Extracting: {url}")
        dataset.append(extract_features(url, driver))

    pd.DataFrame(dataset).to_csv("data.csv", index=False)
    driver.quit()
    print("DONE — data saved to data.csv")
