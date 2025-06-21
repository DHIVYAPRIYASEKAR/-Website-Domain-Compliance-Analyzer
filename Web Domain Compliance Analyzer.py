import tldextract
import whois
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import dns.resolver

try:
    from pyfiglet import Figlet
except ImportError:
    Figlet = None  # fallback

console = Console()

# Pricing in USD/year for common TLDs
DOMAIN_PRICING_USD = {
    'com': 12.99,
    'net': 10.99,
    'org': 9.99,
    'io': 39.99,
    'co': 29.99,
    'in': 8.99,
    'tech': 49.99,
    'info': 11.99,
}

USD_TO_INR = 83.5  # Approximate conversion rate

def usd_to_inr(usd):
    return round(usd * USD_TO_INR, 2)

def get_domain_pricing(domain):
    ext = tldextract.extract(domain)
    tld = ext.suffix.lower()
    price_usd = DOMAIN_PRICING_USD.get(tld)
    if price_usd:
        price_inr = usd_to_inr(price_usd)
        return f"₹{price_inr} / year (approx. ${price_usd})"
    else:
        return "Pricing not available"

def check_keywords_in_content(content, keywords):
    content_lower = content.lower()
    return any(keyword.lower() in content_lower for keyword in keywords)

def check_privacy_policy_validity(content):
    valid_phrases = [
        'information collected and managed by',
        'data collected by',
        'information we collect',
        'data controlled by us',
        'personal data we collect',
        'information collected by us',
        'data we collect',
        'we collect information',
        'we collect personal data',
        'this privacy policy applies to',
        'this policy describes how we collect',
    ]
    content_lower = content.lower()
    return any(phrase in content_lower for phrase in valid_phrases)

def extract_contact_info(soup):
    text = soup.get_text(separator='\n', strip=True)
    contact_info = {}

    phone_pattern = re.compile(
        r'(\+?\d{1,4}[\s\-\.]?)?(\(?\d{1,4}\)?[\s\-\.]?)?[\d\s\-\.]{5,15}\d'
    )
    phones = phone_pattern.findall(text)
    phones_clean = set()
    for match in phones:
        combined = ''.join(match).strip()
        if combined and len(re.sub(r'\D', '', combined)) >= 7:
            phones_clean.add(combined)
    contact_info['Phone Numbers'] = list(phones_clean) if phones_clean else []

    email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
    emails = email_pattern.findall(text)
    contact_info['Emails'] = list(set(emails)) if emails else []

    addresses = []
    for line in text.split('\n'):
        if any(k in line.lower() for k in ['india', 'main branch', 'head office']):
            addresses.append(line.strip())
    contact_info['Addresses (India/Main Branch)'] = addresses if addresses else []

    return contact_info

def extract_social_links(soup):
    social_domains = ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'youtube.com', 't.me', 'wa.me']
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        if href.startswith(('http://', 'https://')):
            for domain in social_domains:
                if domain in href.lower():
                    links.add(href)
    return list(links)

def summarize_policy_info(text_content):
    policies = {}
    policies['Privacy Policy'] = 'privacy policy' in text_content.lower()
    policies['Cookie Policy'] = 'cookie policy' in text_content.lower() or 'cookies' in text_content.lower()
    policies['Security & Data Protection'] = any(x in text_content.lower() for x in ['security', 'data protection', 'encryption', 'ssl'])
    return policies

def extract_about_section(soup):
    about_text = ''

    candidates = soup.find_all(attrs={'id': re.compile('(about|purpose)', re.I)})
    if not candidates:
        candidates = soup.find_all(attrs={'class': re.compile('(about|purpose)', re.I)})

    if candidates:
        about_text = ' '.join([c.get_text(separator=' ', strip=True) for c in candidates])
    else:
        headings = soup.find_all(['h2', 'h3', 'h4'])
        for h in headings:
            heading_text = h.get_text(strip=True).lower()
            if 'about' in heading_text or 'purpose' in heading_text:
                sib = h.find_next_sibling()
                if sib:
                    about_text = sib.get_text(separator=' ', strip=True)
                    break

    if not about_text:
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            about_text = meta_desc['content']

    if about_text:
        about_text = about_text[:1000] + ('...' if len(about_text) > 1000 else '')
    else:
        about_text = 'No clear About or Purpose section found.'

    return about_text

def analyze_vulnerable_status(text_content):
    text_lower = text_content.lower()

    strong_keywords = ['https', 'ssl', 'encryption', 'secure', 'tls', 'https://']
    weak_keywords = ['http://', 'insecure', 'unprotected', 'no ssl', 'not secure']

    strong_count = sum(text_lower.count(k) for k in strong_keywords)
    weak_count = sum(text_lower.count(k) for k in weak_keywords)

    total = strong_count + weak_count
    if total == 0:
        return 0, 0

    strong_percent = (strong_count / total) * 100
    weak_percent = (weak_count / total) * 100

    return round(strong_percent, 2), round(weak_percent, 2)

def get_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:
            records[rtype] = []
    return records

def get_compliance_and_info(url_or_dns):
    extracted = tldextract.extract(url_or_dns)
    domain_name = f"{extracted.domain}.{extracted.suffix}"

    try:
        whois_info = whois.whois(domain_name)
        owner_name = whois_info.get('org') or whois_info.get('name') or 'Not available'
    except Exception:
        owner_name = 'Not available'

    status = {
        'Privacy Policy': False,
        'Privacy Policy Valid for Entity Data': False,
        'Cookie Content': False,
        'Accessibility Statement': False,
        'Security & Data Protection': False,
        'Data Collection/Sharing': False,
        'Copyright Infringement': False,
        'Misusing Content': False,
        'Fraud Content': False,
        'Defamation': False,
        'Promotion of Illegal Sales': False,
        'Non-compliance with Data Protection Laws': False,
    }

    info = {
        'Business Description': '',
        'Contact Information': {},
        'Social Media Links': [],
        'Policy Information': {},
        'About Website': '',
        'Vulnerable Status': (0, 0),
        'DNS Records': {},
        'Domain Pricing': ''
    }

    if not url_or_dns.startswith(('http://', 'https://')):
        url = 'http://' + url_or_dns
    else:
        url = url_or_dns

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        text_content = soup.get_text(separator=' ', strip=True)

        # Compliance checks
        status['Privacy Policy'] = check_keywords_in_content(text_content, ['privacy policy'])
        if status['Privacy Policy']:
            status['Privacy Policy Valid for Entity Data'] = check_privacy_policy_validity(text_content)

        status['Cookie Content'] = check_keywords_in_content(text_content, ['cookie policy', 'cookies'])
        status['Accessibility Statement'] = check_keywords_in_content(text_content, ['accessibility statement', 'wcag compliance'])
        status['Security & Data Protection'] = check_keywords_in_content(text_content, ['ssl', 'encryption', 'data protection'])
        status['Data Collection/Sharing'] = check_keywords_in_content(text_content, ['personal data', 'data collection', 'third-party sharing'])
        status['Copyright Infringement'] = check_keywords_in_content(text_content, ['copyright notice', 'dmca', 'intellectual property'])
        status['Misusing Content'] = check_keywords_in_content(text_content, ['misuse', 'misusing', 'unauthorized use'])
        status['Fraud Content'] = check_keywords_in_content(text_content, ['fraud', 'scam', 'fake', 'phishing'])
        status['Defamation'] = check_keywords_in_content(text_content, ['defamation', 'libel', 'slander'])
        status['Promotion of Illegal Sales'] = check_keywords_in_content(text_content, ['illegal sales', 'black market', 'contraband', 'unauthorized sale', 'pirated'])
        status['Non-compliance with Data Protection Laws'] = not check_keywords_in_content(
            text_content,
            ['gdpr', 'ccpa', 'data protection act', 'privacy shield', 'data privacy', 'data protection laws']
        )

        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            info['Business Description'] = meta_desc['content'][:750]
        else:
            info['Business Description'] = text_content[:750] + ('...' if len(text_content) > 750 else '')

        info['Contact Information'] = extract_contact_info(soup)
        info['Social Media Links'] = extract_social_links(soup)
        info['Policy Information'] = summarize_policy_info(text_content)
        info['About Website'] = extract_about_section(soup)
        info['Vulnerable Status'] = analyze_vulnerable_status(text_content)

    except Exception as e:
        console.print(f"[bold red]Warning:[/bold red] Could not fetch or parse website content. Details: {e}")

    # DNS records & pricing (try even if website fetch failed)
    try:
        info['DNS Records'] = get_dns_records(domain_name)
    except Exception as e:
        console.print(f"[bold red]Warning:[/bold red] Could not fetch DNS records. Details: {e}")
        info['DNS Records'] = {}

    info['Domain Pricing'] = get_domain_pricing(domain_name)

    return domain_name, owner_name, status, info

def print_status_table(status):
    table = Table(title="Compliance Status", show_lines=True)
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", style="magenta", justify="center")

    for check, result in status.items():
        symbol = "[green]✓[/green]" if result else "[red]✗[/red]"
        table.add_row(check, symbol)
    console.print(table)

def print_contact_info(contact_info):
    table = Table(title="Contact Information", show_lines=True)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Details", style="magenta")

    if not any(contact_info.values()):
        console.print("No contact information found.", style="italic yellow")
        return

    for k, v in contact_info.items():
        if v:
            details = "\n".join(v)
        else:
            details = "Not available"
        table.add_row(k, details)
    console.print(table)

def print_social_links(links):
    if not links:
        console.print("No social media links found.", style="italic yellow")
        return

    console.print("[bold underline]Social Media Links (URLs):[/bold underline]")
    for link in links:
        console.print(f"- {link}")

def print_policy_info(policy_info):
    table = Table(title="Policy Information", show_lines=True)
    table.add_column("Policy", style="cyan", no_wrap=True)
    table.add_column("Presence", style="magenta", justify="center")

    for k, v in policy_info.items():
        presence = "[green]Present[/green]" if v else "[red]Not found[/red]"
        table.add_row(k, presence)
    console.print(table)

def print_vulnerable_status(strong_pct, weak_pct):
    table = Table(title="Vulnerable Status", show_lines=True)
    table.add_column("Connection Type", style="cyan", no_wrap=True)
    table.add_column("Percentage", style="magenta", justify="right")

    table.add_row("Strong Connections", f"{strong_pct}%")
    table.add_row("Weak Connections", f"{weak_pct}%")

    console.print(table)

def print_dns_records(dns_records):
    table = Table(title="DNS Here Belonged (DNS Records)", show_lines=True)
    table.add_column("Record Type", style="cyan", no_wrap=True)
    table.add_column("Records", style="magenta")

    if not dns_records:
        console.print("No DNS records found or unable to fetch.", style="italic yellow")
        return

    for rtype, records in dns_records.items():
        if records:
            rec_text = "\n".join(records)
        else:
            rec_text = "None"
        table.add_row(rtype, rec_text)
    console.print(table)

def print_title():
    if Figlet:
        f = Figlet(font='slant')
        title_text = f.renderText('WEB RESUME')
        console.print(title_text, style="bold blue", justify="center")
    else:
        console.print("\n[bold blue][underline]Website Domain & Compliance Analyzer[/underline][/bold blue]\n", justify="center")

def main():
    print_title()

    target = console.input("[bold]Enter website URL or DNS name:[/bold] ").strip()
    domain, owner, compliance, information = get_compliance_and_info(target)

    console.print(Panel(f"[bold]Domain:[/bold] {domain}\n[bold]Registered Owner:[/bold] {owner}", title="Domain Information", style="bright_blue"))

    print_status_table(compliance)

    console.print(Panel(information['Business Description'] or "Not available", title="Business Description", style="bright_green"))

    print_contact_info(information['Contact Information'])

    print_social_links(information['Social Media Links'])

    print_policy_info(information['Policy Information'])

    console.print(Panel(information['About Website'] or "Not available", title="About the Website (Purpose)", style="bright_magenta"))

    strong_pct, weak_pct = information.get('Vulnerable Status', (0, 0))
    print_vulnerable_status(strong_pct, weak_pct)

    print_dns_records(information.get('DNS Records', {}))

    price_str = information.get('Domain Pricing', 'Pricing not available')
    console.print(Panel(f"[bold]{domain}[/bold]\nPreferred domain pricing: [green]{price_str}[/green]", title="Domain Pricing (INR)", style="bright_yellow"))

if __name__ == "__main__":
    main()
