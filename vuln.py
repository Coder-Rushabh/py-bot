import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time

# Function to fetch page content
def fetch_page(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

# Function to extract internal links
def extract_links(html, base_url, domain):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a_tag in soup.find_all('a', href=True):
        link = a_tag['href']
        full_url = urljoin(base_url, link)
        if urlparse(full_url).netloc == domain:
            links.add(full_url)
    return links

# Function to scan for common vulnerabilities
def scan_for_vulnerabilities(html):
    vulnerabilities = []
    
    # Example checks
    if re.search(r"SELECT .* FROM .* WHERE .*='.*'", html, re.IGNORECASE):
        vulnerabilities.append("Potential SQL Injection vulnerability detected.")
    if re.search(r"<script>.*</script>", html, re.IGNORECASE):
        vulnerabilities.append("Potential XSS vulnerability detected.")
    if re.search(r"API_KEY|api_key|secret_key", html):
        vulnerabilities.append("Potential API key exposure detected.")
    if re.search(r"/admin", html):
        vulnerabilities.append("Potential admin panel exposure detected.")
    
    # More complex checks and analysis can be added here

    return vulnerabilities

# Function to attempt to extract site owner/host information
def extract_metadata(html):
    metadata = []
    
    # Check for metadata that might reveal owner info
    if re.search(r"author|owner|admin", html, re.IGNORECASE):
        metadata.append("Possible owner/admin information found.")
    
    # Example of extracting contact emails or names
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)
    if emails:
        metadata.append(f"Found email addresses: {', '.join(emails)}")
    
    # Example of extracting contact phone numbers
    # phones = re.findall(r'\+?\d[\d -]{8,12}\d', html)
    # if phones:
    #     metadata.append(f"Found phone numbers: {', '.join(phones)}")
    
    # More checks can be added here, like looking for special comments or metadata

    return metadata

# Function to generate report
def generate_report(vulnerabilities, metadata, url, filename):
    with open(filename, 'a', encoding='utf-8') as file:
        file.write(f"Report for {url}:\n")
        file.write("Vulnerabilities:\n")
        for vuln in vulnerabilities:
            file.write(f"- {vuln}\n")
        file.write("Metadata:\n")
        for data in metadata:
            file.write(f"- {data}\n")
        file.write("\n")
    print(f"Report updated: {filename}")

if __name__ == "__main__":
    start_url = input("Enter the URL of the website (e.g., https://example.com): ")
    domain = urlparse(start_url).netloc
    timestamp = int(time.time())
    report_file = f"vulnerability_report_{timestamp}.txt"
    
    to_visit = set([start_url])
    visited = set()

    while to_visit:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)
        
        html = fetch_page(url)
        if html:
            vulnerabilities = scan_for_vulnerabilities(html)
            metadata = extract_metadata(html)
            generate_report(vulnerabilities, metadata, url, report_file)
            
            links = extract_links(html, url, domain)
            to_visit.update(links - visited)
    
    print(f"Scanning complete. Report saved to {report_file}.")
