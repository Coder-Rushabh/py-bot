import socket
import re
from googlesearch import search
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse

def get_domain_from_url(url):
    """Extract the domain from a URL."""
    parsed_url = urlparse(url)
    return parsed_url.netloc or parsed_url.path

def get_ip_address(domain):
    """Fetch IP address for the given domain."""
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error as e:
        print(f"Error fetching IP address for {domain}: {e}")
        return None

def search_related_data(query):
    """Search for related data on the internet."""
    results = []
    try:
        for result in search(query, num_results=10):
            results.append(result)
    except Exception as e:
        print(f"Error searching for related data: {e}")
    return results

def extract_emails(text):
    """Extract email addresses from the text."""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(email_pattern, text)

def extract_emails_from_url(url):
    """Extract emails from the content of a given URL."""
    emails = []
    try:
        response = requests.get(url)
        if response.status_code == 200:
            emails.extend(extract_emails(response.text))
    except requests.RequestException as e:
        print(f"Error fetching content from {url}: {e}")
    return emails

def analyze_results(results):
    """Analyze search results to find connections and related information."""
    connections = []
    all_emails = []
    for result in results:
        if result:
            connections.append(result)
            # Fetch and analyze the content of each URL in the search results
            all_emails.extend(extract_emails_from_url(result))
    return connections, all_emails

def generate_report(domain, ip_address, related_data, connections, emails, filename):
    """Generate a report of the findings."""
    with open(filename, 'w') as file:
        file.write(f"Domain: {domain}\n")
        file.write(f"IP Address: {ip_address}\n\n")
        
        file.write("Related Data:\n")
        for data in related_data:
            file.write(f"{data}\n")
        
        file.write("\nConnections:\n")
        for conn in connections:
            file.write(f"{conn}\n")
        
        file.write("\nEmail Addresses:\n")
        for email in emails:
            file.write(f"{email}\n")
    
    print(f"Report has been saved to {filename}")

if __name__ == "__main__":
    url = input("Enter the URL of the website (e.g., https://example.com): ")
    report_file = input("Enter the name of the report file (e.g., report.txt): ")
    
    domain = get_domain_from_url(url)
    ip_address = get_ip_address(domain)
    related_data = search_related_data(domain)
    connections, emails = analyze_results(related_data)
    
    generate_report(domain, ip_address, related_data, connections, emails, report_file)
