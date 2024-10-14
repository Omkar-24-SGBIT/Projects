import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from requests.exceptions import RequestException, SSLError

def check_url(url):
    try:
        # Check URL format
        if not re.match(r"^https?://", url):
            return False, "URL should start with 'http://' or 'https://'"

        # Extract domain from URL
        domain = urlparse(url).netloc

        # Verify SSL certificate
        response = requests.get(url)
        response.raise_for_status()

        # Parse HTML content
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check for SSL certificate
        if not response.url.startswith("https://"):
            return False, "No SSL certificate detected"

        # Check for contact information
        contact_info = soup.find_all(["address", "footer", "contact"])
        if not contact_info:
            return False, "No contact information found"

        # Check for poor design or grammar
        if len(soup.text) < 100:
            return False, "Low-quality design or content"

        # Check for security seals and logos
        security_seals = soup.find_all("img", alt=re.compile(r"security|trust"))
        if not security_seals:
            return False, "No security seals or logos found"

        return True, "The website seems legitimate"

    except SSLError:
        return False, "Certificate verification failed: SSL certificate expired (potential phishing website)"

    except RequestException as e:
        return False, f"Error: {str(e)}"

# Example usage:
url = "https://html.house/l7ceeid6.html"
is_legitimate, message = check_url(url)
print(message)
