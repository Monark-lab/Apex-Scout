import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

class WebCrawler:
    def __init__(self, base_url, max_depth=2):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth

        self.visited = set()
        self.pages_with_params = [] # Changed from dict to list/set for recon
        self.forms = {}

    def crawl(self):
        self._crawl_recursive(self.base_url, depth=0)
        return {
            "base_url": self.base_url,
            "total_pages_found": len(self.visited),
            "pages_with_query_params": self.pages_with_params,
            "forms_found": self.forms
        }

    def _crawl_recursive(self, url, depth):
        # Normalize URL by removing fragments to prevent loops
        url = url.split('#')[0].rstrip('/')
        
        if depth > self.max_depth or url in self.visited:
            return

        self.visited.add(url)

        try:
            # Added a User-Agent to prevent being blocked by basic servers
            headers = {'User-Agent': 'VulnerabilityScanner/1.0'}
            response = requests.get(url, timeout=5, headers=headers)
            
            if "text/html" not in response.headers.get("Content-Type", ""):
                return

            soup = BeautifulSoup(response.text, "html.parser")

            self._extract_forms(url, soup)
            self._extract_links(url, soup, depth)

        except requests.RequestException as e:
            print(f"Error crawling {url}: {e}")
            return

    def _extract_links(self, current_url, soup, depth):
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)

            # Stay within the same domain
            if parsed.netloc == self.domain:
                # If the URL has parameters, it's a high-value target for SQLi/XSS
                if parsed.query:
                    if full_url not in self.pages_with_params:
                        self.pages_with_params.append(full_url)

                self._crawl_recursive(full_url, depth + 1)

    def _extract_forms(self, page_url, soup):
        forms = []
        for form in soup.find_all("form"):
            form_data = {
                "action": urljoin(page_url, form.get("action")), # Normalize action URL
                "method": form.get("method", "get").lower(),
                "inputs": []
            }

            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                if name:
                    form_data["inputs"].append({
                        "name": name,
                        "type": input_tag.get("type", "text")
                    })

            forms.append(form_data)

        if forms:
            self.forms[page_url] = forms