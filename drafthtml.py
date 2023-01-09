import requests
import re
from bs4 import BeautifulSoup

# Function to scan the website for vulnerabilities
def scan(url):
  # Send a GET request to the website
  r = requests.get(url)

  # Parse the HTML response
  soup = BeautifulSoup(r.text, 'html.parser')

  # Search for common patterns that may indicate vulnerabilities
  for tag in soup.find_all():
    # Check for cross-site scripting vulnerabilities
    if tag.name == 'script':
      src = tag.get('src')
      if src:
        if 'https://' not in src and 'http://' not in src:
          src = url + src
        r = requests.get(src)
        if 'xss' in r.text.lower():
          print('Possible XSS vulnerability found')
    # Check for SQL injection vulnerabilities
    elif tag.name == 'form':
      action = tag.get('action')
      if 'https://' not in action and 'http://' not in action:
        action = url + action
      r = requests.get(action)
      if 'sql' in r.text.lower():
        print('Possible SQL injection vulnerability found')

# Read the domain from the user
domain = input('Enter the domain of the website to scan: ')

# Scan the website
scan(domain)

# Write the output to a text file
with open('vulnerabilities.txt', 'w') as f:
  f.write('Scan complete. Any vulnerabilities found are listed above.')

