# Website-Information-Gathering
using Python
# Website Information Gathering Tool using Python

## Overview
This tool is designed to gather information about a website using Python. It extracts various details such as domain name, IP address, server type, SSL certificate information, and more. It can be useful for security assessments, website monitoring, or just general curiosity about a website.

## Features
- **Domain Information**: Retrieves basic information about the domain, including registrar, creation date, and expiration date.
- **IP Address**: Finds the IP address associated with the domain.
- **Server Information**: Detects the type of server hosting the website.
- **SSL Certificate**: Checks for the presence of SSL certificate and provides details such as issuer, expiration date, and encryption strength.
- **WHOIS Lookup**: Performs a WHOIS lookup to retrieve ownership and contact information for the domain.

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/website-info-tool.git
   ```
2. Navigate to the project directory:
   ```
   cd website-info-tool
   ```
3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
1. Run the script `website_info.py`:
   ```
   python website_info.py
   ```
2. Enter the URL of the website you want to gather information about.
3. The tool will display the gathered information on the console.

## Example
```
Enter the URL of the website: example.com

Website Information:
--------------------
Domain: example.com
IP Address: 93.184.216.34
Server: Apache
SSL Certificate:
    - Issuer: DigiCert Inc
    - Expiration Date: 2025-08-20
    - Encryption: 256-bit AES
Domain Registrar: GoDaddy
Creation Date: 1995-08-14
Expiration Date: 2022-08-13
```

## Contributing
Contributions are welcome! If you have any suggestions, improvements, or new features you'd like to add, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
