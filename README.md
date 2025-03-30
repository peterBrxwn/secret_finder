# Secret Finder Burp Extension

## Overview
Secret Finder is a Burp Suite extension that scans HTTP responses for leaked API keys, tokens, credentials, and other sensitive information. It uses predefined regular expressions to detect a wide range of secrets.

## Features
- Automatically scans all HTTP responses for secrets
- Supports multiple API keys, authentication tokens, and credentials
- Logs detected secrets to Burp's output and alert system
- Highlights detected secrets in real-time

## Installation
1. Open Burp Suite.
2. Navigate to `Extender` > `Extensions`.
3. Click `Add`.
4. Select `Java` as the extension type.
5. Load the compiled `SecretFinder.jar` file.

## Usage
- Once loaded, the extension will automatically intercept HTTP responses.
- Any detected secrets will be logged in the Burp output and alerts tab.
- You can review the logs to identify exposed sensitive information.

## Detected Secrets
The extension detects the following types of secrets:
- Google API Keys
- AWS Access Keys
- Facebook Tokens
- Stripe API Keys
- Bearer Tokens
- Basic Authentication Credentials
- JWT Tokens
- RSA/DSA/EC Private Keys
- Email Addresses
- URLs and IP Addresses

**Note:** The regular expressions used in this extension were sourced from the following repository: [https://github.com/Lu3ky13/Search-for-all-leaked-keys-secrets-using-one-regex-](https://github.com/Lu3ky13/Search-for-all-leaked-keys-secrets-using-one-regex-).

## Contributing
If you would like to contribute or suggest additional regex patterns, feel free to submit a pull request or open an issue.

## License
Copyright (c) 2022-2023 PortSwigger Ltd. All rights reserved.

This extension is provided for use with Burp Suite Community and Professional editions, subject to their respective license agreements.