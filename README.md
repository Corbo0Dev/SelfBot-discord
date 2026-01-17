🤖 S€lfB0t – Discord Self-Bot

S€lfB0t is a Discord self-bot developed in Python using discord.py.
It provides various utilities such as message management, encoding tools, IP lookup, VPN/Tor detection, subdomain enumeration, and basic port scanning.

⚠️ Warning: This project uses a Discord self-bot, which is against Discord Terms of Service.
Use it at your own risk. The author is not responsible for any sanctions applied to your account.

✨ Features
🧹 Message Management

clear – Delete a specific number of messages

clearall – Delete all messages in a channel or DM

spam_dm – Send a message multiple times

🔐 Encoding & Utilities

hash – SHA-256 hashing

b64 – Base64 encode / decode

rot13 – ROT13 cipher

morse – Morse code conversion

🌐 Network & OSINT Tools

ipinfo – Get IP address information

vpn_check – Detect if an IP is likely a VPN/Proxy

tor_check – Check if you are using Tor

subdomain – Subdomain enumeration via crt.sh

port_scan – Basic TCP port scanner

📦 Requirements

Python 1.7.3

A Discord user token (not a bot token)

Python Dependencies

Install all required packages using:

pip install -r requirements.txt


Required libraries include:

discord.py

aiohttp

⚙️ Configuration

The bot uses a config.json file.

Example:

{
  "prefix": "!",
  "ipinfo": "on",
  "spammp": "on",
  "vpn_check": "on",
  "tor_check": "on",
  "clear": "on",
  "clearall": "on",
  "hash": "on",
  "b64": "on",
  "rot13": "on",
  "morse": "on",
  "subdomain": "on",
  "port_scan": "on"
}


You can configure the prefix and toggle features directly from the console menu.

▶️ Usage

Run the script:

python main.py


You will see a console menu:

[1] Start Self-Bot
[2] Config Self-Bot
[3] Notice
[4] Setup
[5] Exit


Choose Start Self-Bot

Enter your Discord user token

Use commands directly in Discord

📖 Commands
Command	Description
ping	Check bot status
clear <number>	Delete a number of messages
clearall	Delete all messages
spam_dm <times> <message>	Spam a message
hash <text>	SHA-256 hash
b64 encode/decode <text>	Base64 encoding
rot13 <text>	ROT13 cipher
morse <text>	Morse code
ipinfo <ip>	IP information
vpn_check [ip]	VPN detection
tor_check	Tor detection
subdomain <domain>	Subdomain enumeration
port_scan <ip> <ports>	Port scan (comma-separated ports)

🚨 Disclaimer

This self-bot violates Discord TOS

For educational purposes only

Do NOT use on accounts you care about

The developer is not responsible for misuse

👤 Author

Corbo0Dev
🔗 GitHub: https://github.com/Corbo0Dev

