🤖 S€lfB0t – Discord Self-Bot

S€lfB0t is a Discord self-bot developed in Python using discord.py.
It provides various utilities such as message management, encoding tools, IP lookup, VPN/Tor detection, subdomain enumeration, and basic port scanning.

⚠️ Warning: This project does not comply with Discord's TOS. I am not responsible in case of account deactivation or ban. I still try to minimize the risks.

🔧 Features
-------------------------------------------
💬 Message Management

clear - Delete a certain number of messages in a channel/DM

clearall - Delete all your messages in a channel or private discussion

spam - Spam a number of messages in a private discussion or channel

pic - Get the avatar URL of a user

🔐 Encoding & Utilities

hash – Hash a text in SHA-256 

b64 – Encode or decode a text in Base64

rot13 – ROT13 cipher

morse – Convert a text to morse code

🌐 Network & OSINT Tools

ipinfo – Retrieve information from an IP address

vpn_check – Detect if an IP address is under VPN

subdomain – See all subdomains of a website

port_scan – TCP port scanner

-------------------------------------------
📦 Requirements

Python 3.0+

Run the commands:
      pip install -r requirements.txt

-------------------------------------------

⚙️ Configuration

The bot uses a **config.json** file

Example:

{
  "prefix": "!",
  "ipinfo": "on",
  "spammp": "on",
  "vpn_check": "on",
  "clear": "on",
  "clearall": "on",
  "hash": "on",
  "b64": "on",
  "rot13": "on",
  "morse": "on",
  "subdomain": "on",
  "port_scan": "on",
  "pic": "on"
}


You can configure the prefix using option 2 in the main menu.

-------------------------------------------

🤖 Usage

Run the command:
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
spam <times> <message>	Spam a message
pic [user]	Get avatar URL (yours or mentioned user's)
hash <text>	SHA-256 hash
b64 encode/decode <text>	Base64 encoding
rot13 <text>	ROT13 cipher
morse <text>	Morse code
ipinfo <ip>	IP information
vpn_check [ip]	VPN detection
subdomain <domain>	Subdomain enumeration
port_scan <ip> <ports>	Port scan (comma-separated ports)

-------------------------------------------

🚨 Disclaimer

This self-bot violates Discord TOS

For educational purposes only

Do NOT use on accounts you care about

The developer is not responsible for misuse
-------------------------------------------

👤 Author

Corbo0Dev
🔗 GitHub: https://github.com/Corbo0Dev