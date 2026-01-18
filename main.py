import discord
from discord.ext import commands
import aiohttp
import socket
import base64
import codecs
import hashlib
import json
import os
import sys
import asyncio
sys.tracebacklimit = 1
def loadjson(filename):
    with open(filename, "r") as f:
        return json.load(f)
def savejson(filename, data):
    with open(filename, "w", encoding='utf-8') as f:
        json.dump(data, f, indent=4)
config = loadjson("config.json")
PREFIX = config["prefix"]
bot = commands.Bot(command_prefix=PREFIX, intents=discord.Intents.all(), self_bot=True)
bot.remove_command("help")
def run_bot(auth):
    print("[console] >> Bot starting...")
    try:
        bot.run(auth, bot=False)
    except Exception as e:
        print(f"[console] >> Bot error: {e}")

def update_config(key: str, prompt: str) -> None:
    """Helper function to update config values"""
    value = input(f"[console] >> {prompt} (on/off): ")
    config[key] = "on" if value.lower() == "on" else "off"
    savejson("config.json", config)

def menu():
    while True:
        print("""  .oooooo.                       .o8                   .oooo.   oooooooooo.                         
 d8P'  `Y8b                     "888                  d8P'`Y8b  `888'   `Y8b                        
888           .ooooo.  oooo d8b  888oooo.   .ooooo.  888    888  888      888  .ooooo.  oooo    ooo 
888          d88' `88b `888""8P  d88' `88b d88' `88b 888    888  888      888 d88' `88b  `88.  .8'  
888          888   888  888      888   888 888   888 888    888  888      888 888ooo888   `88..8'   
`88b    ooo  888   888  888      888   888 888   888 `88b  d88'  888     d88' 888    .o    `888'    
 `Y8bood8P'  `Y8bod8P' d888b     `Y8bod8P' `Y8bod8P'  `Y8bd8P'  o888bood8P'   `Y8bod8P'     `8'     
                                                                                                    
                                                                                                                                                                                                    
S€lfB0t by Corbo0Dev - github.com/Corbo0Dev
          
    [1] Start Self-Bot
    [2] Config Self-Bot (SOON)
    [3] Notice
    [4] Setup
    [5] Exit""")
        choice = input("[console] >>  ")
        if choice == "1":
            auth = input("[console] >> Enter your Discord Token: ")
            run_bot(auth)
        elif choice == "2":
            prefix = input("[console] >> Enter your desired prefix: ")
            config["prefix"] = prefix
            savejson("config.json", config)
            
            update_config("ipinfo", "Ipinfo")
            update_config("spammp", "Spammp")
            update_config("vpn_check", "Vpn Check")
            update_config("tor_check", "Tor Check")
            update_config("clear", "Clear")
            update_config("clearall", "Clear All")
            update_config("hash", "Hash")
            update_config("b64", "Base 64")
            update_config("rot13", "Rot13")
            update_config("morse", "Morse")
            update_config("subdomain", "Subdomain")
            update_config("port_scan", "Port Scanner")
        elif choice == "5":
            print("[console] >> Exiting...")
            os._exit(0)
        elif choice == "3":
            print("""[console] >> Notice:
- This self-bot does not respect Discord TOS
- Use at your own risk
- Regularly find updates on my github (github.com/Corbo0Dev)""")
            input("[console] >> Press Enter to continue...")
        elif choice == "4":
            os.system("pip install -r requirements.txt")
        clean_console()
        menu()
        
            
        

    


def clean_console():
    os.system('cls' if os.name == 'nt' else 'clear')


# ////////////////  DISCORD SELF-BOT //////////////////////////////////////

@bot.event
async def on_ready():
    print(f"S€lfB0t status: on | prefix: {PREFIX}")
    


@bot.command()
async def ping(ctx):
    await ctx.message.delete()
    await ctx.send("Pong")


@bot.command()
async def clear(ctx, number: int):
    
    await ctx.message.delete()
    
    deleted = 0
    async for message in ctx.channel.history(limit=number):
        try:
            await message.delete()
            deleted += 1
        except:
            pass
    
    await ctx.send(f"{deleted} messages deleted.", delete_after=5)


@bot.command()
async def clearall(ctx):
    await ctx.message.delete()
    
    deleted = 0
    async for message in ctx.channel.history(limit=None):
        try:
            await message.delete()
            deleted += 1
        except:
            pass
    await ctx.send(f"{deleted} messages deleted.", delete_after=5)


@bot.command()
async def help(ctx):
    message = f"""
# 🤖 S€lfB0t by Corbo0Dev (github.com/Corbo0Dev)
- {PREFIX}clear <number> - Delete a certain number of messages
- {PREFIX}clearall - Delete all messages in the channel/dm
- {PREFIX}hash <text> - SHA-256 hash
- {PREFIX}b64 encode/decode <text> - Base64
- {PREFIX}rot13 <text> - ROT13
- {PREFIX}morse <text> - Morse Code
- {PREFIX}ipinfo <ip> - IP information
- {PREFIX}vpn_check [ip] - Check if detected on VPN
- {PREFIX}subdomain - Subdomain enumeration
- {PREFIX}port_scan - Port scan (comma-separated ports)
- {PREFIX}pic - """
    await ctx.message.delete()
    await ctx.send(message)

@bot.command()
async def hash(ctx, *, message: str):
    await ctx.message.delete()
    hash_object = hashlib.sha256(message.encode())
    hex_dig = hash_object.hexdigest()
    result = f"""- Text: {message}
- Hash: SHA-256
- Result: {hex_dig}"""
    await ctx.send(result)

@bot.command()
async def b64(ctx, action: str, *, text: str):
    await ctx.message.delete()
    try:
        if action.lower() == "encode":
            result = base64.b64encode(text.encode()).decode()
            await ctx.send(f"**Base64 Encode:**\n```{result}```")
        elif action.lower() == "decode":
            result = base64.b64decode(text.encode()).decode()
            await ctx.send(f"**Base64 Decode:**\n```{result}```")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command()
async def rot13(ctx, *, text: str):
    await ctx.message.delete()
    result = codecs.encode(text, 'rot_13')
    await ctx.send(f"**ROT13:**\n```{result}```")
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
    "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
    '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.',
    '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.'
}

@bot.command()
async def morse(ctx, *, text: str):
    await ctx.message.delete()
    result = ' '.join(MORSE_CODE_DICT.get(char.upper(), '') for char in text if char.upper() in MORSE_CODE_DICT or char == ' ')
    await ctx.send(f"**Morse Code:**\n```{result}```")

@bot.command()
async def ipinfo(ctx, ip: str):
    
    await ctx.message.delete()
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"http://ip-api.com/json/{ip}") as resp:
                data = await resp.json()
                if data['status'] == 'success':
                    message = f"""IP Information for {ip}:
- 🏴 Country: {data['country']}
- 🏞️ Region: {data['regionName']}
- 🏙️ City: {data['city']}
- 📡 ISP: {data['isp']}
- 🏢 Organization: {data['org']}
- ⏰ Timezone: {data['timezone']}
- IP Address: {data['query']}"""
                    await ctx.send(message)
        except Exception as e:
            await ctx.send(f"Error: {e}")

@bot.command()
async def vpn_check(ctx, ip: str = None):
    await ctx.message.delete()
    await ctx.send("VPN check in progress...")
    
    async with aiohttp.ClientSession() as session:
        try:
            url = f"http://ip-api.com/json/{ip}" if ip else "http://ip-api.com/json/"
            async with session.get(url) as resp:
                data = await resp.json()
            
            if data.get('status') == 'fail':
                await ctx.send(f"❌ Error: Invalid or inaccessible IP")
                return
            
            checked_ip = data.get('query')
            isp = data.get('isp', '').lower()
            org = data.get('org', '').lower()
            
            vpn_providers = ['vpn', 'proxy', 'datacamp', 'hosting', 'datacenter', 'vps', 'aws', 'azure', 'digitalocean', "proton"]
            
            is_vpn = any(provider in isp or provider in org for provider in vpn_providers)
            
            message = f"""**VPN Check:**
- VPN Detected: {'YES' if is_vpn else 'NO'}
- IP: {checked_ip}
- ISP: {data.get('isp')}
- Org: {data.get('org')}
- Country: {data.get('country')}"""
            
            await ctx.send(message)
        except Exception as e:
            await ctx.send(f"Error: {e}")



@bot.command()
async def subdomain(ctx, domain: str):
    await ctx.message.delete()
    await ctx.send("Subdomain enumeration in progress...")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://crt.sh/?q=%25.{domain}&output=json") as resp:
                data = await resp.json()
                
                subdomains = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and subdomain.endswith(domain):
                            subdomains.add(subdomain)
                
                if subdomains:
                    subdomains_list = "\n".join(sorted(subdomains)[:50])
                    message = f"**Subdomains found ({len(subdomains)}):**\n```{subdomains_list}```"
                    if len(subdomains) > 50:
                        message += f"\n... and {len(subdomains) - 50} more"
                    await ctx.send(message)
                else:
                    await ctx.send("No subdomains found")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command()
async def port_scan(ctx, ip: str, *, ports: str):
    await ctx.message.delete()
    await ctx.send(f"Port scan in progress (ip: {ip})...")
    
    try:
        port_list = [int(p.strip()) for p in ports.split(',')]
        
        results = {
            'open': [],
            'closed': []
        }
        
        for port in port_list:
            socket.setdefaulttimeout(1)
            try:
                result = socket.create_connection((ip, port), timeout=1)
                result.close()
                results['open'].append(port)
            except (socket.timeout, socket.refused_error, OSError):
                results['closed'].append(port)
        
        open_ports = "\n".join(str(p) for p in results['open']) or "None"
        closed_ports = "\n".join(str(p) for p in results['closed'][:10]) or "None"
        
        report = f"""**Port Scan Report - {ip}**
**Open ports:** {len(results['open'])}
{open_ports}

**Closed ports:** {len(results['closed'])}
{closed_ports}
{'...' if len(results['closed']) > 10 else ''}"""
        
        await ctx.send(report)
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command()
async def pic(ctx, user: discord.User = None):
    await ctx.message.delete()
    
    if user is None:
        user = ctx.author
    
    avatar_url = str(user.avatar_url)
    await ctx.send(f"**{user}**:\n{avatar_url}")

@bot.command()
async def spam(ctx, times: int, *, message: str):
    await ctx.message.delete()
    if times > 100:
        await ctx.send("Limit: 100 message", delete_after=5)
        return
    
    if times < 1:
        await ctx.send("The number must be greater than 0", delete_after=5)
        return
    
    for i in range(times):
        try:
            await ctx.send(message)
        except discord.errors.Forbidden:
            await ctx.send("Permissions denied", delete_after=5)
            break
        except discord.errors.HTTPException as e:
            await ctx.send(f"Error : {e}", delete_after=5)
            break
    

menu()



