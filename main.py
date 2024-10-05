import secrets
from CSolver.solver import Solver
import requests
import random
import os
import json
import time
from logger import log
import threading
import ua_generator
import tls_client
import base64
import re

with open('./data/proxies.txt', 'r') as f:
    proxies = f.readlines()
    
proxy = random.choice(proxies)

def solve(key, rqData, sitekey):
    csolver = Solver(key)
    st = time.time()
    while True:
        sol = csolver.hcaptcha(
            'hCaptchaEnterprise',
            sitekey,
            'discord.com',
            proxy,
            rqData
        )
        if sol == None:
            continue
        log.info(f"Solved --> {sol[:45]}... --> {round(time.time()-st,2)}s")
        return sol

def Context(inv):
    data = {
        "location": "Join Guild",
        "location_guild_id": "1279492848470855690",
        "location_channel_id": "1279492848470855693",
        "location_channel_type": 0
    }
    url = f"https://discord.com/api/v10/invites/{inv}"
    
    r = requests.get(url)
    sinfo = r.json()
    gid = sinfo['guild_id']
    cid = sinfo['channel']['id']
    data['location_guild_id'] = gid
    data['location_channel_id'] = cid
    context = base64.b64encode(json.dumps(data).encode()).decode()
    return context
    
def Cookies(session):
    r = session.get('https://discord.com')
    return r.cookies

def BuildNum():
    session = tls_client.Session(client_identifier="chrome_124")
    
    session.headers = {
        "Accept": "*/*",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": "https://discord.com/login",
        "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Sec-Fetch-Dest": "script",
        "Sec-Fetch-Mode": "no-cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    }
        
    try:
        r = session.get("https://discord.com/login")
        
        pattern = r'<script\s+src="([^"]+\.js)"\s+defer>\s*</script>'
        files = re.findall(pattern, r.text)
        
        build_number = None
        for file in files:
            bUrl = f"https://discord.com{file}"
            response = session.get(bUrl)
            if "buildNumber" in response.text:
                build_number = response.text.split('build_number:"')[1].split('"')[0]
                break
        
        return build_number if build_number else 326257
    except Exception:
        return 326257
    finally:
        session.close()

def Xprops(ua):
    data = {
        "os": "Windows",
        "browser": "Chrome",
        "device": "",
        "system_locale": "en-US",
        "browser_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "browser_version": "124.0.0.0",
        "os_version": "10",
        "referrer": "https://discord.com/channels/@me",
        "referring_domain": "discord.com",
        "referrer_current": "",
        "referring_domain_current": "",
        "release_channel": "stable",
        "client_build_number": BuildNum(),
        "client_event_source": None
    }
    
    regex = re.compile(
        r'Mozilla/5\.0 \(([^;]+);.*\) AppleWebKit/([0-9\.]+) \(KHTML, like Gecko\) (?P<browser>[\w\-]+)\/([0-9\.]+) Safari/[0-9\.]+')

    match = regex.match(ua)
    if match:
        OSI, _, browser_name, browser_version = match.groups()
        
        os = OSI.split(" ")[0]
        OSV = " ".join(OSI.split(" ")[1:]) if len(OSI.split(" ")) > 1 else data["os_version"]
        
        data["os"] = os
        data["os_version"] = OSV.split("T ")[1].split(".")[0] if "T " in OSV else OSV
        data["browser"] = browser_name
        data["browser_version"] = browser_version
        data["browser_user_agent"] = ua
    
    ndata = base64.b64encode(json.dumps(data).encode()).decode()
    return ndata

def clientID(ua):
    pattern = r'(Chrome|Firefox|Safari|Edge|Opera)\/(\d+)'
    match = re.search(pattern, ua)
    
    if match:
        browser = match.group(1)
        version = match.group(2)
        client_identifier = f"{browser.lower()}_{version}"
        return client_identifier.lower()
    else:
        return "chrome_124"

def Name(token):
    url = 'https://discord.com/api/v10/users/@me'

    headers = {
        'Authorization': token
    }
    
    r = requests.get(url, headers=headers)
    return r.json()['global_name']

def GID(inv):
    url = f"https://discord.com/api/v10/invites/{inv}"
    
    r = requests.get(url)
    sinfo = r.json()
    id = sinfo['guild_id']
    return id

def GName(inv):
    url = f"https://discord.com/api/v10/invites/{inv}"
    
    r = requests.get(url)
    sinfo = r.json()
    name = sinfo['guild']['name']
    return name
        
def Nickname(name, gid, ua):
    headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'authorization': token,
        'content-type': 'application/json',
        'dnt': '1',
        'origin': 'https://discord.com',
        'priority': 'u=1, i',
        'referer': 'https://discord.com/channels/@me',
        'sec-ch-ua': '"Google Chrome";v="124", "Not=A?Brand";v="8", "Chromium";v="124"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': ua,
        'x-debug-options': 'bugReporterEnabled',
        'x-discord-locale': 'en-US',
        'x-discord-timezone': 'America/Los_Angeles',
        'x-super-properties': Xprops(ua),
    }
    url = f'https://discord.com/api/v9/guilds/{gid}/members/@me'
    data = {
        'nick': name
    }
    r = requests.patch(url, json=data, headers=headers)
    pending = r.json()['pending']
    nick = r.json()['nick']
    if not pending and nick == name:
        log.info(f"Changed Nickname --> {name}")
        
def join(token):
    ua = str(ua_generator.generate(device='desktop', browser=('chrome', 'edge')))
    with open('./data/config.json', 'r') as f:
        config = json.load(f)
        
    inv = config['Invite']
    changeNick = config['Nickname']['Change']
    nick = config['Nickname']['name']
    apiKey = config['CSolver']['API-Key']
    
    st = time.time()
    name = Name(token)
    log.working(f"Joining --> {name} --> {GName(inv)}")
    session = tls_client.Session(random_tls_extension_order=True, client_identifier=clientID(ua))

    session.cookies = Cookies(session)

    session.headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'authorization': token,
        'content-type': 'application/json',
        'dnt': '1',
        'origin': 'https://discord.com',
        'priority': 'u=1, i',
        'referer': 'https://discord.com/channels/@me',
        'sec-ch-ua': '"Google Chrome";v="124", "Not=A?Brand";v="8", "Chromium";v="124"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': ua,
        'x-context-properties': Context(inv),
        'x-debug-options': 'bugReporterEnabled',
        'x-discord-locale': 'en-US',
        'x-discord-timezone': 'America/Los_Angeles',
        'x-super-properties': Xprops(ua),
    }

    jData = {
        'session_id': secrets.token_hex(16),
    }

    r = session.post(f'https://discord.com/api/v9/invites/{inv}', json=jData)
    
    if 'captcha_key' in r.text:
        log.warn(f"Solving Captcha --> {name}")
        rqToken = r.json()['captcha_rqtoken']
        rqData = r.json()['captcha_rqdata']
        sitekey = r.json()['captcha_sitekey']
        session.headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': token,
            'content-type': 'application/json',
            'dnt': '1',
            'origin': 'https://discord.com',
            'priority': 'u=1, i',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': '"Google Chrome";v="124", "Not=A?Brand";v="8", "Chromium";v="124"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': ua,
            'x-captcha-key': solve(apiKey, rqData, sitekey),
            'x-captcha-rqtoken': rqToken,
            'x-context-properties': Context(inv),
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-discord-timezone': 'America/Los_Angeles',
            'x-super-properties': Xprops(ua),
        }
        
        jData = {
            'session_id': secrets.token_hex(16),
        }

        r = session.post(f'https://discord.com/api/v9/invites/{inv}', json=jData)
        if 'new_member' in r.json():
            log.success(f"Joined --> {name} --> {str(r.json()['guild']['name'])}", round(time.time()-st,2))
            if changeNick:
                Nickname(nick, GID(inv), ua)
        else:
            log.fail(f"Failed To Join --> {name} --> {str(r.json())}")
    elif 'new_member' in r.json():
        log.success(f"Joined --> {name} --> {str(r.json()['guild']['name'])}", round(time.time()-st,2))
        if changeNick:
            Nickname(nick, GID(inv), ua)
    else:
        log.fail(f"Failed To Join --> {name} --> {str(r.json())}")
        
if __name__ == "__main__":
    with open('./data/tokens.txt', 'r') as f:
        tokens = f.readlines()
    
    try:
        os.system('cls')
    except:
        os.system('clear')

    threads = []
    for token in tokens:
        t = threading.Thread(target=join, args=(token,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
