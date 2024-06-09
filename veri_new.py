import time
import requests
import re
import httpx
import uuid
import os
import subprocess
import threading
import random
import string
from uuid import UUID
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from github import Github


def change_cookies_fb(cookies: str) -> dict[str]:
    result = {}
    try:
        for i in cookies.split(';'):
            result.update({i.split('=')[0]: i.split('=')[1]})
        return result
    except(Exception,):
        for i in cookies.split('; '):
            result.update({i.split('=')[0]: i.split('=')[1]})
        return result


def upload_data(data_to_save: str) -> None:
    g = Github("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")

    repo = g.get_repo("HuynhMainHatMinh/dataADB")

    file_path = "VERI/data.txt"

    file = repo.get_contents(file_path)
    current_content = file.decoded_content.decode("utf-8")
    current_sha = file.sha

    new_content = current_content + "\n" + data_to_save + "\n"
    repo.update_file(file_path, "", new_content, current_sha, branch="main")


class Vnpt:
    @classmethod
    def loginvnpt(cls) -> dict[str]:
        response = requests.post(
            'http://192.168.1.1/cgi-bin/login.asp', headers={
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Content-Type': 'application/x-www-form-urlencoded',
                'DNT': '1',
                'Origin': 'https://192.168.1.1',
                'Pragma': 'no-cache',
                'Referer': 'https://192.168.1.1/cgi-bin/login.asp',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 920)',
                'sec-ch-ua': '"Chromium";v="117", "Not;A=Brand";v="8"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
            }, data={
                'StatusActionFlag': '',
                'Auth_LoginID': 'admin',
                'Auth_Password': 'Vnpt@123',
            }, verify=False
            )
        cookies: dict[str] = response.cookies.get_dict()
        cookies.update({"base64": "dWlkID1hZG1pbjsgcHN3PVZucHRAMTIz"})
        return cookies

    @classmethod
    def csrftoken(cls, cookies: dict[str]) -> str:
        try:
            response = requests.post(
                'http://192.168.1.1/cgi-bin/home_wan.asp', cookies=cookies, headers={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'DNT': '1',
                    'Origin': 'https://192.168.1.1',
                    'Pragma': 'no-cache',
                    'Referer': 'https://192.168.1.1/cgi-bin/home_wan.asp',
                    'Sec-Fetch-Dest': 'frame',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 920)',
                    'sec-ch-ua': '"Chromium";v="117", "Not;A=Brand";v="8"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                }, data={
                    'submit_disable': 'No',
                    'hidEncapFlag': '0',
                    'hidEncap': '0',
                    'wanIsCreated': 'Yes',
                    'editFlag': '0',
                    'EditingWan': '-1',
                    'isIPv6Supported': '1',
                    'DynIPv6Enable_flag': '1',
                    'PPPDHCPv6Enable_Flag': 'N/A',
                    'PPPDHCPv6Mode_Flag': '0',
                    'IPv6PD_Flag': 'Yes',
                    'DHCP6SMode_Flag': '0',
                    'IPVERSION_IPv4': 'IPv4',
                    'wanTransFlag': '0',
                    'wanBarrierFlag': '0',
                    'ptm_VC': '8',
                    'wanVCFlag': '3',
                    'service_num_flag': '0',
                    'wanSaveFlag': '1',
                    'vciCheckFlag': '0',
                    'wanEncapFlag': '0',
                    'DSLITE_MANUAL_MODE': '1',
                    'IPVersion_Flag': '0',
                    'newVLANFlag': '1',
                    'is8021xsupport': '0',
                    'isDSLITESupported': '1',
                    'wan_8021q': '1',
                    'disp_wan_8021q': '1',
                    'DefaultWan_Active': 'No',
                    'DefaultWan_ISP': '3',
                    'DefaultWan_IPVERSION': 'IPv4',
                    'DefaultWan_MLDproxy': 'N/A',
                    'ipv6SupportValue': '0',
                    'UserMode': '0',
                    'wan_certificate': 'N/A',
                    'wan_CA': 'N/A',
                    'wan_HiddenBiDirectionalAuth': 'N/A',
                    'IPv6PrivacyAddrsSupportedFlag': 'N/A',
                    'wan_TransMode': 'Fiber',
                    'wan_VC': '1',
                    'wan_VCStatus': 'Yes',
                    'ipVerRadio': 'IPv4',
                    'wanTypeRadio': '2',
                    'wan_dot1q': 'Yes',
                    'wan_vid': '11',
                    'wan_dot1pRemark': 'Remark',
                    'wan_dot1p': '0',
                    'wan_mvlan': '-1',
                    'wan_FIREWALL': 'Enable',
                    'wan_TCPBridge': '1492',
                    'wan_status': 'Disabled',
                    'wan_eapIdentity': '',
                    'wan_authentication': 'on',
                    'wan_BridgeInterface0': 'No',
                    'WAN_DefaultRoute0': 'Yes',
                    'wan_TCPMTU0': '1492',
                    'wan_NAT0': 'Enable',
                    'wan_RIP0': 'RIP1',
                    'wan_RIP_Dir0': 'None',
                    'wan_IGMP0': 'No',
                    'DynIPv6EnableRadio': '1',
                    'PPPIPv6PDRadio0': 'Yes',
                    'wan_MLD0': 'No',
                    'DSLITEEnableRadio0': 'No',
                    'DSLITEModeRadio0': '0',
                    'DSLITEAddr0': 'N/A',
                    'wan_BridgeInterface1': 'No',
                    'WAN_DefaultRoute1': 'Yes',
                    'wan_TCPMTU1': '1492',
                    'wan_StaticIPaddr1': '',
                    'wan_StaticIPSubMask1': '',
                    'wan_StaticIpGateway1': '',
                    'wan_NAT1': 'Enable',
                    'wan_RIP1': 'RIP1',
                    'wan_RIP_Dir1': 'None',
                    'wan_IGMP1': 'No',
                    'wan_IPv6Addr': '',
                    'wan_IPv6Prefix': '',
                    'wan_IPv6DefGw': '',
                    'wan_IPv6DNS1': '',
                    'wan_IPv6DNS2': '',
                    'wan_MLD1': 'No',
                    'DSLITEEnableRadio1': 'No',
                    'DSLITEAddr1': '',
                    'wan_PPPUsername': 'huynhhoa21',
                    'TTNETGuiSupport': '0',
                    'wan_PPPPassword': 'vungtau',
                    'wan_BridgeInterface2': 'No',
                    'wan_ConnectSelect': 'Connect_Keep_Alive',
                    'wan_TCPMSS': '0',
                    'WAN_DefaultRoute2': 'Yes',
                    'wan_PPPGetIP': 'Dynamic',
                    'wan_NAT2': 'Enable',
                    'wan_RIP2': 'RIP1',
                    'wan_RIP_Dir2': 'None',
                    'wan_TCPMTU2': '1492',
                    'wan_IGMP2': 'No',
                    'PPPIPv6ModeRadio': '0',
                    'PPPIPv6PDRadio2': 'Yes',
                    'wan_MLD2': 'No',
                    'DSLITEEnableRadio2': 'No',
                    'DSLITEModeRadio2': '0',
                    'DSLITEAddr2': '',
                    'isPPPAuthen': 'N/A',
                    'isWanTagChk': 'N/A',
                    'isdot1pSupport': 'Yes',
                    'isTPIDSupported': 'N/A',
                    'DefaultDmz_Active': 'No',
                    'DefaultDmz_HostIP': '0.0.0.0',
                    'delWanFlag': '0',
                    'CsrfToken': ''
                }, verify=False).text
            return re.findall(r'NAME="CsrfToken" VALUE="([^"]*)"', response)[0]
        except(IndexError, ):
            return "NONE"

    @classmethod
    def reset_vnpt(cls, CsrfToken: str, cookies: dict[str]) -> None:
        _ = requests.post(
            'http://192.168.1.1/cgi-bin/home_wan.asp', cookies=cookies, headers={
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Content-Type': 'application/x-www-form-urlencoded',
                'DNT': '1',
                'Origin': 'https://192.168.1.1',
                'Pragma': 'no-cache',
                'Referer': 'https://192.168.1.1/cgi-bin/home_wan.asp',
                'Sec-Fetch-Dest': 'frame',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 920)',
                'sec-ch-ua': '"Chromium";v="117", "Not;A=Brand";v="8"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
            }, data={
                'submit_disable': 'No',
                'hidEncapFlag': '0',
                'hidEncap': '0',
                'wanIsCreated': 'Yes',
                'editFlag': '0',
                'EditingWan': '-1',
                'isIPv6Supported': '1',
                'DynIPv6Enable_flag': '1',
                'PPPDHCPv6Enable_Flag': 'N/A',
                'PPPDHCPv6Mode_Flag': '0',
                'IPv6PD_Flag': 'Yes',
                'DHCP6SMode_Flag': '0',
                'IPVERSION_IPv4': 'IPv4',
                'wanTransFlag': '0',
                'wanBarrierFlag': '0',
                'ptm_VC': '8',
                'wanVCFlag': '3',
                'service_num_flag': '0',
                'wanSaveFlag': '1',
                'vciCheckFlag': '0',
                'wanEncapFlag': '0',
                'DSLITE_MANUAL_MODE': '1',
                'IPVersion_Flag': '0',
                'newVLANFlag': '1',
                'is8021xsupport': '0',
                'isDSLITESupported': '1',
                'wan_8021q': '1',
                'disp_wan_8021q': '1',
                'DefaultWan_Active': 'No',
                'DefaultWan_ISP': '3',
                'DefaultWan_IPVERSION': 'IPv4',
                'DefaultWan_MLDproxy': 'N/A',
                'ipv6SupportValue': '0',
                'UserMode': '0',
                'wan_certificate': 'N/A',
                'wan_CA': 'N/A',
                'wan_HiddenBiDirectionalAuth': 'N/A',
                'IPv6PrivacyAddrsSupportedFlag': 'N/A',
                'wan_TransMode': 'Fiber',
                'wan_VC': '1',
                'wan_VCStatus': 'Yes',
                'ipVerRadio': 'IPv4',
                'wanTypeRadio': '2',
                'wan_dot1q': 'Yes',
                'wan_vid': '11',
                'wan_dot1pRemark': 'Remark',
                'wan_dot1p': '0',
                'wan_mvlan': '-1',
                'wan_FIREWALL': 'Enable',
                'wan_TCPBridge': '1492',
                'wan_status': 'Disabled',
                'wan_eapIdentity': '',
                'wan_authentication': 'on',
                'wan_BridgeInterface0': 'No',
                'WAN_DefaultRoute0': 'Yes',
                'wan_TCPMTU0': '1492',
                'wan_NAT0': 'Enable',
                'wan_RIP0': 'RIP1',
                'wan_RIP_Dir0': 'None',
                'wan_IGMP0': 'No',
                'DynIPv6EnableRadio': '1',
                'PPPIPv6PDRadio0': 'Yes',
                'wan_MLD0': 'No',
                'DSLITEEnableRadio0': 'No',
                'DSLITEModeRadio0': '0',
                'DSLITEAddr0': 'N/A',
                'wan_BridgeInterface1': 'No',
                'WAN_DefaultRoute1': 'Yes',
                'wan_TCPMTU1': '1492',
                'wan_StaticIPaddr1': '',
                'wan_StaticIPSubMask1': '',
                'wan_StaticIpGateway1': '',
                'wan_NAT1': 'Enable',
                'wan_RIP1': 'RIP1',
                'wan_RIP_Dir1': 'None',
                'wan_IGMP1': 'No',
                'wan_IPv6Addr': '',
                'wan_IPv6Prefix': '',
                'wan_IPv6DefGw': '',
                'wan_IPv6DNS1': '',
                'wan_IPv6DNS2': '',
                'wan_MLD1': 'No',
                'DSLITEEnableRadio1': 'No',
                'DSLITEAddr1': '',
                'wan_PPPUsername': 'huynhhoa21',
                'TTNETGuiSupport': '0',
                'wan_PPPPassword': 'vungtau',
                'wan_BridgeInterface2': 'No',
                'wan_ConnectSelect': 'Connect_Keep_Alive',
                'wan_TCPMSS': '0',
                'WAN_DefaultRoute2': 'Yes',
                'wan_PPPGetIP': 'Dynamic',
                'wan_NAT2': 'Enable',
                'wan_RIP2': 'RIP1',
                'wan_RIP_Dir2': 'None',
                'wan_TCPMTU2': '1492',
                'wan_IGMP2': 'No',
                'PPPIPv6ModeRadio': '0',
                'PPPIPv6PDRadio2': 'Yes',
                'wan_MLD2': 'No',
                'DSLITEEnableRadio2': 'No',
                'DSLITEModeRadio2': '0',
                'DSLITEAddr2': '',
                'isPPPAuthen': 'N/A',
                'isWanTagChk': 'N/A',
                'isdot1pSupport': 'Yes',
                'isTPIDSupported': 'N/A',
                'DefaultDmz_Active': 'No',
                'DefaultDmz_HostIP': '0.0.0.0',
                'delWanFlag': '0',
                'CsrfToken': CsrfToken
            }, verify=False).text

    def run(self) -> None:
        while True:
            cookies = self.loginvnpt()
            CsrfToken = self.csrftoken(cookies)
            if CsrfToken == "NONE":
                time.sleep(10)
                pass
            else:
                self.reset_vnpt(CsrfToken=CsrfToken, cookies=cookies)
                break

    @staticmethod
    def check_connection() -> bool:
        while True:
            command = f"ping -n 1 1.1.1.1"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            if "Destination net unreachable" in str(output.decode()):
                continue
            elif "Request timed out." in str(output.decode()):
                continue
            else:
                break
        return True


class VeriMail(threading.Thread):
    def __init__(self, data_account: str) -> None:
        super(VeriMail, self).__init__()

        self.info: str = data_account

        self.data_account: list[str] = data_account.split("|")

        self.cookie_account: str = self.data_account[-1]
        self.id_account: str = self.data_account[0]

        self.cookies: dict[str] = change_cookies_fb(self.cookie_account)

        self.code = []

        self.session = requests.Session()

        self.session.cookies.update(self.cookies)

    def add_cover_image(self) -> bool:
        list_os = random.choice(os.listdir('COVER'))

        IMG_FILE = f'COVER/{list_os}'
        try:
            profile = self.session.get(
                "https://www.facebook.com/profile.php", params={
                    'id': self.id_account,
                }, headers={
                    'authority': 'www.facebook.com',
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'accept-language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
                    'cache-control': 'max-age=0',
                    'dpr': '1.25',
                    'referer': 'https://www.facebook.com/',
                    'sec-ch-prefers-color-scheme': 'dark',
                    'sec-ch-ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
                    'sec-ch-ua-full-version-list': '"Google Chrome";v="119.0.6045.105", "Chromium";v="119.0.6045.105", "Not?A_Brand";v="24.0.0.0"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-model': '""',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-ch-ua-platform-version': '"15.0.0"',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-site': 'same-origin',
                    'sec-fetch-user': '?1',
                    'upgrade-insecure-requests': '1',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                }).text
            fb_dtsg = re.findall(r'"f":"([^"]*)","l', profile)[0]
            jazoest = re.findall(r'jazoest=([^"]*)","e', profile)[0]
            lsd = re.search('LSD",,{"token":"(.+?)"', profile.replace('[]', '')).group(1)
            haste_session = re.findall(r'haste_session":"([^"]*)"', profile)[0]
            hsi = re.findall(r'parent_lid":"([^"]*)"', profile)[0]
            rev = re.findall(r'"rev":([^"]*)},"rsrcMap', profile)[0]
            spin_t = re.findall(r'__spin_t":([^"]*),"vip"', profile)[0]

            profile_cover = self.session.post(
                'https://www.facebook.com/profile/cover/comet_upload/', params={
                    'profile_id': self.id_account,
                    'av': self.id_account,
                    '__user': self.id_account,
                    '__a': '1',
                    '__hs': haste_session,
                    'dpr': '1.5',
                    '__ccg': 'EXCELLENT',
                    '__rev': str(rev),
                    '__hsi': hsi,
                    'fb_dtsg': fb_dtsg,
                    'jazoest': jazoest,
                    'lsd': lsd,
                    '__spin_r': str(rev),
                    '__spin_b': 'trunk',
                    '__spin_t': spin_t,
                }, files={
                    'filename': (IMG_FILE, open(IMG_FILE, 'rb'), 'multipart/form-data'),
                }, headers={
                    'authority': 'www.facebook.com',
                    'accept': '*/*',
                    'cache-control': 'no-cache',
                    'origin': 'https://www.facebook.com',
                    'pragma': 'no-cache',
                    'referer': f'https://www.facebook.com/profile.php?id={self.id_account}',
                    'sec-ch-prefers-color-scheme': 'light',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                    'x-fb-lsd': lsd,
                }, timeout=10
            ).text
            cover_id = re.findall(r'fbid":"([^"]*)"', profile_cover)[0]
            self.session.post(
                'https://www.facebook.com/api/graphql/', data={
                    'av': self.id_account,
                    '__user': self.id_account,
                    '__a': '1',
                    '__hs': haste_session,
                    'dpr': '1.5',
                    '__ccg': 'EXCELLENT',
                    '__rev': str(rev),
                    '__hsi': hsi,
                    'fb_dtsg': fb_dtsg,
                    'jazoest': jazoest,
                    'lsd': lsd,
                    '__spin_r': str(rev),
                    '__spin_b': 'trunk',
                    '__spin_t': spin_t,
                    'fb_api_caller_class': 'RelayModern',
                    'fb_api_req_friendly_name': 'ProfileCometCoverPhotoUpdateMutation',
                    'variables': '{"input":{"attribution_id_v2":"ProfileCometTimelineListViewRoot.react,comet.profile.timeline.list,via_cold_start,1689344395985,291664,190055527696468,","cover_photo_id":"' + cover_id + '","focus":{"x":0.5,"y":0.4907216494845356},"target_user_id":"' + self.id_account + '","actor_id":"' + self.id_account + '","client_mutation_id":"1"},"scale":1,"contextualProfileContext":null}',
                    'server_timestamps': 'true',
                    'doc_id': '6099517113440760',
                }, headers={
                    'authority': 'www.facebook.com',
                    'accept': '*/*',
                    'cache-control': 'no-cache',
                    'content-type': 'application/x-www-form-urlencoded',
                    'origin': 'https://www.facebook.com',
                    'pragma': 'no-cache',
                    'referer': f'https://www.facebook.com/profile.php?id={self.id_account}',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                    'x-fb-friendly-name': 'ProfileCometCoverPhotoUpdateMutation',
                    'x-fb-lsd': lsd,
                }, timeout=30)
            return True
        except(Exception, ):
            return False

    def add_avatar(self) -> bool:
        try:
            list_os = random.choice(os.listdir('MALE'))

            IMG_FILE = f'MALE/{list_os}'

            profile = self.session.get(
                "https://www.facebook.com/profile.php", params={
                    'id': self.id_account,
                }, headers={
                    'authority': 'www.facebook.com',
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'accept-language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
                    'cache-control': 'max-age=0',
                    'dpr': '1.25',
                    'referer': 'https://www.facebook.com/',
                    'sec-ch-prefers-color-scheme': 'dark',
                    'sec-ch-ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
                    'sec-ch-ua-full-version-list': '"Google Chrome";v="119.0.6045.105", "Chromium";v="119.0.6045.105", "Not?A_Brand";v="24.0.0.0"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-model': '""',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-ch-ua-platform-version': '"15.0.0"',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-site': 'same-origin',
                    'sec-fetch-user': '?1',
                    'upgrade-insecure-requests': '1',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                }).text
            fb_dtsg = re.findall(r'"f":"([^"]*)","l', profile)[0]
            jazoest = re.findall(r'jazoest=([^"]*)","e', profile)[0]
            lsd = re.search('LSD",,{"token":"(.+?)"', profile.replace('[]', '')).group(1)
            haste_session = re.findall(r'haste_session":"([^"]*)"', profile)[0]
            hsi = re.findall(r'parent_lid":"([^"]*)"', profile)[0]
            rev = re.findall(r'"rev":([^"]*)},"rsrcMap', profile)[0]
            spin_t = re.findall(r'__spin_t":([^"]*),"vip"', profile)[0]

            profile_picture = self.session.post(
                'https://www.facebook.com/profile/picture/upload/', params={
                    'profile_id': self.id_account,
                    'av': self.id_account,
                    '__user': self.id_account,
                    '__a': '1',
                    '__hs': haste_session,
                    'dpr': '1.5',
                    '__ccg': 'EXCELLENT',
                    '__rev': str(rev),
                    '__hsi': hsi,
                    'fb_dtsg': fb_dtsg,
                    'jazoest': jazoest,
                    'lsd': lsd,
                    '__spin_r': str(rev),
                    '__spin_b': 'trunk',
                    '__spin_t': spin_t,
                }, files={
                    'filename': (IMG_FILE, open(IMG_FILE, 'rb'), 'multipart/form-data'),
                }, headers={
                    'authority': 'www.facebook.com',
                    'accept': '*/*',
                    'cache-control': 'no-cache',
                    'origin': 'https://www.facebook.com',
                    'pragma': 'no-cache',
                    'referer': f'https://www.facebook.com/profile.php?id={self.id_account}',
                    'sec-ch-prefers-color-scheme': 'light',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                    'x-fb-lsd': lsd,
                }, timeout=10).text
            picture_id = re.findall(r'fbid":"([^"]*)"', profile_picture)[0]
            self.session.post(
                'https://www.facebook.com/api/graphql/', headers={
                    'authority': 'www.facebook.com',
                    'accept': '*/*',
                    'cache-control': 'no-cache',
                    'content-type': 'application/x-www-form-urlencoded',
                    'origin': 'https://www.facebook.com',
                    'pragma': 'no-cache',
                    'referer': f'https://www.facebook.com/profile.php?id={self.id_account}',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                    'x-fb-friendly-name': 'ProfileCometProfilePictureSetMutation',
                    'x-fb-lsd': lsd,
                }, data={
                    'av': self.id_account,
                    '__user': self.id_account,
                    '__a': '1',
                    '__hs': haste_session,
                    'dpr': '1.5',
                    '__ccg': 'EXCELLENT',
                    '__rev': str(rev),
                    '__hsi': hsi,
                    'fb_dtsg': fb_dtsg,
                    'jazoest': jazoest,
                    'lsd': lsd,
                    '__spin_r': str(rev),
                    '__spin_b': 'trunk',
                    '__spin_t': spin_t,
                    'fb_api_caller_class': 'RelayModern',
                    'fb_api_req_friendly_name': 'ProfileCometProfilePictureSetMutation',
                    'variables': '{"input":{"attribution_id_v2":"ProfileCometTimelineListViewRoot.react,comet.profile.timeline.list,tap_bookmark,1697874937307,293436,' + self.id_account + ',","caption":"","existing_photo_id":"' + picture_id + '","expiration_time":null,"profile_id":"' + self.id_account + '","profile_pic_method":"EXISTING","profile_pic_source":"TIMELINE","scaled_crop_rect":{"height":0.99999,"width":0.5625,"x":0.21875,"y":0},"skip_cropping":true,"actor_id":"' + self.id_account + '","client_mutation_id":"2"},"isPage":false,"isProfile":true,"sectionToken":"UNKNOWN","collectionToken":"UNKNOWN","scale":1.5}',
                    'server_timestamps': 'true',
                    'doc_id': '6695984043854097',
                }, timeout=30)
            return True
        except(Exception, ):
            return False

    def get_data_fb(self):
        try:
            response: str = self.session.get(
                'https://www.facebook.com/confirmemail.php', params={
                    'next': 'https://www.facebook.com/',
                }, headers={
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'accept-language': 'vi,en-US;q=0.9,en;q=0.8',
                    'cache-control': 'no-cache',
                    'pragma': 'no-cache',
                    'priority': 'u=0, i',
                    'referer': 'https://www.facebook.com/',
                    'sec-ch-ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-site': 'same-origin',
                    'sec-fetch-user': '?1',
                    'upgrade-insecure-requests': '1',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                }).text

            fb_dtsg: str = re.findall(r'name="fb_dtsg" value="([^"]*)"', response)[0]
            jazoest: str = re.findall(r'name="jazoest" value="([^"]*)"', response)[0]
            lsd: str = re.findall(r'"LSD",,{"token":"([^"]*)"', response.replace('[', '').replace(']', ''))[0]
            return fb_dtsg, jazoest, lsd
        except(IndexError, ):
            return "NONE"

    def add_mail_fb(self, mail_new: str, data_fb: tuple) -> None:
        _ = self.session.post(
            'https://www.facebook.com/add_contactpoint/dialog/submit/', headers={
                'accept': '*/*',
                'accept-language': 'vi,en-US;q=0.9,en;q=0.8',
                'cache-control': 'no-cache',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://www.facebook.com',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://www.facebook.com/confirmemail.php?next=https%3A%2F%2Fwww.facebook.com%2F',
                'sec-ch-ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'x-fb-lsd': data_fb[2],
            }, data={
                'jazoest': data_fb[1],
                'fb_dtsg': data_fb[0],
                'next': 'https://www.facebook.com',
                'contactpoint': mail_new,
                '__user': self.id_account,
                '__a': '1',
                '__req': '5',
                'dpr': '1',
                '__ccg': 'GOOD',
                '__csr': '',
                'lsd': data_fb[2],
                '__spin_b': 'trunk',
            })

    def send_code_fb(self, mail_new: str, data_fb: tuple) -> None:
        _ = self.session.post(
            'https://www.facebook.com/confirm/resend_code/', params={
                'cp': mail_new,
            }, headers={
                'accept': '*/*',
                'accept-language': 'vi,en-US;q=0.9,en;q=0.8',
                'cache-control': 'no-cache',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://www.facebook.com',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://www.facebook.com/confirmemail.php?next=https%3A%2F%2Fwww.facebook.com%2F',
                'sec-ch-prefers-color-scheme': 'dark',
                'sec-ch-ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
                'sec-ch-ua-full-version-list': '"Google Chrome";v="125.0.6422.113", "Chromium";v="125.0.6422.113", "Not.A/Brand";v="24.0.0.0"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-model': '""',
                'sec-ch-ua-platform': '"Windows"',
                'sec-ch-ua-platform-version': '"15.0.0"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'x-fb-lsd': data_fb[2],
            }, data={
                'cp': mail_new,
                '__asyncDialog': '2',
                '__user': self.id_account,
                '__a': '1',
                '__req': '4',
                'dpr': '1',
                '__ccg': 'GOOD',
                '__rev': '1013918766',
                '__csr': '',
                'fb_dtsg': data_fb[0],
                'jazoest': data_fb[1],
                'lsd': data_fb[2],
                '__spin_r': '1013918766',
                '__spin_b': 'trunk',
                '__spin_t': '1717354263',
            })

    def veri_mail(self, mail_new: str, code_mail: str, data_fb: tuple) -> None:
        _ = self.session.post(
            'https://www.facebook.com/confirm_code/dialog/submit/', headers={
                'accept': '*/*',
                'accept-language': 'vi,en-US;q=0.9,en;q=0.8',
                'cache-control': 'no-cache',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://www.facebook.com',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://www.facebook.com/confirmemail.php?next=https%3A%2F%2Fwww.facebook.com%2F',
                'sec-ch-ua-mobile': '?0',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'x-fb-lsd': data_fb[2],
            }, data={
                'jazoest': data_fb[1],
                'fb_dtsg': data_fb[0],
                'code': code_mail,
                'source_verified': '',
                'confirm': '0',
                '__user': self.id_account,
                '__a': '1',
                '__req': '4',
                '__ccg': 'GOOD',
                '__csr': '',
                'lsd': data_fb[2],
                '__spin_b': 'trunk',
            }, params={
                'next': 'https://www.facebook.com/?sk=welcome',
                'cp': mail_new,
                'from_cliff': '0',
                'conf_surface': '',
                'event_location': '',
            })

    @staticmethod
    def get_code_mail(cookies: dict[str]) -> str:
        check_code = 0
        loop_check = False
        while not loop_check:
            time.sleep(8)
            r = requests.get(
                'https://10minutemail.net/address.api.php', headers={
                    'authority': '10minutemail.net',
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'accept-language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
                    'cache-control': 'no-cache',
                    'dnt': '1',
                    'pragma': 'no-cache',
                    'sec-ch-ua': '"Chromium";v="117", "Not;A=Brand";v="8"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-site': 'none',
                    'sec-fetch-user': '?1',
                    'upgrade-insecure-requests': '1',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
                }, cookies=cookies
            ).json()["mail_list"]
            check_code += 1
            if check_code > 4:
                loop_check = True
                return "NONE"
            for _ in r:
                subject = _['subject']
                if "Facebook" in str(subject):
                    match = re.search(r'\b(\d+)\b', str(subject)).group(1)
                    loop_check = True
                    return match

    @staticmethod
    def get_new_mail():
        headers = {
            'authority': '10minutemail.net',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
            'cache-control': 'no-cache',
            'dnt': '1',
            'pragma': 'no-cache',
            'sec-ch-ua': '"Chromium";v="117", "Not;A=Brand";v="8"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
        }

        response = requests.get('https://10minutemail.net/address.api.php', headers=headers)
        mail_get_mail = response.json()["mail_get_mail"]
        print(mail_get_mail)
        cookies_mail = response.cookies.get_dict()
        return mail_get_mail, cookies_mail

    def run(self):
        data_fb = self.get_data_fb()
        if data_fb != "NONE":
            mail_10 = self.get_new_mail()
            self.add_mail_fb(mail_10[0], data_fb)
            self.send_code_fb(mail_10[0], data_fb)
            code_mail = self.get_code_mail(mail_10[1])
            if code_mail != "NONE":
                self.veri_mail(mail_10[0], code_mail, data_fb)
                if self.add_avatar() is True:
                    if self.add_cover_image() is True:
                        print(f"[+] {self.id_account} XÁC MINH THÀNH CÔNG (COVER : TRUE) & (AVATAR : TRUE)\n")
                        upload_data(self.id_account)
                    else:
                        print(f"[-] {self.id_account} XÁC MINH THẤT BẠI (COVER : FALSE ) & (AVATAR : FALSE)\n")
                else:
                    print(f"\n[-] {self.id_account} XÁC MINH THẤT BẠI (COVER : FALSE) & (AVATAR : FALSE)\n")
            else:
                print(f"\n[!] {self.id_account} KHÔNG NHẬN CODE (COVER : NONE) & (AVATAR : NONE)\n")
        else:
            print(f"\n[-] {self.id_account} XÁC MINH THẤT BẠI (COVER : FALSE) & (AVATAR : FALSE)\n")


count = 0
files = open(input("NHẬP TÊN FILES NOVERY : ")).read().strip().split("\n")

for _ in files:
    if count == 6:
        Vnpt().run()
        if Vnpt().check_connection() is True:
            print("\nĐỔI IP THÀNH CÔNG")
            count -= count
            time.sleep(10)
    else:
        VeriMail(_).run()
        count += 1
