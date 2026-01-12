import re
from urllib.parse import quote
import execjs
import requests

from loguru import logger
from pyquery import PyQuery as pq
import tools


class LOGIN:
    def __init__(self):
        self.session = requests.Session()
        self.user_agent = "MomoChat/9.17.8_64 Android/13405 (Pixel 4 XL; Android 13; Gapps 0; zh_CN; 7; Google)"

        self.session.headers = {
            "X-Span-Id": "0",
            "Accept-Language": "zh-CN",
            "X-Trace-Id": tools.getUUID(),
            "Host": "api.immomo.com",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": self.user_agent

        }
        self.cookies = {
            "SESSIONID": tools.getUUID() + "_G"
        }

    # 发送验证码
    def sendMsg(self, phone):
        url = "https://api.immomo.com/api/safe/verifycode/send"
        params = {
            "fu": tools.get32UUID()
        }
        data = {
            "mmuid": "",
            "countryCode": "+86",
            "phonenumber": phone,
            "_iid": tools.get32UUID(),
            "voiceSms": "0",
            "_net_": "wifi",
            "_uid_": tools.get32UUID()
        }
        response = self.session.post(url, params=params, data=data, cookies=self.cookies)
        logger.info(f"验证码发送请求结果  :{response.text}")
        if response.status_code == 200:
            logger.info(f"短信发送成功")

    # 登陆
    def login(self, phone, smsCode):
        headers = {
            "X-ACT": "br",
            "X-LV": "1",
            "X-KV": "0e96c5f2",  # 设备信息
            "X-SIGN": "BSpvZTq1vKkCjaqJzL/w2m3eWqs=",
        }
        return ""


if __name__ == '__main__':
    phone = '17262206238'
    login = LOGIN()
    login.sendMsg(phone)
    smsCode = input('请输入验证码:')
