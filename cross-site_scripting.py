import os
import requests
from urllib.parse import urljoin
from urllib.parse import urlparse

# dict, thông tin về plugin
options = {
    "vuln_id": "",
    "plugin_id": ""
}

# thông tin của tác vụ quét
new_task = {
    "id": 1583,
    "target": 319,
    "task": 495,
    "module": 5,
    # Ten cac object
    "scan_objects": [
        ""
    ],
    "configuration": {
        "speed": 4,
        "scan_config": "standard",
        "scan_custom_configs": None,
        "exclude_url": [
            ""
        ],
        "crawler_manual_file": None,
        "custom_headers": {},
        "custom_cookies": ["login=test%2Ftest"],
        "user_agent": None,
        "using_vpn": False,
        "using_proxy": False
    },
    "technologies": [
        {
            "technology": "Web Servers",
            "app": "NGINX",
            "version": "1.19.0"
        },
        {
            "technology": "Programming Languages",
            "app": "PHP",
            "version": "5.6.40"
        }
    ],
    "url_info": [
        {
            "url": "http://testphp.vulnweb.com/search.php",
            #"url": "http://testphp.vulnweb.com/listproducts.php",
            #"url": "http://testphp.vulnweb.com/comment.php",
            #"url": "http://testphp.vulnweb.com/guestbook.php",
            #"url": "http://testphp.vulnweb.com/hpp/params.php",
            #"url": "http://testphp.vulnweb.com/secured/newuser.php",
            #"url": "http://testphp.vulnweb.com/userinfo.php",
            #"method": "POST",
            "method": "GET",
            "params": {
               #"test": ["query"],
               #"cat": ["1"],  # listProduct
               #"artist": ["1"],  # listProduct
               #"p": ["1"],  # params.php
               "pp": ["1"]  # params.php
            },
            "request_header": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
                "Connection": "keep-alive",
                "Content-Length": "114",
                "Host": "testphp.vulnweb.com",
                "Origin": "http://testphp.vulnweb.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
            },
            #"request_body": "searchFor=s&goButton=go", #search.php
            "request_body": "",  #request body GET
            #"request_body": "Submit=Submit&comment=dsa&name=oki&phpaction=asd",  # comment.php
            #"request_body": "name=anonymous+user&text=1&submit=add+message", # guestbook.php
            #"request_body": "uuname=aa&upass=admin&upass2=admin&urname=3339999&uemail=dmin@admin.com&uphone=9999997777&uaddress=hanoi&signup=signup&ucc=abc", #newsuser.php
            #"request_body": "urname=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&ucc=1&uemail=sdjhhs&uphone=23477&uaddress=sdcds&update=update",  # userinfo.php
            "content_key": "495-1497:883922b67bc970cab5fb8d9c09051582",
            "response_header": {
                 "Server": "nginx/1.19.0",
                 "Date": "Wed, 31 Aug 2022 09:20:21 GMT",
                 "Content-Type": "text/html; charset=UTF-8",
                 "transfer-Encoding": "chunked",
                 "Connection": "keep-alive",
                 "X-Powered-By": "PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1",
                 "Content-Length": "587",
                 "Content-Encoding": "gzip"
            },
            "is_login": False,
            "is_first_url": False,
            "http_version": 1,
            "status": 200,
            "security_level": "safe"
        }
    ],
    "status": "requested",
    "progress": 0,
    "additional_info": [],
    "agent_uuid": "d869d1d5-01ef-4a9d-86ea-916f0adab2a1"
}

proxy_config = {"http": "http://user:pass@ip_proxy:port"}

content = {
    "url": "http://testphp.vulnweb.com",
    "request": {
        "method": "POST",
        "post_data": None,
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        },
        "resourceType": "document",
        "click": []
    },
    "response": {
        "status": 200,
        "content": '',
        "headers": {
            "server": "nginx/1.19.0",
            "date": "Wed, 31 Aug 2022 07:59:53 GMT",
            "content-type": "text/html; charset=UTF-8",
            "transfer-encoding": "chunked",
            "connection": "keep-alive",
            "x-powered-by": "PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1",
            "content-encoding": "gzip"
        },
        "resourceType": "document"
    }
}


def cross_site_scripting(new_task, proxy_config, content):
    try:
        url = new_task["url_info"][0]["url"]
        params = new_task["url_info"][0]["params"]  # dictionary
        method = new_task["url_info"][0]["method"]
        header = content["request"]["headers"]
        request_body = new_task["url_info"][0]["request_body"]
        status_code = content["response"]["status"]

        # Create payload list from .txt . file
        payload_list = []
        try:
            with open(os.path.join(os.path.dirname(__file__), 'payloads.txt'), encoding="utf8") as f:
                payload_list = [line.rstrip() for line in f]
        except Exception as e:
            print('[+] Error open \'payloads.txt\' file', e)

        lst_Form = []
        data_lst = request_body.split('&')  # ['searchFor=s', 'goButton=go']
        data_dict_lst = {}  # dictionary data_lst

        for dat_item in data_lst:  # create dictionary data from list data_lst
            data_dict_lst[dat_item[0:dat_item.find('=')]] = dat_item[dat_item.find('=') + 1:len(dat_item)]  # key=value

        # Concatenate url string and param to form target url
        arr_param_value = []  # create an array url (key = param, value = url with param = payload)
        str = '?'
        parsed = urlparse(url)
        path_url = parsed.path + str  # /search.php
        for item in params:
            param_add_url = item + '=' + params[item][0] + '&'  # key=value
            path_url += param_add_url
        target_url = urljoin(url, path_url.rstrip('&'))  # http://testphp.vulnweb.com/search.php?test=query
        arr_param_value.append(target_url)

        is_vulnerable = False
        for payload in payload_list:
            for item in params:  # dictionary of url params
                old = item + '=' + params[item][0]  # param=old_value (test=query)
                new = item + '=' + payload  # param=payload  (test= <script>alert('1')</script>)
                arr_param_value.append(target_url.replace(old, new))  # example: ['http://testphp.vulnweb.com/search.php?test=<script>alert('1')</script>']
            for url_in_list in arr_param_value:
                for data in data_lst:
                    key = data[0:data.find('=')]  # example: searchFor
                    data_temp = data_dict_lst  # create a temporary dictionary of request body param
                    temp_val = data_temp[key]  # save the value of body param key in temporary variable temp_val
                    data_temp[key] = payload  # assign payload of payload_list to body param value
                    # {'searchFor': "<script>alert('1')</script>", 'goButton': "<script>alert('1')</script>"}
                    content_response = submit_request(url_in_list, header, params, data_temp,
                                                      method).text  # lấy response content của url
                    data_temp[key] = temp_val  # assign the value back to param after send request with payloads
                    if payload in content_response and status_code != 404:  # check payload is in content
                        is_vulnerable = True
                        print(f"[+] XSS Detected on {target_url} with key = {key} and value = {payload}")
                        print(f"[*] Form Data: {request_body}")
                        print(f"[*] Result:")
                        result = dict()
                        result["affects"] = new_task["url_info"][0]["url"]
                        result["request"] = target_url
                        result["param"] = params
                        result["attackDetail"] = 'Tìm thấy lỗ hổng XSS vì dữ liệu trả về có đoạn <script> nhập vào input form'
                        result["response"] = 'details: {}'.format(content_response)
                        get_result(new_task, result)
            if is_vulnerable: break
        if is_vulnerable == False:
            print(f"No XSS vulnerability detected in site")
    except:
        print("unspecified error!")


def submit_request(url, header, param, value, method):
    if method == "POST":
        return requests.post(url, headers=header,  timeout=10, data=value,  cookies=get_cookie(new_task), verify=False)
    else:
        # GET request
        return requests.get(url, headers=header, timeout=10, params=param, cookies=get_cookie(new_task), verify=False)

def get_cookie(new_task):
    jar = requests.cookies.RequestsCookieJar()
    for cookies in new_task["configuration"]["custom_cookies"]:
        for cookie in str(cookies).split(";"):
            k, v = str(cookie).split("=")
            jar.set(k, v)
    return jar



def get_result(new_task, output_result):
    output = {
        'scan': new_task['id'],
        'security_risk': options.get("vuln_id"),
        'nvt': options.get("plugin_id"),
        'object': new_task['scan_objects'],
        'port': '',
        'family': '',
        'affects': output_result['affects'],
        'param': output_result['param'],
        'attack_detail': output_result["attackDetail"],
        'request': output_result["request"],
        'output': output_result["response"]
    }
    print(output_result, new_task)

if __name__ == '__main__':
    cross_site_scripting(new_task, proxy_config, content)


