import logging
import os
import random
import re
import sys
from dataclasses import dataclass
from typing import List

import requests as requests


@dataclass
class Proxy:
    ip: str
    port: str
    protocol: str
    login: str = None
    password: str = None

    def get_formatted(self):
        if not self.login:
            return f"{self.protocol}://{self.ip}:{self.port}"
        return f"{self.protocol}://{self.login}:{self.password}@{self.ip}:{self.port}"

    def __str__(self):
        data = f"{self.ip}:{self.port}#{self.protocol}"
        if self.login and self.password:
            data = f"{data} {self.login}:{self.password}"
        return data


def get_log_level(verbose: int):
    levels = [
        logging.ERROR,
        logging.WARNING,
        logging.INFO,
        logging.DEBUG,
    ]
    return levels[verbose] if verbose < len(levels) else levels[-1]


def config_logger(verbose: bool, log_to_stdout: bool):
    kwargs = {}
    if not log_to_stdout:
        kwargs["filename"] = os.path.abspath(sys.argv[0]).split(".")[0] + ".log"
    logging.basicConfig(
        level=get_log_level(verbose),
        format="[%(asctime)s] %(levelname)s:  %(message)s",
        datefmt="%d-%m-%Y %I:%M:%S",
        **kwargs,
    )


def set_limits():
    try:
        import resource
    except ImportError:
        logging.error(
            "Your platform does not supports setting limits for open files count"
        )
        logging.error(
            'If you see a lot of errors like "Too meny open files" pls check README.md'
        )
        return
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    limit = hard
    while limit > soft:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (limit, hard))
            logging.info("New limit of open files is %s", limit)
            return
        except:
            limit -= ((hard - soft) / 100) or 1

    logging.error(
        'Can not change limit of open files, if you get a message "too many open files"'
    )
    logging.error("Current limit is: %s", soft)
    logging.error("In linux/unix/mac you should run")
    logging.error("\t$ ulimit -n 100000")
    logging.error("In WSL:")
    logging.error("\t$ mylimit=100000")
    logging.error("\t$ sudo prlimit --nofile=$mylimit --pid $$; ulimit -n $mylimit")


def parse_proxy(line: str, protocol: str, regexp: re.Pattern) -> Proxy:
    """line format be default is 'ip:port[#protocol] [login]:[password]'"""
    match = regexp.match(line.strip())
    if match:
        proxy_data = match.groupdict()
        if protocol and not proxy_data.get("protocol"):
            proxy_data["protocol"] = protocol
        proxy = Proxy(**proxy_data)
        return proxy
    raise ValueError(line)


def get_proxy_regex(custom_format: str) -> re.Pattern:
    if custom_format:
        escaped = re.escape(custom_format)
        for name in ("ip", "protocol", "login", "password"):
            escaped = escaped.replace(f"\\{{{name}\\}}", rf"(?P<{name}>[^\s]+)")
        escaped = escaped.replace("\\{port\\}", r"(?P<port>\d+)")
        escaped = escaped.replace(r"\ ", r"\s+")
        return re.compile(escaped)
    return re.compile(
        r"(?P<ip>[\w\.]+):(?P<port>\d+)(#(?P<protocol>\w+))?(\s+(?P<login>\w+):(?P<password>\w+))?"
    )


def load_proxies(
    proxy_file: str,
    proxy_url: str,
    protocol: str = None,
    shuffle: bool = None,
    custom_format: str = None,
) -> List[Proxy]:
    if proxy_url:
        logging.info("Loading proxy list from %s..", proxy_url)
        proxy_data = requests.get(proxy_url).text
    elif proxy_file:
        logging.info("Loading proxy list from %s..", proxy_file)
        proxy_data = open(proxy_file).read()
    else:
        proxy_data = None
    if proxy_data:
        proxies = []
        proxy_regex = get_proxy_regex(custom_format)
        for line in proxy_data.splitlines():
            if line.strip():
                try:
                    proxies.append(parse_proxy(line, protocol, proxy_regex))
                except ValueError as error:
                    logging.error('Wrong proxy line format "%s"', error)
        logging.info("Loaded %s proxies", len(proxies))
        if shuffle:
            logging.debug("Shuffling proxies list")
            random.shuffle(proxies)
        return proxies
    return None
