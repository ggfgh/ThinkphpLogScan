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

requests.packages.urllib3.disable_warnings()
console = Console()
arg = ArgumentParser(description='thinkphp log scanner')
arg.add_argument('-u', '--url', help='The target url', dest='target')
arg.add_argument('-sY', '--start-year', help='The year the scan began. Example: 22.', dest='syear', type=int,default=22)
arg.add_argument('-eY', '--end-year', help='The year the scan end. Example: 23', dest='eyear', type=int,default=23)
arg.add_argument('-t', '--thread', help='The number of threads.Default value is 10', dest='thread_count', type=int, default=10)
arg.add_argument('-f', '--file', help='The target list file.', dest='scan_file', default='urls.txt')
arg.add_argument('--proxy',help='The setting of proxy. Example: http://127.0.0.1:31120',dest='proxy',default='')
arg.add_argument('-o', '--outfile', help='The file location where the results are saved.Default value is vuln.txt', dest='outfile', default='vuln.txt')
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
        :return: None
        '''
        mouth = str(random.randint(1, 12))
        day = str(random.randint(1,31))
        log_format = f"{self.syear}_{mouth.rjust(2, '0')}_{day.rjust(2, '0')}.log"
        verify_url_1 = f"{target}{self.thinkphp_3_1_log_path}{log_format}"
        verify_url_2 = f"{target}{self.thinkphp_3_2_log_path}{log_format}"
        try:
            console.log(f"[green][INFO] Start verify:{target} request url:{verify_url_1}.")
            if self.proxies['http']:
                console.log(f"[green][INFO] Http proxy:{self.proxies['http']} Https proxy:{self.proxies['https']}")
            res_1 = requests.get(verify_url_1,headers=self.headers,allow_redirects= False,verify=False,timeout=5,proxies=self.proxies)
            console.log(f"[green][INFO] Start verify:{target} request url:{verify_url_2}")
            res_2 = requests.get(verify_url_2, headers=self.headers,allow_redirects= False,verify=False, timeout=5, proxies=self.proxies)

            if (res_1.status_code == 200 and "INFO" in res_1.text) or res_1.headers['Content-Type'] == "application/octet-stream":
                console.log(f"[green][SUCCESS]  Found log url :) {verify_url_1}")
                with open(option.outfile,'a') as f:
                    f.write(verify_url_1 + '\n')

            elif (res_2.status_code == 200 and "INFO" in res_2.text) or res_2.headers['Content-Type'] == "application/octet-stream":
                console.log(f"[green][SUCCESS] Found log url :) {verify_url_2}")
                with open(option.outfile, 'a') as f:
                    f.write(verify_url_2 + '\n')
        except Exception as e:
            console.log(f"Error in verify {target}, error info: {e}")

    def run(self):
        '''
        overwrite run function of Tread
        '''
        while not self._que.empty():
            target = self._que.get()
            try:
                self._verify(target)
            except Exception as e:
                console.log(f"[red] Error: {e}")
def main():
    threads = []
    thread_count = option.thread_count
    que = Queue()
    if option.scan_file:
        with open(option.scan_file,'r') as f:
            for url in f.readlines():
                url = url.replace('\n','')
                que.put(url)
        for t in range(thread_count):
            threads.append(ThinkphpLogScan(que))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    else:
        ThinkphpLogScan()._verify(option.target)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
         console.log(f"[yellow] Error: {e} Use --help to see usage")



    
    