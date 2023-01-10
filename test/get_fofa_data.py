from pocsuite3.api import Fofa

def main():
    fa = Fofa()
    urls = fa.search('app="thinkphp"', resource='web',pages=1)
    print(len(urls))
    for url in urls:
        print(url)

if __name__ == "__main__":
    main()