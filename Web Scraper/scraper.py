import time
from bs4 import BeautifulSoup
from selenium import webdriver    

class Scraper:
    def __init__(self, urls):
        self.urls = urls
    
    def addUrl(self, url):
        if not (url in self.urls):
            self.urls.append(url)
    
    def removeUrl(self, url):
        if url in self.urls:
            self.urls.remove(url)

    def getHTMLSoup(self, url):
        if not (url in self.urls):
            return None
        
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        browser = webdriver.Chrome(options=options)
        browser.get(url)
        time.sleep(10)
        html = browser.page_source
        soup = BeautifulSoup(html, features="html.parser")
        browser.quit()

        return soup


urls = ['https://manga4life.com/']
myScraper = Scraper(urls)

manga4life = myScraper.getHTMLSoup(urls[0])
print(manga4life.get_text())

