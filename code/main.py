# coding=utf-8
import os
import time
import codecs
import feedparser

rss_urls = [
    'http://www.freebuf.com/feed', 'http://paper.seebug.org/rss/',
    'https://evi1cg.me/feed', 'http://www.91ri.org/feed'
]


def get_feeds_lastday_published(rss_url):
    """ 获取订阅内容. """
    lastday_published_news = []
    timestamp = time.time() - 86400
    time_tuple = time.localtime(timestamp)
    time_str = time.strftime("%Y-%m-%d", time_tuple)
    feeds = feedparser.parse(rss_url)
    print feeds['feed']['title'].encode('utf-8')
    for entry in feeds['entries']:
        if entry.published_parsed is not None:
            entry_time_str = time.strftime("%Y-%m-%d", entry.published_parsed)
            if entry_time_str == time_str:
                item = {'link': entry.link, 'title': entry.title}
                lastday_published_news.append(item)
    return lastday_published_news


def fetch_all_feeds():
    """ 遍历rss_url,获取所有订阅. """
    lastday_news = []
    for url in rss_urls:
        single_news = get_feeds_lastday_published(url)
        lastday_news.extend(single_news)
    return lastday_news


def write_markdown_file(news):
    """ 把订阅消息写入markdown格式的文件中. """
    if not news:
        print "No feed news in last day."
    else:
        timestamp = time.time()
        time_tuple = time.localtime(timestamp)
        current_year = time.strftime("%Y")
        file_name = time.strftime("%m-%d-daily.md", time_tuple)
        docs_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
            "docs", current_year)
        if os.path.exists(docs_path):
            md_file = codecs.open(
                os.path.join(docs_path, file_name), 'wa', 'utf-8')
            md_file.write(u"* Quick news\r\n\r\n")
            for feed_new in news:
                md_file.write("    [%s](%s)\r\n\r\n" % (feed_new['title'],
                                                        feed_new['link']))
            md_file.flush()
            md_file.close()
        else:
            os.mkdir(docs_path)


if __name__ == '__main__':
    write_markdown_file(fetch_all_feeds())
