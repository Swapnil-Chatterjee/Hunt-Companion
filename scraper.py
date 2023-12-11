import requests
from bs4 import BeautifulSoup

query = 'q="malware"&lr=&safe=images&hl=en-IN&tbs=qdr:d&sxsrf=APwXEdcqLdWJLkwhhR4hZvNkSzjbLbqWOA:1684262450011&ei=Ms5jZMQsg9Xj4Q_i1434Ag&start=10&sa=N&ved=2ahUKEwjEjarIvvr-AhWD6jgGHeJrAy8Q8NMDegQIBBAW&biw=1536&bih=714&dpr=1.25'
url = f"https://www.google.com/search?{query}"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
}  # Add a user-agent header to mimic a web browser

response = requests.get(url, headers=headers)
soup = BeautifulSoup(response.content, "html.parser")
# print(soup)
# Find the search results containers
search_results = soup.find_all("div", class_="g")
# Extract the relevant information from each search result
for result in search_results:
    title = result.find("h3").text  # Extract the title
    link = result.find("a")["href"]  # Extract the URL
   # print(result)
    print(f"Title: {title}")
    print(f"Link: {link}")