import requests
from bs4 import BeautifulSoup

query = "accenture"
url = f"https://github.com/search?q={query}"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
}  # Add a user-agent header to mimic a web browser

response = requests.get(url, headers=headers)
soup = BeautifulSoup(response.content, "html.parser")

# Find the search results containers
search_results = soup.find_all("li", class_="repo-list-item")

# Extract the relevant information from each search result
for result in search_results:
    title = result.find("h3").text  # Extract the repository name
    description = result.find("p", class_="repo-list-description").text  # Extract the repository description
    language = result.find("span", itemprop="programmingLanguage").text  # Extract the programming language
    stars = result.find("a", class_="muted-link mr-3").text  # Extract the number of stars
    repo_url = "https://github.com" + result.find("a", itemprop="name codeRepository")["href"]  # Extract the repository URL

    print(f"Repository: {title}")
    print(f"Description: {description}")
    print(f"Language: {language}")
    print(f"Stars: {stars}")
    print(f"URL: {repo_url}")
    print()
