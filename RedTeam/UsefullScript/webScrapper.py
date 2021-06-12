import requests
from bs4 import BeautifulSoup


URL = 'https://portswigger.net/web-security/all-labs'
page = requests.get(URL)

soup = BeautifulSoup(page.content, 'html.parser')


## Example working on well formed website
# job_elems = soup.find_all('div', class_='su-spoiler su-spoiler-style-default su-spoiler-icon-plus su-spoiler-closed')

# cnt = 0
# with open("C:\\Users\\Hato0\\Documents\\Always Be Better\\RedTeam\\General Knowledge\\web.md",'w', encoding='utf-8') as file:
# 	file.write(f'## Data extracted from {URL}\n')
# 	for elem in job_elems:
# 		question = elem.find('div', class_='su-spoiler-title')
# 		answer = elem.find('div', class_='su-spoiler-content su-u-clearfix su-u-trim')
# 		file.write("#### "+ str(question.text))
# 		file.write(str(answer.text)+"\n")


## Example working on shitty website
with open("C:\\Users\\Hato0\\Documents\\Always Be Better\\RedTeam\\General Knowledge\\web.md",'w', encoding='utf-8') as file:
	file.write('## Web Knowledge \n')
	for section in soup.findAll('h2'):
		file.write("#### " + section.text + "\n")
		toCheck = section.find_next_sibling()
		while 'div' in toCheck.name:
			file.write("- " + toCheck.findChildren('a')[0].text + "\n")
			toCheck = toCheck.find_next_sibling()