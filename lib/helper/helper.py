import ast
import json

import requests
##### Warna ####### 
N = '\033[0m'
W = '\033[1;37m' 
B = '\033[1;34m' 
M = '\033[1;35m' 
R = '\033[1;31m' 
G = '\033[1;32m' 
Y = '\033[1;33m' 
C = '\033[1;36m' 
##### Styling ######
underline = "\033[4m"
##### Default ######
agent = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'} 
line = "—————————————————"
#####################
def _parse_mapping(value, field_name):
	if value is None:
		return None

	if isinstance(value, dict):
		return value

	if not isinstance(value, str):
		raise ValueError(f"Invalid {field_name} type: {type(value).__name__}")

	raw = value.strip()
	if not raw:
		return None

	try:
		parsed = json.loads(raw)
	except json.JSONDecodeError:
		try:
			parsed = ast.literal_eval(raw)
		except Exception as exc:
			raise ValueError(f"Invalid {field_name} format: {exc}") from exc

	if not isinstance(parsed, dict):
		raise ValueError(f"Invalid {field_name} format: expected key-value mapping")

	return parsed


def session(proxies, headers, cookie):
	r = requests.Session()

	if headers is not None:
		if isinstance(headers, str):
			headers = {"User-Agent": headers}
		r.headers.update(headers)

	parsed_proxy = _parse_mapping(proxies, "proxy")
	if parsed_proxy:
		r.proxies = parsed_proxy

	parsed_cookie = _parse_mapping(cookie, "cookie")
	if parsed_cookie:
		r.cookies.update(parsed_cookie)

	return r

logo=G+r"""██╗  ██╗███████╗███████╗███████╗███╗   ██╗███████╗███████╗
╚██╗██╔╝██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝
 ╚███╔╝ ███████╗███████╗█████╗  ██╔██╗ ██║███████╗█████╗   %s
 ██╔██╗ ╚════██║╚════██║██╔══╝  ██║╚██╗██║╚════██║██╔══╝   %s
██╔╝ ██╗███████║███████║███████╗██║ ╚████║███████║███████╗
╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝
<<<<<<< STARTING >>>>>>>
"""%(R+"{v1.0}"+G,underline+C+"https://github.com/SatriaDivo/XSSense"+N+G)
