import requests
from lib.helper.Log import *
from lib.helper.helper import *
from lib.core import *


def _resolve_rust_engine():
	try:
		import xssense_engine as rust_engine
	except Exception:
		return None

	if hasattr(rust_engine, "run_crawler"):
		return rust_engine

	nested = getattr(rust_engine, "xssense_engine", None)
	if nested is not None and hasattr(nested, "run_crawler"):
		return nested

	return None

class crawler:
	
	@classmethod
	def crawl(
		self,
		base,
		depth,
		proxy,
		headers,
		payloads,
		method,
		cookie,
		timeout=15,
		retries=1,
		output_json=None,
		reporter=None,
		detection_mode="strict",
	):
		engine = _resolve_rust_engine()
		if engine is None:
			Log.high("Crawler engine function run_crawler is unavailable in xssense_engine module")
			return

		Log.info(f"[*] Menyalakan Mesin Crawler RUST kecepatan Tinggi (Max Depth: {depth}) untuk menyedot URL...")
		
		# Mengeksekusi ekstensi Rust yang merayap semua URL dalam hitungan detik!
		urls = engine.run_crawler(base, depth)
		
		# Menghapus duplikat dan mensortir output URL
		urls = list(set(urls))
		
		Log.info(f"[+] Crawler Rust berhasil mengekstrak {len(urls)} link dari {base}! Mengoper ke modul Injector XSS...")
		
		# Melakukan pemindaian terhadap SEMUA link yang dikeruk oleh Rust secara satu persatu.
		for url in urls:
			if url.rstrip("/") == base.rstrip("/"):
				continue
			if url.startswith("https://") or url.startswith("http://"):
				# Langsung Panggil Scanner Core tanpa Process lama
				core.main(
					url,
					proxy,
					headers,
					payloads,
					cookie,
					method,
					timeout,
					retries,
					output_json,
					reporter=reporter,
					auto_export=False,
					detection_mode=detection_mode,
				)
