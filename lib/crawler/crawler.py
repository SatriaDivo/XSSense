import requests
from lib.helper.Log import *
from lib.helper.helper import *
from lib.core import *
import xssense_engine

class crawler:
	
	@classmethod
	def crawl(
		self,
		base,
		depth,
		proxy,
		headers,
		level,
		method,
		cookie,
		timeout=15,
		retries=1,
		output_json=None,
	):
		Log.info(f"[*] Menyalakan Mesin Crawler RUST kecepatan Tinggi (Max Depth: {depth}) untuk menyedot URL...")
		
		# Mengeksekusi ekstensi Rust yang merayap semua URL dalam hitungan detik!
		urls = xssense_engine.run_crawler(base, depth)
		
		# Menghapus duplikat dan mensortir output URL
		urls = list(set(urls))
		
		Log.info(f"[+] Crawler Rust berhasil mengekstrak {len(urls)} link dari {base}! Mengoper ke modul Injector XSS...")
		
		# Melakukan pemindaian terhadap SEMUA link yang dikeruk oleh Rust secara satu persatu.
		for url in urls:
			if url.startswith("https://") or url.startswith("http://"):
				# Langsung Panggil Scanner Core tanpa Process lama
				core.main(url, proxy, headers, level, cookie, method, timeout, retries, output_json)	
