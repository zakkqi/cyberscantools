# backend/services/google_dorking_scanner.py
import requests
import os
import time
import json
from urllib.parse import urlparse
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class GoogleDorkingScanner:
    def __init__(self):
        # API credentials
        self.api_key = os.getenv("GOOGLE_API_KEY", "AIzaSyBzt92w3eTnOcGf2qSmMDf4rQ-bK1qNk3k")
        self.search_engine_id = os.getenv("GOOGLE_CSE_ID", "c17a45a6ac320453a")
        
        # Common Google Dorks
        self.common_dorks = [
            "inurl:admin",
            "filetype:pdf",
            "intitle:\"index of\"",
            "intext:password",
            "ext:php OR ext:asp OR ext:aspx OR ext:jsp OR ext:html OR ext:htm OR ext:cf OR ext:pl",
            "inurl:wp-content",
            "intitle:\"Login Page\"",
            "inurl:config",
            "intext:\"sql syntax near\" OR intext:\"syntax error has occurred\" OR intext:\"incorrect syntax near\" OR intext:\"unexpected end of SQL command\" OR intext:\"Warning: mysql_connect()\" OR intext:\"Warning: mysql_query()\" OR intext:\"Warning: pg_connect()\"",
            "ext:log OR ext:txt OR ext:conf OR ext:cnf OR ext:ini OR ext:env OR ext:sh OR ext:bak OR ext:backup OR ext:swp OR ext:old OR ext:~ OR ext:git OR ext:svn OR ext:htpasswd OR ext:htaccess"
        ]
        
    def scan(self, target, scan_options=None):
        """
        Melakukan scan Google Dorking pada domain target dengan paginasi.
        
        Args:
            target (str): Domain target yang akan di-scan
            scan_options (dict): Opsi scan, termasuk dorks yang akan digunakan
            
        Returns:
            dict: Hasil scan
        """
        if scan_options is None:
            scan_options = {}
            
        dorks = scan_options.get('dorks', self.common_dorks)
        
        if isinstance(dorks, str):
            dorks = [d.strip() for d in dorks.split('\n') if d.strip()]
        
        # Tambahkan parameter untuk jumlah halaman yang akan diambil
        num_pages = scan_options.get('num_pages', 3)  # Default 3 halaman
        num_results_per_page = 10  # Google CSE maksimum 10 per halaman
        
        print(f"Starting Google Dorking scan for target: {target} with {len(dorks)} dorks, {num_pages} pages per dork")
        
        results = []
        errors = []
        
        for dork_index, dork in enumerate(dorks):
            # Ganti | dengan OR untuk Google CSE API
            clean_dork = dork.replace("|", "OR")
            query = f"{clean_dork} site:{target}"
            
            print(f"[{dork_index+1}/{len(dorks)}] Scanning with dork: {clean_dork}")
            
            # Loop untuk setiap halaman yang ingin diambil
            for page in range(num_pages):
                try:
                    start_index = page * num_results_per_page + 1  # Google mulai dari indeks 1
                    
                    print(f"  Fetching page {page+1} (start index: {start_index})")
                    
                    url = "https://www.googleapis.com/customsearch/v1"
                    params = {
                        'key': self.api_key,
                        'cx': self.search_engine_id,
                        'q': query,
                        'num': num_results_per_page,
                        'start': start_index,  # Parameter penting untuk paginasi
                        'safe': 'off'
                    }
                    
                    # Tambahkan delay untuk menghindari rate limiting
                    time.sleep(1)
                    
                    response = requests.get(url, params=params)
                    data = response.json()
                    
                    if 'error' in data:
                        error_msg = f"API Error ({data['error']['code']}): {data['error']['message']}"
                        errors.append({
                            'dork': dork,
                            'error': error_msg,
                            'page': page + 1
                        })
                        print(f"  Error: {error_msg}")
                        break  # Berhenti mencoba halaman lain jika ada error
                    
                    # Periksa apakah ada hasil
                    if 'items' in data:
                        page_results = len(data['items'])
                        print(f"  Found {page_results} results on page {page+1}")
                        
                        for item in data['items']:
                            result = {
                                'title': item.get('title', ''),
                                'link': item.get('link', ''),
                                'snippet': item.get('snippet', ''),
                                'dork': dork,
                                'page': page + 1  # Halaman dimulai dari 1 untuk user
                            }
                            results.append(result)
                        
                        # Jika hasil kurang dari maksimum, tidak ada halaman lain
                        if page_results < num_results_per_page:
                            print(f"  No more results available (found {page_results} < {num_results_per_page})")
                            break
                    else:
                        # Tidak ada hasil pada halaman ini
                        print(f"  No results found on page {page+1}")
                        break
                        
                except Exception as e:
                    print(f"  Exception during scan: {str(e)}")
                    errors.append({
                        'dork': dork,
                        'error': str(e),
                        'page': page + 1
                    })
                    break  # Hentikan paginasi jika terjadi error
        
        # Kategorisasi hasil berdasarkan sektor
        sector_results = self.categorize_by_sector(results)
        
        # Hitung jumlah hasil per sektor dan tentukan risk level
        sector_summary = self.generate_sector_summary(sector_results)
        
        # Buat domain summary
        domain_summary = self.analyze_domains(results)
        
        # Informasi paginasi
        pagination_info = {
            'total_pages_requested': num_pages,
            'max_results_per_page': num_results_per_page,
            'total_dorks': len(dorks),
            'max_potential_results': num_pages * num_results_per_page * len(dorks)
        }
        
        print(f"Scan completed. Found {len(results)} results across {len(dorks)} dorks.")
        
        return {
            'status': 'success' if not errors else 'partial',
            'target': target,
            'results': results,
            'errors': errors,
            'sector_results': sector_results,
            'sector_summary': sector_summary,
            'domain_summary': domain_summary,
            'pagination_info': pagination_info,
            'summary': {
                'total_dorks': len(dorks),
                'successful_dorks': len(dorks) - len({err['dork'] for err in errors}),
                'total_findings': len(results)
            }
        }
    
    def categorize_by_sector(self, results):
        """Kategorisasi hasil berdasarkan sektor"""
        sectors = {
            'pemerintah': [],
            'rumah_sakit': [],
            'universitas': [],
            'bumn': [],
            'bank': [],
            'kepolisian': [],
            'militer': [],
            'pengadilan': [],
            'pajak': [],
            'transportasi': [],
            'pendidikan': [],
            'lingkungan': [],
            'pariwisata': [],
            'pertanian': [],
            'energi': [],
            'lainnya': []
        }
        
        # Keywords untuk setiap sektor
        sector_keywords = {
            'pemerintah': ['kementerian', 'kemenko', 'kemenag', 'kemendikbud', 'kemenpar', 'kemenkeu', 'kemenkes', 
                           'kemendag', 'kemenperin', 'kemensos', 'kemenhub', 'kemenlu', 'pemkot', 'pemkab', 'pemda', 
                           'pemprov', 'dprd', 'dpr', 'bappenas', 'bappeda', 'lapan', 'bpip', 'lkpp', 'bnpb'],
            'rumah_sakit': ['rs', 'rsud', 'rumahsakit', 'rumah sakit', 'puskesmas', 'klinik', 'kesehatan'],
            'universitas': ['universitas', 'univ', 'university', 'institut', 'its', 'itb', 'ui', 'ugm', 'undip', 
                            'unair', 'uns', 'unsri', 'uin', 'iain', 'stie', 'stikom', 'stis', 'stmik', 'stba', 
                            'stikes', 'politeknik', 'poltekkes', 'akademi'],
            'bumn': ['bumn', 'pertamina', 'pln', 'telkom', 'pos', 'kereta', 'garuda', 'pelni', 'antam', 'inalum', 
                     'bio farma', 'pegadaian', 'taspen', 'jasa marga'],
            'bank': ['bank', 'bi.go.id', 'ojk', 'lps'],
            'kepolisian': ['polri', 'polda', 'polres', 'polsek', 'kepolisian'],
            'militer': ['tni', 'tentara', 'militer', 'kodam', 'korem', 'kemhan'],
            'pengadilan': ['pengadilan', 'pn', 'pa', 'pt', 'ma', 'mk', 'kejaksaan', 'kejari', 'kejati', 'hukum', 'ham', 'kumham'],
            'pajak': ['pajak', 'djp', 'perpajakan', 'bea cukai', 'bc'],
            'transportasi': ['kemenhub', 'dephub', 'dishub', 'perhubungan', 'transportasi', 'pelabuhan', 'bandara', 'terminal'],
            'pendidikan': ['sekolah', 'sma', 'smk', 'smp', 'sd', 'madrasah', 'mts', 'man', 'min', 'tk', 'paud', 'dinas pendidikan'],
            'lingkungan': ['lingkungan', 'klhk', 'kehutanan', 'dlh', 'blh'],
            'pariwisata': ['pariwisata', 'wisata', 'budaya', 'heritage', 'museum', 'cagar-budaya', 'tourism'],
            'pertanian': ['pertanian', 'perkebunan', 'peternakan', 'pangan', 'perikanan', 'kelautan'],
            'energi': ['esdm', 'tambang', 'mineral', 'batubara', 'minyak', 'gas', 'energi']
        }
        
        for result in results:
            url = result['link'].lower()
            title = result['title'].lower()
            snippet = result['snippet'].lower()
            content = title + ' ' + snippet + ' ' + url
            
            # Assign ke sektor
            assigned = False
            for sector, keywords in sector_keywords.items():
                if any(keyword in content for keyword in keywords):
                    sectors[sector].append(result)
                    result['sector'] = sector
                    assigned = True
                    break
            
            # Jika tidak terdeteksi oleh keyword, coba deteksi dari domain
            if not assigned:
                domain = self.extract_domain(result['link'])
                
                # Coba deteksi dari domain
                if '.go.id' in domain:
                    sectors['pemerintah'].append(result)
                    result['sector'] = 'pemerintah'
                elif '.ac.id' in domain:
                    sectors['universitas'].append(result)
                    result['sector'] = 'universitas'
                elif '.sch.id' in domain:
                    sectors['pendidikan'].append(result)
                    result['sector'] = 'pendidikan'
                elif '.mil.id' in domain:
                    sectors['militer'].append(result)
                    result['sector'] = 'militer'
                elif '.bumn.go.id' in domain:
                    sectors['bumn'].append(result)
                    result['sector'] = 'bumn'
                else:
                    sectors['lainnya'].append(result)
                    result['sector'] = 'lainnya'
        
        return sectors
    
    def generate_sector_summary(self, sector_results):
        """Generate ringkasan berdasarkan sektor dan tentukan risk level"""
        sector_counts = {sector: len(results) for sector, results in sector_results.items() if results}
        
        # Urutkan sektor berdasarkan jumlah hasil (dari terbanyak ke tersedikit)
        sorted_sectors = sorted(sector_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Tentukan risk level berdasarkan urutan (4 teratas)
        risk_levels = {}
        for i, (sector, count) in enumerate(sorted_sectors):
            if i == 0 and count > 0:
                risk_levels[sector] = 'critical'
            elif i == 1 and count > 0:
                risk_levels[sector] = 'high'
            elif i == 2 and count > 0:
                risk_levels[sector] = 'medium'
            elif i == 3 and count > 0:
                risk_levels[sector] = 'low'
            else:
                risk_levels[sector] = 'info'
        
        # Buat ringkasan
        summary = {
            'sector_counts': sector_counts,
            'sorted_sectors': sorted_sectors,
            'risk_levels': risk_levels
        }
        
        return summary
    
    def analyze_domains(self, results):
        """Analisis domain untuk detail hasil"""
        domains = {}
        
        for result in results:
            domain = self.extract_domain(result['link'])
            
            if domain not in domains:
                domains[domain] = 0
            domains[domain] += 1
        
        # Sort domains by count
        sorted_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)
        top_domains = {domain: count for domain, count in sorted_domains[:20]}  # top 20
        
        return {
            'domains': top_domains,
            'total_domains': len(domains)
        }
    
    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed_url = urlparse(url)
            return parsed_url.netloc
        except:
            return ""
    
    def get_common_dorks(self):
        """
        Mengembalikan daftar common dorks yang dapat digunakan.
        
        Returns:
            list: Daftar common dorks
        """
        return self.common_dorks