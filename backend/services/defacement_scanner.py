# backend/services/defacement_scanner.py
import os
import time
import hashlib
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
import re
from datetime import datetime
import tempfile
import subprocess

class DefacementScanner:
    def __init__(self):
        self.base_dir = "monitoring_data"
        self.screenshots_dir = os.path.join(self.base_dir, "screenshots")
        self.html_snapshots_dir = os.path.join(self.base_dir, "html_snapshots")
        self.reports_dir = os.path.join(self.base_dir, "reports")
        
        # Create directories
        for directory in [self.screenshots_dir, self.html_snapshots_dir, self.reports_dir]:
            os.makedirs(directory, exist_ok=True)
        
        # Defacement keywords
        self.defacement_keywords = [
            'hacked by', 'pwned by', 'defaced by', 'owned by',
            'anonymous', 'lulzsec', 'free palestine', 'allah akbar',
            'bitcoin', 'cryptocurrency', 'ransomware', 'pay ransom',
            'your site has been hacked', 'contact us for recovery',
            'isis', 'cyber army', 'ghost team', 'exploit'
        ]
        
        # Active monitors
        self.active_monitors = {}
        
        # Check if required tools are available
        self.selenium_available = self._check_selenium()
        self.screenshot_method = self._determine_screenshot_method()
        
        print(f"DefacementScanner initialized:")
        print(f"  - Selenium available: {self.selenium_available}")
        print(f"  - Screenshot method: {self.screenshot_method}")
    
    def _check_selenium(self):
        """Check if Selenium and Chrome are available"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            # Try to create a Chrome driver
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            
            driver = webdriver.Chrome(options=options)
            driver.quit()
            return True
        except Exception as e:
            print(f"Selenium/Chrome not available: {e}")
            return False
    
    def _determine_screenshot_method(self):
        """Determine the best available screenshot method"""
        if self.selenium_available:
            return "selenium"
        
        # Check for wkhtmltopdf
        try:
            subprocess.run(['wkhtmltopdf', '--version'], 
                         capture_output=True, check=True)
            return "wkhtmltopdf"
        except:
            pass
        
        # Check for headless Chrome
        try:
            subprocess.run(['google-chrome', '--version'], 
                         capture_output=True, check=True)
            return "chrome_headless"
        except:
            pass
        
        return "requests_only"
    
    def capture_snapshot(self, url, monitor_id):
        """Capture screenshot and HTML snapshot using available method"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Clean URL
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Capture HTML first (always possible)
            html_content = self._capture_html(url)
            html_path = os.path.join(
                self.html_snapshots_dir,
                f"{monitor_id}_{timestamp}.html"
            )
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Try to capture screenshot
            screenshot_path = None
            if self.screenshot_method == "selenium":
                screenshot_path = self._capture_screenshot_selenium(url, monitor_id, timestamp)
            elif self.screenshot_method == "wkhtmltopdf":
                screenshot_path = self._capture_screenshot_wkhtmltopdf(url, monitor_id, timestamp)
            elif self.screenshot_method == "chrome_headless":
                screenshot_path = self._capture_screenshot_chrome(url, monitor_id, timestamp)
            
            # If screenshot capture failed, create a placeholder
            if not screenshot_path:
                screenshot_path = self._create_placeholder_screenshot(monitor_id, timestamp)
            
            page_info = {
                'title': self._extract_title(html_content),
                'url': url,
                'timestamp': timestamp,
                'screenshot_path': screenshot_path,
                'html_path': html_path,
                'html_hash': hashlib.md5(html_content.encode()).hexdigest(),
                'page_size': len(html_content),
                'method': self.screenshot_method
            }
            
            return page_info
            
        except Exception as e:
            raise Exception(f"Failed to capture snapshot: {str(e)}")
    
    def _capture_html(self, url):
        """Capture HTML content using requests"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.text
        except Exception as e:
            return f"<html><body><h1>Error capturing HTML</h1><p>{str(e)}</p></body></html>"
    
    def _capture_screenshot_selenium(self, url, monitor_id, timestamp):
        """Capture screenshot using Selenium"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--window-size=1920,1080')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-extensions')
            
            driver = webdriver.Chrome(options=options)
            driver.get(url)
            
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            time.sleep(3)  # Additional wait for dynamic content
            
            screenshot_path = os.path.join(
                self.screenshots_dir, 
                f"{monitor_id}_{timestamp}.png"
            )
            driver.save_screenshot(screenshot_path)
            driver.quit()
            
            return screenshot_path
            
        except Exception as e:
            print(f"Selenium screenshot failed: {e}")
            return None
    
    def _capture_screenshot_wkhtmltopdf(self, url, monitor_id, timestamp):
        """Capture screenshot using wkhtmltopdf"""
        try:
            screenshot_path = os.path.join(
                self.screenshots_dir, 
                f"{monitor_id}_{timestamp}.png"
            )
            
            cmd = [
                'wkhtmltoimage',
                '--width', '1920',
                '--height', '1080',
                '--format', 'png',
                url,
                screenshot_path
            ]
            
            subprocess.run(cmd, check=True, timeout=30)
            return screenshot_path
            
        except Exception as e:
            print(f"wkhtmltopdf screenshot failed: {e}")
            return None
    
    def _capture_screenshot_chrome(self, url, monitor_id, timestamp):
        """Capture screenshot using headless Chrome"""
        try:
            screenshot_path = os.path.join(
                self.screenshots_dir, 
                f"{monitor_id}_{timestamp}.png"
            )
            
            cmd = [
                'google-chrome',
                '--headless',
                '--disable-gpu',
                '--window-size=1920,1080',
                '--screenshot=' + screenshot_path,
                url
            ]
            
            subprocess.run(cmd, check=True, timeout=30)
            return screenshot_path
            
        except Exception as e:
            print(f"Chrome headless screenshot failed: {e}")
            return None
    
    def _create_placeholder_screenshot(self, monitor_id, timestamp):
        """Create a placeholder screenshot when capture fails"""
        try:
            from PIL import Image, ImageDraw, ImageFont
            
            # Create a simple placeholder image
            img = Image.new('RGB', (1920, 1080), color='#f8f9fa')
            draw = ImageDraw.Draw(img)
            
            # Try to use default font
            try:
                font = ImageFont.truetype("arial.ttf", 48)
            except:
                font = ImageFont.load_default()
            
            text = "Screenshot not available\nHTML content captured successfully"
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            
            x = (1920 - text_width) // 2
            y = (1080 - text_height) // 2
            
            draw.text((x, y), text, fill='#6b7280', font=font, align='center')
            
            screenshot_path = os.path.join(
                self.screenshots_dir, 
                f"{monitor_id}_{timestamp}_placeholder.png"
            )
            img.save(screenshot_path)
            return screenshot_path
            
        except Exception as e:
            print(f"Failed to create placeholder screenshot: {e}")
            return None
    
    def _extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()
            return "No title found"
        except:
            return "Title extraction failed"
    
    def compare_html_content(self, html1_path, html2_path):
        """Compare HTML content and detect changes"""
        try:
            with open(html1_path, 'r', encoding='utf-8') as f:
                html1 = f.read()
            with open(html2_path, 'r', encoding='utf-8') as f:
                html2 = f.read()
            
            # Calculate similarity
            from difflib import SequenceMatcher
            similarity = SequenceMatcher(None, html1, html2).ratio()
            change_percentage = (1 - similarity) * 100
            
            # Extract text content for keyword detection
            text1 = re.sub(r'<[^>]+>', ' ', html1).lower()
            text2 = re.sub(r'<[^>]+>', ' ', html2).lower()
            
            # Check for defacement keywords
            suspicious_keywords = []
            for keyword in self.defacement_keywords:
                if keyword in text2 and keyword not in text1:
                    suspicious_keywords.append(keyword)
            
            return {
                'similarity_percentage': round(similarity * 100, 2),
                'change_percentage': round(change_percentage, 2),
                'suspicious_keywords': suspicious_keywords,
                'html1_size': len(html1),
                'html2_size': len(html2)
            }
            
        except Exception as e:
            return {'error': f"HTML comparison failed: {str(e)}"}
    
    def compare_screenshots(self, img1_path, img2_path):
        """Compare two screenshots and return difference percentage"""
        try:
            # If either image doesn't exist, return basic comparison
            if not os.path.exists(img1_path) or not os.path.exists(img2_path):
                return {
                    'change_percentage': 0,
                    'changed_pixels': 0,
                    'total_pixels': 0,
                    'note': 'Screenshot comparison not available'
                }
            
            # Try to use PIL for basic comparison
            from PIL import Image
            
            img1 = Image.open(img1_path).convert('RGB')
            img2 = Image.open(img2_path).convert('RGB')
            
            # Resize to same dimensions if needed
            if img1.size != img2.size:
                img2 = img2.resize(img1.size)
            
            # Simple pixel difference calculation
            import numpy as np
            
            arr1 = np.array(img1)
            arr2 = np.array(img2)
            
            diff = np.abs(arr1 - arr2)
            changed_pixels = np.count_nonzero(diff)
            total_pixels = arr1.size
            
            change_percentage = (changed_pixels / total_pixels) * 100
            
            return {
                'change_percentage': round(change_percentage, 2),
                'changed_pixels': changed_pixels,
                'total_pixels': total_pixels
            }
            
        except Exception as e:
            return {
                'error': f"Screenshot comparison failed: {str(e)}",
                'change_percentage': 0,
                'changed_pixels': 0,
                'total_pixels': 0
            }
    
    def analyze_changes(self, current_snapshot, previous_snapshot, monitor_config):
        """Analyze changes between snapshots"""
        analysis_result = {
            'timestamp': datetime.now().isoformat(),
            'monitor_id': monitor_config['id'],
            'url': monitor_config['url'],
            'change_detected': False,
            'severity': 'low',
            'screenshot_comparison': {},
            'html_comparison': {},
            'alerts': []
        }
        
        # Compare HTML (always available)
        if previous_snapshot:
            html_diff = self.compare_html_content(
                previous_snapshot['html_path'],
                current_snapshot['html_path']
            )
            analysis_result['html_comparison'] = html_diff
            
            # Compare screenshots if available
            screenshot_diff = self.compare_screenshots(
                previous_snapshot.get('screenshot_path'),
                current_snapshot.get('screenshot_path')
            )
            analysis_result['screenshot_comparison'] = screenshot_diff
            
            # Determine if significant change occurred
            html_threshold = monitor_config.get('html_threshold', 10.0)
            screenshot_threshold = monitor_config.get('screenshot_threshold', 5.0)
            
            html_changed = html_diff.get('change_percentage', 0) > html_threshold
            screenshot_changed = screenshot_diff.get('change_percentage', 0) > screenshot_threshold
            keywords_detected = len(html_diff.get('suspicious_keywords', [])) > 0
            
            if keywords_detected:
                analysis_result['change_detected'] = True
                analysis_result['severity'] = 'critical'
                analysis_result['alerts'].append({
                    'type': 'defacement_keywords',
                    'message': f"Suspicious keywords detected: {', '.join(html_diff['suspicious_keywords'])}",
                    'severity': 'critical'
                })
            
            elif html_changed or screenshot_changed:
                analysis_result['change_detected'] = True
                analysis_result['severity'] = 'medium' if screenshot_changed else 'low'
                
                if screenshot_changed:
                    analysis_result['alerts'].append({
                        'type': 'visual_change',
                        'message': f"Visual change detected: {screenshot_diff['change_percentage']}% of page modified",
                        'severity': 'medium'
                    })
                
                if html_changed:
                    analysis_result['alerts'].append({
                        'type': 'content_change',
                        'message': f"Content change detected: {html_diff['change_percentage']}% of HTML modified",
                        'severity': 'low'
                    })
        
        return analysis_result
    
    def save_analysis_report(self, analysis_result):
        """Save analysis report to file"""
        report_file = os.path.join(
            self.reports_dir,
            f"{analysis_result['monitor_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(report_file, 'w') as f:
            json.dump(analysis_result, f, indent=2, default=str)
        
        return report_file
    
    def start_monitoring(self, monitor_config):
        """Start monitoring a website"""
        monitor_id = monitor_config['id']
        self.active_monitors[monitor_id] = {
            'config': monitor_config,
            'status': 'active',
            'started_at': datetime.now()
        }
        
        print(f"Started monitoring {monitor_config['url']} with ID: {monitor_id}")
        return True
    
    def stop_monitoring(self, monitor_id):
        """Stop monitoring a website"""
        if monitor_id in self.active_monitors:
            del self.active_monitors[monitor_id]
            print(f"Stopped monitoring: {monitor_id}")
            return True
        return False
    
    def get_latest_snapshot(self, monitor_id):
        """Get the latest snapshot for a monitor"""
        try:
            screenshots = [f for f in os.listdir(self.screenshots_dir) if f.startswith(monitor_id)]
            if not screenshots:
                return None
            
            # Get most recent screenshot
            latest_screenshot = sorted(screenshots)[-1]
            timestamp = latest_screenshot.split('_')[1].replace('.png', '').replace('_placeholder', '')
            
            html_file = f"{monitor_id}_{timestamp}.html"
            html_path = os.path.join(self.html_snapshots_dir, html_file)
            
            if os.path.exists(html_path):
                return {
                    'screenshot_path': os.path.join(self.screenshots_dir, latest_screenshot),
                    'html_path': html_path,
                    'timestamp': timestamp
                }
            
        except Exception as e:
            print(f"Error getting latest snapshot: {str(e)}")
        
        return None
    
    def get_monitor_history(self, monitor_id, days=7):
        """Get monitoring history for a specific monitor"""
        try:
            reports = []
            cutoff_date = datetime.now() - timedelta(days=days)
            
            for filename in os.listdir(self.reports_dir):
                if filename.startswith(monitor_id):
                    file_path = os.path.join(self.reports_dir, filename)
                    file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                    
                    if file_time >= cutoff_date:
                        with open(file_path, 'r') as f:
                            report = json.load(f)
                            reports.append(report)
            
            return sorted(reports, key=lambda x: x['timestamp'], reverse=True)
            
        except Exception as e:
            print(f"Error getting monitor history: {str(e)}")
            return []
    
    def get_status(self):
        """Get scanner status"""
        return {
            'available': True,
            'method': self.screenshot_method,
            'selenium_available': self.selenium_available,
            'active_monitors': len(self.active_monitors),
            'capabilities': {
                'screenshot_capture': self.screenshot_method != 'requests_only',
                'html_comparison': True,
                'keyword_detection': True,
                'continuous_monitoring': True
            }
        }