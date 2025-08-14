#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WordPress Güvenlik Test Aracı
===============================

⚠️  SADECE EĞİTİM AMAÇLI VE KENDİ SİTENİZDE KULLANIN!

Bu araç kendi WordPress sitenizin güvenlik açıklarını tespit etmenize yardımcı olur.
Başka sitelerde kullanmak yasadışıdır ve etik değildir.

Kullanım:
    python wp_security_tester.py http://localhost:8080

Gereksinimler:
    pip install requests beautifulsoup4 mysql-connector-python
"""

import requests
import sys
import re
import time
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import mysql.connector
from mysql.connector import Error

class WordPressSecurityTester:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WordPress-Security-Tester/1.0 (Educational Purpose Only)'
        })
        
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                WordPress Güvenlik Test Aracı                ║
║                                                              ║
║  ⚠️  SADECE KENDİ SİTENİZDE KULLANIN!                      ║
║  Bu araç sadece eğitim amaçlı ve kendi güvenliğinizi       ║
║  test etmek içindir.                                        ║
╚══════════════════════════════════════════════════════════════╝

🎯 Hedef: {self.target_url}
""")
    
    def log(self, message, level="INFO"):
        """Logging fonksiyonu"""
        timestamp = time.strftime("%H:%M:%S")
        if level == "WARN":
            print(f"⚠️  [{timestamp}] {message}")
        elif level == "ERROR":
            print(f"❌ [{timestamp}] {message}")
        elif level == "SUCCESS":
            print(f"✅ [{timestamp}] {message}")
        else:
            print(f"ℹ️  [{timestamp}] {message}")
    
    def check_accessibility(self):
        """Sitenin erişilebilirliğini kontrol eder"""
        self.log("Site erişilebilirlik kontrolü...")
        try:
            response = self.session.get(self.target_url, timeout=10)
            if response.status_code == 200:
                self.log("Site erişilebilir", "SUCCESS")
                return True
            else:
                self.log(f"Site erişilemiyor (HTTP {response.status_code})", "ERROR")
                return False
        except Exception as e:
            self.log(f"Bağlantı hatası: {str(e)}", "ERROR")
            return False
    
    def detect_wordpress(self):
        """WordPress varlığını tespit eder"""
        self.log("WordPress tespit edilmeye çalışılıyor...")
        
        indicators = [
            '/wp-content/',
            '/wp-includes/',
            '/wp-admin/',
            'wp-json',
            'wordpress'
        ]
        
        try:
            response = self.session.get(self.target_url)
            content = response.text.lower()
            
            wp_found = any(indicator in content for indicator in indicators)
            
            if wp_found:
                self.log("WordPress tespit edildi!", "SUCCESS")
                return True
            else:
                self.log("WordPress tespit edilemedi", "WARN")
                return False
                
        except Exception as e:
            self.log(f"WordPress tespit hatası: {str(e)}", "ERROR")
            return False
    
    def get_wordpress_version(self):
        """WordPress versiyonunu tespit eder"""
        self.log("WordPress versiyonu tespit ediliyor...")
        
        version_urls = [
            '/readme.html',
            '/wp-admin/',
            '/wp-includes/js/jquery/jquery.js'
        ]
        
        for url in version_urls:
            try:
                response = self.session.get(urljoin(self.target_url, url))
                
                # readme.html'den versiyon
                if 'readme.html' in url and response.status_code == 200:
                    version_match = re.search(r'Version (\d+\.\d+(?:\.\d+)?)', response.text)
                    if version_match:
                        version = version_match.group(1)
                        self.log(f"WordPress versiyon tespit edildi: {version}", "SUCCESS")
                        return version
                
                # wp-admin'den versiyon
                elif 'wp-admin' in url:
                    version_match = re.search(r'ver=(\d+\.\d+(?:\.\d+)?)', response.text)
                    if version_match:
                        version = version_match.group(1)
                        self.log(f"WordPress versiyon tespit edildi: {version}", "SUCCESS")
                        return version
                        
            except Exception as e:
                if self.verbose:
                    self.log(f"Versiyon tespit hatası ({url}): {str(e)}", "ERROR")
        
        self.log("WordPress versiyonu tespit edilemedi", "WARN")
        return None
    
    def check_common_files(self):
        """Yaygın WordPress dosyalarını kontrol eder"""
        self.log("Yaygın dosya erişilebilirlik kontrolü...")
        
        sensitive_files = [
            ('/wp-config.php', 'Kritik yapılandırma dosyası'),
            ('/wp-config.php.bak', 'Yedek yapılandırma dosyası'),
            ('/wp-config.php~', 'Geçici yapılandırma dosyası'),
            ('/wp-admin/install.php', 'Kurulum dosyası'),
            ('/wp-content/debug.log', 'Debug log dosyası'),
            ('/xmlrpc.php', 'XML-RPC servisi'),
            ('/.htaccess', 'Apache yapılandırma dosyası'),
            ('/wp-content/uploads/', 'Upload dizini'),
        ]
        
        accessible_files = []
        
        for file_path, description in sensitive_files:
            try:
                response = self.session.get(urljoin(self.target_url, file_path))
                if response.status_code == 200:
                    self.log(f"Erişilebilir dosya: {file_path} ({description})", "WARN")
                    accessible_files.append((file_path, description))
                elif self.verbose:
                    self.log(f"Dosya korunuyor: {file_path}", "SUCCESS")
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"Dosya kontrol hatası ({file_path}): {str(e)}", "ERROR")
        
        return accessible_files
    
    def check_user_enumeration(self):
        """Kullanıcı numaralandırma açığını kontrol eder"""
        self.log("Kullanıcı numaralandırma açığı kontrol ediliyor...")
        
        found_users = []
        
        for user_id in range(1, 11):  # İlk 10 kullanıcıyı kontrol et
            try:
                # Author sayfası yöntemi
                response = self.session.get(f"{self.target_url}/?author={user_id}")
                
                if response.status_code == 200 and 'author' in response.url.lower():
                    # URL'den kullanıcı adını çıkarmaya çalış
                    username_match = re.search(r'/author/([^/]+)', response.url)
                    if username_match:
                        username = username_match.group(1)
                        found_users.append((user_id, username))
                        self.log(f"Kullanıcı tespit edildi - ID: {user_id}, Username: {username}", "WARN")
                
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                if self.verbose:
                    self.log(f"Kullanıcı numaralandırma hatası (ID: {user_id}): {str(e)}", "ERROR")
        
        if not found_users:
            self.log("Kullanıcı numaralandırma koruması aktif", "SUCCESS")
        
        return found_users
    
    def check_xmlrpc(self):
        """XML-RPC servisini kontrol eder"""
        self.log("XML-RPC servisi kontrol ediliyor...")
        
        try:
            xmlrpc_data = """<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
</methodCall>"""
            
            response = self.session.post(
                f"{self.target_url}/xmlrpc.php",
                data=xmlrpc_data,
                headers={'Content-Type': 'text/xml'},
                timeout=10
            )
            
            if response.status_code == 200 and 'methodResponse' in response.text:
                self.log("XML-RPC servisi aktif (güvenlik riski)", "WARN")
                
                # Mevcut metodları kontrol et
                if 'wp.getUsersBlogs' in response.text:
                    self.log("XML-RPC brute force saldırı riski mevcut", "WARN")
                    
                return True
            else:
                self.log("XML-RPC servisi devre dışı veya korunuyor", "SUCCESS")
                return False
                
        except Exception as e:
            self.log(f"XML-RPC kontrol hatası: {str(e)}", "ERROR")
            return False
    
    def test_login_security(self, usernames=None, passwords=None):
        """Login güvenliğini test eder"""
        self.log("Login güvenlik testi başlatılıyor...")
        
        if not usernames:
            usernames = ['admin', 'administrator', 'test', 'demo', 'user']
        if not passwords:
            passwords = ['123456', 'password', 'admin', 'test', '12345']
        
        login_url = f"{self.target_url}/wp-login.php"
        vulnerable_credentials = []
        
        # Rate limiting kontrolü
        attempt_count = 0
        max_attempts = 5  # Güvenlik için sınırlı test
        
        self.log(f"⚠️  Maksimum {max_attempts} deneme yapılacak (güvenlik için sınırlı)")
        
        for username in usernames:
            if attempt_count >= max_attempts:
                break
                
            for password in passwords:
                if attempt_count >= max_attempts:
                    break
                    
                try:
                    data = {
                        'log': username,
                        'pwd': password,
                        'wp-submit': 'Log In',
                        'redirect_to': f"{self.target_url}/wp-admin/"
                    }
                    
                    response = self.session.post(login_url, data=data, timeout=10)
                    attempt_count += 1
                    
                    # Başarılı giriş kontrolü
                    if response.status_code == 302 or 'dashboard' in response.text.lower():
                        vulnerable_credentials.append((username, password))
                        self.log(f"Zayıf kimlik bilgisi tespit edildi: {username}:{password}", "WARN")
                    
                    # Rate limiting tespit
                    elif 'too many' in response.text.lower() or response.status_code == 429:
                        self.log("Rate limiting tespit edildi (iyi güvenlik)", "SUCCESS")
                        break
                    
                    time.sleep(1)  # Nazik davranış
                    
                except Exception as e:
                    if self.verbose:
                        self.log(f"Login test hatası: {str(e)}", "ERROR")
        
        if not vulnerable_credentials:
            self.log("Zayıf kimlik bilgisi tespit edilmedi", "SUCCESS")
        
        return vulnerable_credentials
    
    def test_sql_injection_basic(self):
        """Temel SQL injection testleri yapar"""
        self.log("Temel SQL injection testi başlatılıyor...")
        
        # Basit SQL injection payloadları
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin'--",
            "' or 1=1#"
        ]
        
        login_url = f"{self.target_url}/wp-login.php"
        potential_sqli = []
        
        for payload in payloads[:3]:  # Sadece ilk 3'ünü test et
            try:
                data = {
                    'log': payload,
                    'pwd': 'test',
                    'wp-submit': 'Log In'
                }
                
                response = self.session.post(login_url, data=data, timeout=10)
                
                # SQL hata mesajları
                sql_errors = [
                    'mysql', 'sql syntax', 'database error', 
                    'warning: mysql', 'function.mysql', 'mysqli_'
                ]
                
                response_lower = response.text.lower()
                if any(error in response_lower for error in sql_errors):
                    potential_sqli.append(payload)
                    self.log(f"Potansiyel SQL injection: {payload}", "WARN")
                
                time.sleep(1)
                
            except Exception as e:
                if self.verbose:
                    self.log(f"SQL injection test hatası: {str(e)}", "ERROR")
        
        if not potential_sqli:
            self.log("SQL injection açığı tespit edilmedi", "SUCCESS")
        
        return potential_sqli
    
    def generate_report(self, results):
        """Test sonuçlarının raporunu oluşturur"""
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    GÜVENLİK TEST RAPORU                     ║
╚══════════════════════════════════════════════════════════════╝

🎯 Test Edilen Site: {self.target_url}
📅 Test Tarihi: {time.strftime('%Y-%m-%d %H:%M:%S')}

📊 SONUÇLAR:
""")
        
        if results.get('accessible_files'):
            print("⚠️  ERİŞİLEBİLİR DOSYALAR:")
            for file_path, desc in results['accessible_files']:
                print(f"   • {file_path} - {desc}")
        
        if results.get('found_users'):
            print("\n⚠️  TESPİT EDİLEN KULLANICILAR:")
            for user_id, username in results['found_users']:
                print(f"   • ID: {user_id}, Username: {username}")
        
        if results.get('vulnerable_creds'):
            print("\n⚠️  ZAYIF KİMLİK BİLGİLERİ:")
            for username, password in results['vulnerable_creds']:
                print(f"   • {username}:{password}")
        
        if results.get('sql_injection'):
            print("\n⚠️  SQL INJECTION RİSKİ:")
            for payload in results['sql_injection']:
                print(f"   • {payload}")
        
        print(f"""
🔒 GÜVENLİK ÖNERİLERİ:
   1. Güçlü şifreler kullanın
   2. XML-RPC'yi devre dışı bırakın
   3. wp-config.php dosyasını koruyun
   4. Kullanıcı numaralandırmayı engelleyin
   5. Rate limiting uygulayın
   6. Güvenlik eklentileri kullanın

⚠️  UYARI: Bu sonuçlar sadece eğitim amaçlıdır.
   Tespit edilen açıkları derhal kapatın!
""")
    
    def run_full_scan(self):
        """Tam güvenlik taraması yapar"""
        if not self.check_accessibility():
            return
        
        if not self.detect_wordpress():
            self.log("WordPress tespit edilemediği için tarama durduruluyor", "ERROR")
            return
        
        results = {}
        
        # WordPress versiyon tespiti
        version = self.get_wordpress_version()
        results['version'] = version
        
        # Dosya erişilebilirlik kontrolü
        results['accessible_files'] = self.check_common_files()
        
        # Kullanıcı numaralandırma
        results['found_users'] = self.check_user_enumeration()
        
        # XML-RPC kontrolü
        results['xmlrpc_active'] = self.check_xmlrpc()
        
        # Login güvenlik testi
        results['vulnerable_creds'] = self.test_login_security()
        
        # SQL injection testi
        results['sql_injection'] = self.test_sql_injection_basic()
        
        # Rapor oluştur
        self.generate_report(results)
        
        return results

def main():
    parser = argparse.ArgumentParser(
        description='WordPress Güvenlik Test Aracı (Sadece eğitim amaçlı)'
    )
    parser.add_argument('url', help='Test edilecek WordPress sitesinin URL\'si')
    parser.add_argument('-v', '--verbose', action='store_true', help='Detaylı çıktı')
    
    args = parser.parse_args()
    
    # URL doğrulama
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
    
    # Güvenlik uyarısı
    print("""
⚠️  GÜVENLİK UYARISI:
Bu araç sadece EĞİTİM AMAÇLI ve KENDİ SİTENİZDE kullanım içindir.
Başka sitelerde kullanmak YASADIŞ ve ETİK DEĞİLDİR.

Devam etmek istiyor musunuz? (y/N): """, end="")
    
    confirmation = input().strip().lower()
    if confirmation not in ['y', 'yes', 'evet', 'e']:
        print("İşlem iptal edildi.")
        sys.exit(0)
    
    # Test başlat
    tester = WordPressSecurityTester(args.url, args.verbose)
    tester.run_full_scan()

if __name__ == "__main__":
    main()