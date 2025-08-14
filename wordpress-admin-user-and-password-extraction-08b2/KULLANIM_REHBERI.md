# WordPress Güvenlik Test Araçları - Kullanım Rehberi

## ⚠️ ÖNEMLİ UYARI

**Bu araçlar SADECE:**
- Eğitim amaçlı
- Kendi sahip olduğunuz WordPress sitelerde
- İzinli penetrasyon testlerinde

**kullanılmalıdır. Başka sitelerde kullanmak yasadışıdır!**

## Kurulum

### 1. Python Bağımlılıklarını Yükleyin

```bash
pip install -r requirements.txt
```

### 2. Test Ortamı Hazırlayın

#### Yerel WordPress Kurulumu (Docker ile)

```bash
# docker-compose.yml oluşturun
cat > docker-compose.yml << EOF
version: '3.8'
services:
  wordpress:
    image: wordpress:latest
    ports:
      - "8080:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
      WORDPRESS_DB_NAME: wordpress
    volumes:
      - wordpress_data:/var/www/html

  db:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress
      MYSQL_ROOT_PASSWORD: rootpassword
    volumes:
      - db_data:/var/lib/mysql

volumes:
  wordpress_data:
  db_data:
EOF

# WordPress'i başlatın
docker-compose up -d
```

## Kullanım

### Temel Güvenlik Taraması

```bash
python wp_security_tester.py http://localhost:8080
```

### Detaylı Çıktı ile

```bash
python wp_security_tester.py http://localhost:8080 -v
```

## Test Edilen Güvenlik Açıkları

### 1. 🔍 WordPress Tespit ve Versiyon Analizi
- WordPress varlığının tespit edilmesi
- Versiyon bilgisi çıkarma
- Eski versiyon güvenlik açıkları

### 2. 📁 Hassas Dosya Erişimi
- `wp-config.php` erişilebilirliği
- Yedek dosyalar (`.bak`, `~`)
- Debug log dosyaları
- Kurulum dosyaları

### 3. 👥 Kullanıcı Numaralandırma
- Author sayfaları üzerinden kullanıcı tespiti
- Kullanıcı ID'leri ve isimleri
- Admin hesapları

### 4. 🔐 Kimlik Doğrulama Zayıflıkları
- Zayıf şifre kombinasyonları
- Rate limiting kontrolü
- Brute force koruması

### 5. 💉 SQL Injection Testleri
- Login formunda SQL injection
- Hata mesajı analizi
- Database bilgi sızıntısı

### 6. 🌐 XML-RPC Güvenlik
- XML-RPC servis durumu
- Brute force saldırı riski
- Amplifikasyon saldırıları

## Örnek Çıktı

```
╔══════════════════════════════════════════════════════════════╗
║                WordPress Güvenlik Test Aracı                ║
║                                                              ║
║  ⚠️  SADECE KENDİ SİTENİZDE KULLANIN!                      ║
║  Bu araç sadece eğitim amaçlı ve kendi güvenliğinizi       ║
║  test etmek içindir.                                        ║
╚══════════════════════════════════════════════════════════════╝

🎯 Hedef: http://localhost:8080

ℹ️  [14:30:15] Site erişilebilirlik kontrolü...
✅ [14:30:15] Site erişilebilir
ℹ️  [14:30:15] WordPress tespit edilmeye çalışılıyor...
✅ [14:30:15] WordPress tespit edildi!
ℹ️  [14:30:15] WordPress versiyonu tespit ediliyor...
✅ [14:30:16] WordPress versiyon tespit edildi: 6.4.2
```

## Güvenlik Sertleştirme Önerileri

### wp-config.php Güvenlik Ayarları

```php
// Dosya düzenlemeyi devre dışı bırak
define('DISALLOW_FILE_EDIT', true);

// SSL zorla
define('FORCE_SSL_ADMIN', true);

// Debug modunu kapat
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);

// Güvenlik anahtarları
define('AUTH_KEY',         'güçlü-rastgele-anahtar-buraya');
define('SECURE_AUTH_KEY',  'güçlü-rastgele-anahtar-buraya');
define('LOGGED_IN_KEY',    'güçlü-rastgele-anahtar-buraya');
define('NONCE_KEY',        'güçlü-rastgele-anahtar-buraya');
define('AUTH_SALT',        'güçlü-rastgele-anahtar-buraya');
define('SECURE_AUTH_SALT', 'güçlü-rastgele-anahtar-buraya');
define('LOGGED_IN_SALT',   'güçlü-rastgele-anahtar-buraya');
define('NONCE_SALT',       'güçlü-rastgele-anahtar-buraya');

// Veritabanı prefix değiştir
$table_prefix = 'wp_custom_';
```

### .htaccess Güvenlik Kuralları

```apache
# wp-config.php'yi koru
<Files wp-config.php>
    Order allow,deny
    Deny from all
</Files>

# XML-RPC'yi devre dışı bırak
<Files xmlrpc.php>
    Order allow,deny
    Deny from all
</Files>

# wp-admin'i IP ile sınırla
<RequireAll>
    Require all granted
    Require not ip 192.168.1.100
</RequireAll>

# Hassas dosyaları gizle
<FilesMatch "^(wp-config\.php|\.htaccess|readme\.html|license\.txt)$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

### WordPress Güvenlik Eklentileri

1. **Wordfence Security**
2. **Sucuri Security**
3. **iThemes Security**
4. **All In One WP Security**

## Yasal Uyarılar

1. **Sadece kendi sistemlerinizde test yapın**
2. **İzin almadan başka sitelerde kullanmayın**
3. **Test sonuçlarını güvenli saklayın**
4. **Açıkları sorumlu bir şekilde bildirin**

## Sorumluluk Reddi

Bu araçlar sadece eğitim amaçlıdır. Yanlış kullanımdan doğacak her türlü hukuki sorumluluk kullanıcıya aittir.

---

**Unutmayın:** En iyi savunma, proaktif güvenlik önlemleridir!