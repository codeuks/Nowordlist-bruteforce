# Network Scanner (Nmap Benzeri)

Go dilinde yazılmış basit bir network tarama aracı. Eğitim amaçlı olarak geliştirilmiştir.

## Özellikler

- TCP port tarama
- Çoklu thread desteği
- Esnek port aralığı tanımlama
- Host keşfi
- Hızlı ve etkili tarama

## Kurulum

```bash
go mod tidy
go build -o scanner main.go
```

## Kullanım

### Temel Port Tarama
```bash
go run main.go -host google.com -ports 80,443
```

### Port Aralığı Tarama
```bash
go run main.go -host 192.168.1.1 -ports 1-1000
```

### Gelişmiş Tarama
```bash
go run main.go -host example.com -ports 20-25,80,443,8080 -threads 200 -timeout 3s
```

### Host Keşfi ile Tarama
```bash
go run main.go -host 192.168.1.1 -host-discovery -ports 1-100
```

### Kapalı Portları da Göster
```bash
go run main.go -host localhost -ports 1-100 -show-closed
```

## Parametreler

- `-host`: Taranacak hedef host (zorunlu)
- `-ports`: Port aralığı (varsayılan: 1-1000)
  - Tek port: `80`
  - Çoklu port: `22,80,443`
  - Aralık: `1-1000`
- `-threads`: Eş zamanlı thread sayısı (varsayılan: 100)
- `-timeout`: Bağlantı timeout süresi (varsayılan: 2s)
- `-show-closed`: Kapalı portları da göster
- `-host-discovery`: Host keşfi yap

## Örnek Çıktı

```
Starting port scan on google.com...
Scanning 3 ports with 100 threads

Scan Results for google.com:
PORT    STATE
----    -----
80/tcp  open
443/tcp open

Scan completed: 2 open ports found
Scan completed in 1.234s
```

## Uyarılar

- Bu araç sadece eğitim amaçlıdır
- Yalnızca kendi sistemlerinizde veya izniniz olan sistemlerde kullanın
- Ağ yöneticilerinin politikalarına uyun
- Yasal sorumluluk kullanıcıya aittir

## Lisans

Eğitim amaçlı açık kaynak proje.
