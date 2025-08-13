# Hedef hash 
$targetHash = "5d41402abc4b2a76b9719d911017c592"  

# Kullanılacak karakter seti:
$charset = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`~!@#$%^&*()-_=+[{]}\|;:'"',<.>/? ') -split ''
# Maksimum şifre uzunluğu
$maxLength = 12
function Get-MD5Hash([string]$input) {
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($input)
    $hash = $md5.ComputeHash($bytes)
    return ([System.BitConverter]::ToString($hash)).Replace("-", "").ToLower()
}
function BruteForce($prefix) {
    if ($prefix.Length -ge $maxLength) { return }

    foreach ($char in $charset) {
        $candidate = "$prefix$char"
        $candidateHash = Get-MD5Hash $candidate
        if ($candidateHash -eq $targetHash) {
            Write-Host "Şifre bulundu: $candidate"
            exit
        }
        BruteForce $candidate
    }
}
# Başlat
BruteForce ""
Write-Host "Şifre bulunamadı."
