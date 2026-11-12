# Public, loopback-only test credentials. NEVER use these keys/certificates in deployment.
$ErrorActionPreference='Stop'
$sha=[Security.Cryptography.HashAlgorithmName]::SHA256
$padding=[Security.Cryptography.RSASignaturePadding]::Pkcs1
$rootKey=[Security.Cryptography.RSA]::Create(2048)
$leafKey=[Security.Cryptography.RSA]::Create(2048)
$root=$null;$leaf=$null
try {
    $rootReq=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=ferroc proxy test root',$rootKey,$sha,$padding)
    $rootReq.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
    $rootReq.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign,$true))
    $rootReq.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($rootReq.PublicKey,$false))
    $from=[DateTimeOffset]::new(2020,1,1,0,0,0,[TimeSpan]::Zero)
    $root=$rootReq.CreateSelfSigned($from,[DateTimeOffset]::new(2040,1,1,0,0,0,[TimeSpan]::Zero))
    $leafReq=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=ferroc loopback fixture',$leafKey,$sha,$padding)
    $leafReq.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
    $leafReq.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,$true))
    $eku=[Security.Cryptography.OidCollection]::new();$eku.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))|Out-Null
    $leafReq.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku,$false))
    $san=[Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    foreach($name in @('localhost','relay.invalid','proxy.invalid')){$san.AddDnsName($name)}
    $san.AddIpAddress([Net.IPAddress]::Parse('127.0.0.1'));$leafReq.CertificateExtensions.Add($san.Build())
    $serial=[Security.Cryptography.RandomNumberGenerator]::GetBytes(16);$serial[0]=$serial[0] -band 0x7f
    $leaf=$leafReq.Create($root,$from,[DateTimeOffset]::new(2039,1,1,0,0,0,[TimeSpan]::Zero),$serial)
    [IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'proxy-test-leaf.der'),$leaf.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    [IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'proxy-test-key.der'),$leafKey.ExportPkcs8PrivateKey())
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'proxy-test-root.pem'),($root.ExportCertificatePem().Replace("`r`n","`n")+"`n"),[Text.UTF8Encoding]::new($false))
    Write-Output 'Generated PUBLIC TEST ONLY CA, TLS leaf and unencrypted PKCS8 test key (valid 2020..2039); no system trust store change.'
} finally {if($leaf){$leaf.Dispose()};if($root){$root.Dispose()};$leafKey.Dispose();$rootKey.Dispose()}
