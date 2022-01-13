# nazareth.nekopon.pl

Configs that I use on my OpenBSD VPS.  

---

SSL certs are generated with:

	certbot certonly --manual \
	  --must-staple \
	  --preferred-challenges=dns \
	  --email nat@nekopon.pl \
	  --server https://acme-v02.api.letsencrypt.org/directory \
	  --agree-tos \
	  --manual-public-ip-logging-ok \
	  -d "*.nekopon.pl" \
	  -d "*.internal.nekopon.pl" \
	  -d nekopon.pl

Apparently Must Staple is wrong practice on SMTP, so:

	certbot certonly --manual \
	  --preferred-challenges=dns \
	  --email nat@nekopon.pl \
	  --server https://acme-v02.api.letsencrypt.org/directory \
	  --agree-tos \
	  --manual-public-ip-logging-ok \
	  -d "nazareth.nekopon.pl" \
	  -d "mail.internal.nekopon.pl"

---

Services like NextCloud are being hosted on internal WireGuard network. I know that it's only obscurity but I'm not going to just expose such big PHP codebase.

---

nekopon.pl DNS zone

	$TTL 3600
	@	IN SOA dns19.ovh.net. tech.ovh.net. (2022010305 86400 3600 3600000 60)
	                           IN NS     ns19.ovh.net.
	                           IN NS     dns19.ovh.net.
	                           IN MX     1 nazareth.nekopon.pl.
	                           IN A      188.68.55.97
	                           IN AAAA   2a03:4000:6:e5e6::1
	                           IN CAA    128 issue "letsencrypt.org"
	                           IN SSHFP  4 2 5e5803d7238a206a0ae606deebee178c0c4a1adaaba63ded7133d2d8de89b206
	                       600 IN TXT    "oa1:xmr recipient_address=83i6pD6NcQnUSmFvq328Fw1QTuXjTG76zM3xKGQtNyxm727FmJgKN9w9Lkw5w9eMTZEa4X5PRtnv7HkiKFw7YtjK6ktxpkY; recipient_name=nekopon.pl;"
	                       600 IN TXT    "google-site-verification=nLXFoRn0mKpLtuYS42NNgvnMU5bUkcYbD83wOjMlsfg"
	                       600 IN TXT    "v=spf1 mx -all"
	                       600 IN TXT    "oa1:btc recipient_address=bc1qmeq3gars87cahp83nqg5nqnl3r9s83yjy28y5e; recipient_name=nekopon.pl;"
	20210325._domainkey        IN TXT    ( "v=DKIM1;k=rsa;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHJfkJupoAeH/AqfsjwKflYoK1bIzN9YgRmXwCNK13Ed7ARlJ8dUu0eAlbvuvHDbMX+UEzqAmmaQgdpLFrepqz5zbLZ+sm6y4ceA/skEpk0eZotaSXl1P7rh3Use1UoR7L878y8+dJfpoGpFQh9BOZ3GW3XJIHqvZDLr2CH9SoYwIDAQAB;" )
	_dmarc                     IN TXT    "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s"
	matrix                     IN A      188.68.55.97
	matrix                     IN AAAA   2a03:4000:6:e5e6::1
	nazareth                   IN A      188.68.55.97
	nazareth                   IN AAAA   2a03:4000:6:e5e6::1
	neko                       IN A      34.116.179.40
