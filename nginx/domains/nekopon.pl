upstream synapse {
	zone synapse 32k;
	server [::1]:8008 max_conns=4096 fail_timeout=1s;
}

# matrix.nekopon.pl
server {
	listen 443 ssl http2 backlog=4096;
	listen [::]:443 ssl http2 backlog=4096;
	server_name matrix.nekopon.pl;

	root /var/empty;

	include snippets/security-headers.conf;
	add_header Cross-Origin-Resource-Policy "same-origin" always;
	add_header Permissions-Policy "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), xr-spatial-tracking=()" always;
	add_header Content-Security-Policy "font-src 'none'; manifest-src 'none'; object-src 'none'; script-src 'none'; style-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; block-all-mixed-content" always;
	add_header X-Frame-Options "DENY" always;

	location ~ ^(?:/_matrix|/_synapse/client) {
		# remove security headers that are statically set to the strictest possible values below
		proxy_hide_header Referrer-Policy;
		proxy_hide_header X-Frame-Options;

		include snippets/security-headers.conf;
		add_header Permissions-Policy "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), xr-spatial-tracking=()" always;
		add_header Content-Security-Policy "font-src 'none'; manifest-src 'none'; object-src 'none'; script-src 'none'; style-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; block-all-mixed-content" always;
		add_header Cross-Origin-Resource-Policy "cross-origin" always;
		add_header X-Frame-Options "DENY" always;
		add_header X-Robots-Tag "none";

		proxy_pass http://synapse;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Forwarded-Proto $scheme;
		proxy_set_header Host $host;
		proxy_read_timeout 600s;

		client_max_body_size 100m;
		client_body_buffer_size 16k;
	}

	location / { return 200 "synapse se smiga i essa Xd"; }
}

# element.internal.nekopon.pl
server {
	listen [fd69:6969:6969::1]:443 ssl http2;
	server_name element.internal.nekopon.pl;

	root /var/www/htdocs/element.internal.nekopon.pl;

	include snippets/security-headers.conf;
	add_header Cross-Origin-Resource-Policy "cross-origin" always;
	add_header Permissions-Policy "accelerometer=(), ambient-light-sensor=(), battery=(), camera=(), clipboard-read=(), display-capture=(), document-domain=(), encrypted-media=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), xr-spatial-tracking=()" always;
	add_header Content-Security-Policy "font-src 'self'; img-src 'self' https://matrix.nekopon.pl data: blob:; manifest-src 'self'; object-src 'none'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; frame-src 'self'; base-uri 'none'; form-action 'self'; worker-src 'self'; block-all-mixed-content" always;
	add_header X-Frame-Options "SAMEORIGIN" always;
	add_header X-Robots-Tag "none";
}

# intro.internal.nekopon.pl
server {
	listen [fd69:6969:6969::1]:443 ssl http2;
	server_name intro.internal.nekopon.pl;

	root /var/www/htdocs/intro.internal.nekopon.pl;

	include snippets/security-headers.conf;
	add_header Cross-Origin-Resource-Policy "cross-origin" always;
	add_header Cross-Origin-Embedder-Policy "unsafe-none" always;
	add_header Permissions-Policy "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), xr-spatial-tracking=()" always;
	add_header Content-Security-Policy "default-src 'none'; child-src 'none'; connect-src https://api.openweathermap.org; font-src 'none'; img-src 'self' https://openweathermap.org; manifest-src 'none'; script-src 'self'; style-src 'self'; form-action 'self' https://www.google.com; frame-ancestors 'none'; block-all-mixed-content; base-uri 'none'" always;
	add_header X-Frame-Options "DENY" always;
	add_header X-Robots-Tag "none";

	location / { try_files $uri $uri/ =404; }
}

# nekopon.pl
server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2;
	listen 127.0.0.1:8080;
	server_name nekopon.pl www.nekopon.pl nekoponmvppnutba7awvelxayxoutkolpplmmp7mxmfrobswqkbi5kad.onion;

	root /var/www/htdocs/nekopon.pl;

	include snippets/security-headers.conf;
	add_header Cross-Origin-Resource-Policy "same-origin" always;
	add_header Permissions-Policy "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), xr-spatial-tracking=()" always;
	# Google's web.dev/measure, Lighthouse and scrapers won't be able to use robots.txt with connect-src 'none'. Sad.
	add_header Content-Security-Policy "default-src 'none'; child-src 'none'; connect-src 'self'; font-src 'none'; img-src 'self'; manifest-src 'none'; script-src 'none'; style-src 'self'; form-action 'none'; frame-ancestors 'none'; block-all-mixed-content; base-uri 'none'" always;
	add_header X-Frame-Options "DENY" always;

	location / { try_files $uri $uri/ =404; }

	location /.well-known/matrix/client {
		include snippets/security-headers.conf;
		add_header Cross-Origin-Resource-Policy "cross-origin" always;
		add_header Permissions-Policy "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), xr-spatial-tracking=()" always;
		add_header Content-Security-Policy "default-src 'none'; child-src 'none'; connect-src 'self'; font-src 'none'; img-src 'self'; manifest-src 'none'; script-src 'none'; style-src 'self'; form-action 'none'; frame-ancestors 'none'; block-all-mixed-content; base-uri 'none'" always;
		add_header X-Frame-Options "DENY" always;
		add_header Access-Control-Allow-Origin *;
		return 200 '{"m.homeserver": {"base_url": "https://matrix.nekopon.pl:443"}}';
		default_type application/json;
	}

	location /.well-known/matrix/server {
		return 200 '{"m.server": "matrix.nekopon.pl:443"}';
		default_type application/json;
	}

	location ~ "\.webp$" {
		include snippets/security-headers.conf;
		# avoid breaking image hotlinking such as https://github.com/TryGhost/Ghost/issues/12880
		add_header Cross-Origin-Resource-Policy "cross-origin" always;
		add_header Permissions-Policy "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), xr-spatial-tracking=()" always;
		add_header Content-Security-Policy "default-src 'none'; child-src 'none'; connect-src 'self'; font-src 'none'; img-src 'self'; manifest-src 'none'; script-src 'none'; style-src 'self'; form-action 'none'; frame-ancestors 'none'; block-all-mixed-content; base-uri 'none'" always;
		add_header X-Frame-Options "DENY" always;
	}

	location /site/img/gravatar.png {
		include snippets/security-headers.conf;
		# avoid breaking image hotlinking such as https://github.com/TryGhost/Ghost/issues/12880
		add_header Cross-Origin-Resource-Policy "cross-origin" always;
		add_header Permissions-Policy "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), xr-spatial-tracking=()" always;
		add_header Content-Security-Policy "default-src 'none'; child-src 'none'; connect-src 'self'; font-src 'none'; img-src 'self'; manifest-src 'none'; script-src 'none'; style-src 'self'; form-action 'none'; frame-ancestors 'none'; block-all-mixed-content; base-uri 'none'" always;
		add_header X-Frame-Options "DENY" always;

		proxy_pass https://secure.gravatar.com/avatar/b1ba96bc4847f45193a62856d3592063;
		proxy_pass_request_headers off;
		proxy_buffering on;
		proxy_cache static;
		proxy_ignore_headers Cache-Control;
		proxy_ignore_headers Expires;
		proxy_hide_header Cache-Control;
		proxy_hide_header Expires;
	}
}
