
server {
	listen $STATIP$:80;
	server_name default_server;
	return 301 https://$server_addr$request_uri;
}


server {

	# SSL configuration
	#
	listen $STATIP$:443 ssl;

	root $FALCONGATEDIR$/html;

	index index.html index.htm index.nginx-debian.html index.php;

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	server_name default_server;
	ssl_certificate $FALCONGATEDIR$/ssl/nginx.crt;
	ssl_certificate_key $FALCONGATEDIR$/ssl/nginx.key;
	
	location ~\.php$ {
                  fastcgi_pass unix:/run/php/php7.0-fpm.sock;
                  fastcgi_split_path_info ^(.+\.php)(/.*)$;
                  fastcgi_index index.php;
                  fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                  fastcgi_param HTTPS off;
                  try_files $uri =404;
                  include fastcgi_params;
          }	
location ~ /(\.|pwd.db|readme.html|license.txt)
{
        deny all;
}

}

