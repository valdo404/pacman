```
pacman --http-port 8080 --https-port 8443 --cert mycert.pem --key mykey.pem --bind 0.0.0.0
curl -v -x http://localhost:8080 https://www.google.com
curl -v -k --proxy-insecure -x https://localhost:8443 https://www.google.com
```
