# نصب بدون دانلود روی سرور

این بسته کد DNS Bond و هر دو باینری رسمی MasterDnsVPN را دارد. اینترنت برای نصب برنامه لازم نیست. لینوکس با systemd، پایتون ۳٫۱۱ یا جدیدتر در /usr/bin/python3، ابزارهای متداول لینوکس و OpenSSL باید از قبل نصب باشند. برای انتقال با scp و همگام‌سازی فهرست، SSH لازم است. اگر همهٔ مسیرهای DNS تا سرور خارج قطع باشند، تونل هم وصل نمی‌شود.

۱. دستور uname -m را روی هر سرور بزن. برای x86_64 بستهٔ amd64 و برای aarch64 بستهٔ arm64 را بگیر. بستهٔ مربوط به هر سرور را قبل از قطعی روی همان سرور بگذار. مثال برای amd64:

```sh
tar -xzf dns-bond-offline-linux-amd64.tar.gz
cd dns-bond-offline-linux-amd64
```

۲. روی خارج دستور اول و روی ایران دستور دوم را اجرا کن. نصب‌کننده سلامت فایل‌ها را بررسی می‌کند.

```sh
sudo sh install.sh outside
sudo sh install.sh iran
```

۳. برای هر جفت، در zone دامنه‌ات یک A برای ns1 به IPv4 عمومی خارج (DNS only) و یک NS برای tun1 به ns1.example.com بساز. دامنهٔ تونل در این مثال tun1.example.com است. ورودی TCP و UDP روی پورت ۵۳ خارج باید در دسترس باشد. این کار و انتقال کلیدها را پیش از قطع دسترسی مدیریتی انجام بده.

۴. روی خارج پروفایل بساز. outside و سپس master یا helper را انتخاب کن. پس از اتمام، فایل pair.json را به‌صورت خصوصی به ایران همان جفت منتقل کن. برای اولین نصب با دو سرور نقش هر دو master است.

```sh
sudo -u dnsbond /usr/bin/python3 /opt/dns-bond/setup_node.py /var/lib/dns-bond/node
```

۵. روی ایران، فایل pair.json و فایل resolverها را در محلی قابل خواندن برای dnsbond بگذار. مثال زیر فرض می‌کند هر دو در پوشهٔ فعلی هستند. بعد دستور ساخت پروفایل را اجرا کن، iran و نقش را انتخاب کن و مسیر کامل دو فایل را وارد کن. برای آزمایش اولیه بدون کمکی در دو پرسش کمکی‌ها علامت - بزن. پورت SOCKS5 را خودت تعیین می‌کنی.

```sh
sudo install -o dnsbond -g dnsbond -m 600 pair.json /var/lib/dns-bond/pair.json
sudo install -o dnsbond -g dnsbond -m 600 resolvers.txt /var/lib/dns-bond/resolvers.txt
sudo -u dnsbond /usr/bin/python3 /opt/dns-bond/setup_node.py /var/lib/dns-bond/node
```

۶. یک‌بار روی یک ماشین مطمئن با OpenSSL گواهی بساز. دستور را از پوشهٔ بستهٔ بازشده اجرا کن:

```sh
sh app/certificates.sh bond-keys
```

از پوشهٔ bond-keys سه فایل ca.crt و entry.crt و entry.key را به مستر ایران و سه فایل ca.crt و exit.crt و exit.key را به مستر خارج ببر. ca.key فقط روی ماشین مدیریت بماند. روی هر مستر از پوشه‌ای که سه فایل مربوط به آن را گذاشتی، دستور متناسب را بزن:

```sh
# مستر ایران
sudo install -o dnsbond -g dnsbond -m 600 ca.crt entry.crt entry.key /var/lib/dns-bond/node/
# مستر خارج
sudo install -o dnsbond -g dnsbond -m 600 ca.crt exit.crt exit.key /var/lib/dns-bond/node/
```

۷. اول روی خارج و بعد روی ایران سرویس را روشن کن:

```sh
sudo systemctl enable --now dns-bond
sudo systemctl status dns-bond --no-pager
```

روی مستر ایران از 127.0.0.1 و پورت انتخابی برای outbound SOCKS استفاده کن. برای مثال اگر پورت 1080 بود:

```sh
curl --noproxy '' --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

این تست در صورت دسترسی به سایت، IP خروجی مستر خارج را نشان می‌دهد. راهنمای جفت‌های کمکی و پایش در app/README.md، از بخش دوم به بعد است. نصب آنلاین موتور در آن راهنما را برای این بسته رد کن.
