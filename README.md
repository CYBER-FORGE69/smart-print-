# Pay-per-print server
Run: `pip install -r requirements.txt && SECRET_KEY=change-me python app.py`
1. Open `http://<pc-ip>:5000/setup` and create the first admin, then set your security code.
2. Admin panel `/admin`: choose printer, price, payment mode, show the form QR, add admins, turn on 2-step login.
3. Printer connection (USB, WiFi, Bluetooth, Ethernet): add the printer in your OS (CUPS on Linux/Pi, Settings on Windows). It then appears in the admin list.
4. Real payments: set mode to Razorpay, enter keys, and in the Razorpay dashboard add webhook `https://<your-domain>/webhook/razorpay` for event `qr_code.credited` with the same secret. HTTPS is required.
Test mode shows a "simulate payment" button; switch to Razorpay before real use.

## Security built in
- Logins: 5 wrong passwords or 2FA codes lock that account/IP for 10 minutes; 15-minute idle logout; changing a password or security code logs that admin out everywhere else.
- Security code (PIN/password) is checked on the server for payment settings, account changes, adding admins and turning off 2FA; 5 wrong tries lock it for 5 minutes.
- Passwords need 10+ characters with letters and numbers. Passwords and codes are stored hashed; Razorpay keys are encrypted (keys in `.secret_key` and `.enc_key`, owner-only; back them up, keep them out of git).
- CSRF tokens, strict Content-Security-Policy, no-framing, no-sniff, no-store on admin pages. Set `HTTPS=1` when serving over HTTPS (secure cookies + HSTS).
- Uploads: real file-type check, password-protected PDFs and PDFs with scripts rejected, page limit, 10 uploads per 10 minutes per IP, files deleted after printing or expiry.
- Payments: signed webhooks, exact amount match, duplicate webhooks ignored, late payments on expired jobs flagged in the log.
- Security log in the admin panel records logins, failures, setting changes and payments.

## Running it for real
- First run prints a one-time setup code in the console; enter it on `/setup` (or set `SETUP_TOKEN`).
- Don't use `python app.py` on the internet. Use `waitress-serve --port 5000 app:app` (Windows) or `gunicorn -w 1 -b 127.0.0.1:5000 app:app` (Linux), with `-w 1` so lockouts stay consistent, behind HTTPS. Set `HTTPS=1`, and `PROXY=1` only if a reverse proxy sits in front.
- Run `pip install pip-audit && pip-audit -r requirements.txt` now and then to check dependencies.
