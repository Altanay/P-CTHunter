# P-CTHunter
<p align="center">
  <img src="assets/logo_pacth.svg" width="120" alt="P@CTH logo">
</p>

# P@CTH Pentest Scanner (POC-only)

```bash
pip install -r requirements.txt
python -m playwright install chromium

# hızlı tarama
python main.py quick https://hedef.tld --rate-ms 400

# login sonrası örnek
python main.py scan https://hedef.tld \
  --login-url https://hedef.tld/login \
  --auth-user tester --auth-pass S3cr3t!
