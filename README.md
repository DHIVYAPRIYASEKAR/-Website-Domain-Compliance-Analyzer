🌐 Website Domain & Compliance Analyzer

A powerful Python-based CLI tool to evaluate a website's domain information, DNS records, security compliance, and content-related policy markers. Ideal for auditing domains for legal and privacy best practices.

---

## 🚀 Features

- 🔎 Extracts domain name and WHOIS ownership details
- 🌐 Checks for DNS records (A, MX, NS, TXT, etc.)
- ✅ Scans content for privacy policy, data protection, cookies, etc.
- 📄 Flags for legal compliance (fraud, defamation, copyright, GDPR)
- 🕵️ Detects phone numbers, emails, and address info from website content
- 🔗 Collects social media profile links
- 🔒 Analyzes SSL/HTTPS mentions to assess secure vs. weak connection mentions
- 💸 Estimates domain pricing in INR and USD
- 🖥️ Beautiful CLI output using `rich` and optional `pyfiglet`

---

## 📦 Requirements

- Python 3.7+
- Packages (install via pip):

```bash
pip install tldextract whois requests beautifulsoup4 rich dnspython pyfiglet
🛠️ How to Use
Clone the repository:

bash
Copy
Edit
git clone https://github.com/yourusername/domain-compliance-analyzer.git
cd domain-compliance-analyzer
Run the tool:

bash
Copy
Edit
python analyzer.py
Follow the prompt to enter a URL or DNS name (e.g., https://example.com or example.com).

🧪 Example Output
nginx
Copy
Edit
Enter website URL or DNS name: https://example.com

📄 Compliance Status
✓ Privacy Policy
✗ Cookie Policy
✓ Security & Data Protection
...

📞 Contact Information
- Emails: info@example.com
- Phone Numbers: +1-800-555-1234

🔗 Social Media Links
- https://linkedin.com/company/example
- https://twitter.com/example

🔒 Vulnerable Status
Strong Connections: 80%
Weak Connections: 20%

🧾 Domain Pricing
example.com
Preferred domain pricing: ₹1084.66 / year (approx. $12.99)
📁 Project Structure
Copy
Edit
analyzer.py
README.md
LICENSE
🧑‍💻 Author
Developed by Dhivyapriya
🔗 https://github.com/DHIVYAPRIYASEKAR

📄 License
This project is licensed under the MIT License.
See the LICENSE file for more information.

❤️ Contributions
Contributions are welcome! Feel free to:

Fork the repo

Add features or bug fixes

Create a pull request

💡 Future Improvements
Add GUI support using tkinter or streamlit

Export results to JSON or CSV

Integrate more comprehensive compliance frameworks (GDPR, CCPA scanners)
