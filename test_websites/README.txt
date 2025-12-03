1. Open Terminal

2. Navigate to the test_websites folder:
   cd "/Users/hussain/Documents/CYSE 610/CYSE610Project/test_websites"

3. Start the Python HTTP server:
   python3 -m http.server 8080




--------------------------------------------------
TEST PAGE LINKS
--------------------------------------------------

PHISHING PAGES (Should be flagged):

1. Fake PayPal Login
   http://localhost:8080/fake_paypal.html
   - Typosquatting (PayPaI instead of PayPal)
   - Asks for SSN and credit card at login
   - Urgent warning messages and countdown timer
   - Hidden form fields capturing browser info

2. Fake Bank Login
   http://localhost:8080/fake_bank.html
   - Misspelled bank name (Chase Banck)
   - Asks for ATM PIN, account/routing numbers
   - Popup requesting mother's maiden name
   - Fake security badges

3. Fake Tech Support Scam
   http://localhost:8080/fake_tech_support.html
   - Fake virus/malware warnings
   - Fake Microsoft branding
   - Fake scan results and infection meter
   - Requests personal info for "remote access"


LEGITIMATE PAGE (Should NOT be flagged):

4. Green Valley Organic Market
   http://localhost:8080/legit_store.html
   - Proper meta descriptions
   - Favicon present
   - Social media links
   - Copyright information
   - No hidden fields or external form submissions
   - Professional layout and design


--------------------------------------------------
EXPECTED RESULTS
--------------------------------------------------

| Page              | Expected Result | Detection Type |
|-------------------|-----------------|----------------|
| fake_paypal.html  | PHISHING        | URL + Page     |
| fake_bank.html    | PHISHING        | URL + Page     |
| fake_tech_support | PHISHING        | URL + Page     |
| legit_store.html  | LEGITIMATE      | URL + Page     |


--------------------------------------------------
NOTES
--------------------------------------------------

- Make sure the browser extension is installed and enabled
- After making changes to extension code, reload the extension
  at chrome://extensions/
- The extension analyzes both URL features and page content
- Confidence percentages combine URL (80%) and Page (20%) analysis


