# Import necessary libraries
import streamlit as st
import pickle
import numpy as np
from urllib.parse import urlparse
import ipaddress
import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import whois
import urllib

# URL shortening services for detecting TinyURL
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# Feature Extraction Function
def check_website_accessibility(url):
    try:
        response = requests.get(url, timeout=10)  # Timeout after 10 seconds
        if response.status_code == 200:
            # If the page is accessible, you can also parse the HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else 'No title found'
            return True, f"Website is accessible. Title: '{title}'"
        else:
            return False, f"Website returned status code: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return False, f"Website is not accessible. Error: {str(e)}"

def iframe(url):
    try:
        response = requests.get(url, timeout=5)  # Timeout after 5 seconds
        if response.status_code == 200:
            if re.findall(r"<iframe>|<frameBorder>", response.text):
                return 0  # Phishing (iframe present)
            else:
                return 1  # Legitimate (no iframe)
        else:
            return 1  # Assume legitimate if non-200 status code
    except requests.exceptions.RequestException:
        return 1  # Default to legitimate if connection fails

def featureExtraction(url):
    features = []
    st.write("Extracting features...")  # Inform the user about feature extraction

    # 1. Checks for IP address in the URL
    try:
        ipaddress.ip_address(url)
        features.append(1)  # Have_IP
        st.write("Feature 1: IP address found in the URL.")
    except:
        features.append(0)
        st.write("Feature 1: No IP address found in the URL.")

    # 2. Checks for "@" symbol in the URL
    has_at = 1 if "@" in url else 0
    features.append(has_at)
    st.write(f"Feature 2: '@' symbol {'found' if has_at else 'not found'} in the URL.")

    # 3. Length of the URL
    url_length = 1 if len(url) >= 54 else 0
    features.append(url_length)
    st.write(f"Feature 3: URL length is {'greater than or equal to 54' if url_length else 'less than 54'}.")

    # 4. Depth of URL (number of '/' in URL)
    url_depth = len(urlparse(url).path.split('/')) - 1
    features.append(url_depth)
    st.write(f"Feature 4: URL depth is {url_depth}.")

    # 5. Redirection "//" in the URL
    pos = url.rfind('//')
    redirection = 1 if pos > 7 else 0
    features.append(redirection)
    st.write(f"Feature 5: Redirection {'found' if redirection else 'not found'} in the URL.")

    # 6. "https" in domain part
    https_domain = 1 if 'https' in urlparse(url).netloc else 0
    features.append(https_domain)
    st.write(f"Feature 6: HTTPS {'present' if https_domain else 'not present'} in the domain.")

    # 7. TinyURL detection
    tinyurl_found = 1 if re.search(shortening_services, url) else 0
    features.append(tinyurl_found)
    st.write(f"Feature 7: URL {'is' if tinyurl_found else 'is not'} a TinyURL.")

    # 8. Prefix or Suffix "-" in the domain
    prefix_suffix = 1 if '-' in urlparse(url).netloc else 0
    features.append(prefix_suffix)
    st.write(f"Feature 8: Prefix or suffix '-' {'found' if prefix_suffix else 'not found'} in the domain.")

    # Domain-based features (WHOIS and Web traffic)
    try:
        domain = urlparse(url).netloc
        domain_name = whois.whois(domain)
        dns = 0
        st.write("Feature 9: WHOIS lookup successful.")
    except:
        dns = 1
        st.write("Feature 9: WHOIS lookup failed.")
    features.append(dns)  # DNS_Record

    # 9. Web Traffic from Alexa
    try:
        url_encoded = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url_encoded).read(), "xml").find("REACH")['RANK']
        web_traffic = 1 if int(rank) < 100000 else 0
        features.append(web_traffic)
        st.write(f"Feature 10: Alexa rank {'is less than 100,000' if web_traffic else 'is greater than or equal to 100,000'}.")
    except:
        features.append(1)  # Phishing if no rank is found
        st.write("Feature 10: Unable to retrieve Alexa rank, defaulting to phishing.")

    # 10. Domain Age
    try:
        if dns == 0:
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            age_of_domain = abs((expiration_date - creation_date).days)
            domain_age = 1 if (age_of_domain / 30) < 6 else 0
            features.append(domain_age)
            st.write(f"Feature 11: Domain age is {'less than 6 months' if domain_age else 'greater than or equal to 6 months'}.")
        else:
            features.append(1)
            st.write("Feature 11: Unable to assess domain age, defaulting to phishing.")
    except:
        features.append(1)
        st.write("Feature 11: Error in domain age calculation, defaulting to phishing.")

    # 11. End period of Domain (in months)
    try:
        if dns == 0:
            expiration_date = domain_name.expiration_date
            today = datetime.now()
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            end_time = abs((expiration_date - today).days)
            domain_end = 1 if (end_time / 30) < 6 else 0
            features.append(domain_end)
            st.write(f"Feature 12: Domain end time is {'less than 6 months' if domain_end else 'greater than or equal to 6 months'}.")
        else:
            features.append(1)
            st.write("Feature 12: Unable to assess domain end time, defaulting to phishing.")
    except:
        features.append(1)
        st.write("Feature 12: Error in domain end time calculation, defaulting to phishing.")

    # 12. iFrame Redirection
    iframe_result = iframe(url)
    features.append(iframe_result)
    st.write(f"Feature 13: iFrame {'found' if iframe_result == 0 else 'not found'} in the URL.")

    # 13. Mouse Over presence
    try:
        mouse_over = 1 if "onmouseover" in requests.get(url).text else 0
        features.append(mouse_over)
        st.write(f"Feature 14: Mouse over presence {'detected' if mouse_over else 'not detected'}.")
    except:
        features.append(1)
        st.write("Feature 14: Error checking mouse over presence, defaulting to not detected.")

    # 14. Right Click presence
    try:
        right_click = 1 if "contextmenu" in requests.get(url).text else 0
        features.append(right_click)
        st.write(f"Feature 15: Right click presence {'detected' if right_click else 'not detected'}.")
    except:
        features.append(1)
        st.write("Feature 15: Error checking right click presence, defaulting to not detected.")

    # 15. Web Forward presence
    try:
        web_forward = 1 if "forward" in requests.get(url).text else 0
        features.append(web_forward)
        st.write(f"Feature 16: Web forward presence {'detected' if web_forward else 'not detected'}.")
    except:
        features.append(1)
        st.write("Feature 16: Error checking web forward presence, defaulting to not detected.")

    return features

# Streamlit App
def main():
    st.title("Phishing URL Detection")
    st.write("Enter a URL below to check if it's legitimate or phishing.")

    # URL input from user
    url = st.text_input("Enter the URL:")

    if st.button("Check URL"):
        if url:
            # Extract features from the input URL
            features = featureExtraction(url)
            features = np.array(features).reshape(1, -1)

            # Load the pre-trained model
            loaded_model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))

            # Make the prediction
            st.write("Making prediction...")  # Inform the user about the prediction process
            prediction = loaded_model.predict(features)

            # Show the result
            if prediction[0] == 1:
                status,text=check_website_accessibility(url)
                print(status,text)
                if status:
                    st.success("The URL is legitimate.")
                else:                    
                    st.error("The URL is likely a phishing site.")
            else:
                st.success("The URL is legitimate.")

            # Show disclaimer
            st.write("**Disclaimer:** The model has an accuracy of 83%, so results may not be 100% accurate.")
        else:
            st.warning("Please enter a URL.")

if __name__ == "__main__":
    main()
