import streamlit as st
import numpy as np
import pandas as pd
import joblib
from urllib.parse import urlparse
import re
from googlesearch import search
from tldextract import extract as tld_extract
from tld import get_tld


# Function to get the length of the URL
def get_url_length(url):
    return len(url)

# Function to extract domain from the URL
def get_domain(url):
    try:
        res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
        domain = res.parsed_url.netloc
    except :
        domain = None
    return domain

# Function to get the length of the domain from the URL
def get_domain_length(url):
    try:
        res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
        domain = len(res.parsed_url.netloc)
    except:
        domain = 0
    return domain


# Function to check if the URL is abnormal
def get_abnormal_url(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if hostname:
        hostname = str(hostname)
        match = re.search(hostname, url)
        if match:
            return 0
        else: 
            return 1
    return 0

# Function to check if the URL contains an IP address
def get_having_ip_address(url: str) -> int:
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

# Function to count the number of special characters in the URL
def get_sum_count_special_characters(url: str) -> int:
    special_chars = ['@','?','-','=','.','#','%','+','$','!','*',',','//']

    num_special_chars = sum(char in special_chars for char in url)
    return num_special_chars

# Function to check if the URL is secured with HTTPS
def get_httpSecured(url: str) -> int:
    htp = urlparse(url).scheme
    match = str(htp)
    if match == 'https':
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

#Function to count the number of digits in the URL
def get_digit_count(url: str) -> int:
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

# Function to count the number of letters in the URL
def get_letter_count(url: str) -> int:
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

# Function to check if the URL uses a URL shortening service
def get_has_shortening_service(url):
    pattern = re.compile(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                         r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                         r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                         r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                         r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                         r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                         r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                         r'tr\.im|link\.zip\.net')
    match = pattern.search(url)
    return int(bool(match))


# Function to check if the URL is secured with HTTPS
def get_secure_http(url):
    scheme = urlparse(url).scheme
    if scheme == 'https':
        return 1
    else:
        return 0

# Function to check if the URL contains an IP address
def get_have_ip_address(url):
    pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.' \
              r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|' \
              r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.' \
              r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|' \
              r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)' \
              r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|' \
              r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)|' \
              r'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)'

    match = re.search(pattern, url)
    if match:
        return 1
    else:
        return 0

# Function to check if the URL is indexed by Google
def get_google_index(url):
    site = search(url, 5)
    return 1 if site else 0


# Loading the machine learning model
model = joblib.load('./Models/classifier5_model.joblib')

# Setting the title of the Streamlit app
st.title('Is the URL Malicious')

# Function to extract features from the URL
def get_url(url):
    url = url.replace('www.', '')
    url_len = len(url)
    letters_count = get_letter_count(url)
    digits_count  = get_digit_count(url)
    special_chars_count = get_sum_count_special_characters(url)
    shortened = get_has_shortening_service(url)
    abnormal = get_abnormal_url(url)
    secure_https = get_httpSecured(url)
    have_ip = get_having_ip_address(url)
    index_google = get_google_index(url)
    domain_length = get_domain_length(url)
    
    parsed_url  = urlparse(url)
    
    return {
        'url_len': url_len,
        'abnormal_url': abnormal,
        'use_of_ip_address': have_ip,
        'sum_count_special_chars': special_chars_count,
        'https': secure_https,
        'digits': digits_count,
        'letters': letters_count,
        'Shortining_Service': shortened,
        'google_index' : index_google,
        'domain_length' : domain_length
    }

# Function to display the results based on the features extracted
def result(numerical_values):
    st.write('Due to following reasons:')
    st.write('URL Length: '  + str(numerical_values['url_len']))
    st.write('Abnormal URL: ' + str(numerical_values['abnormal_url']))
    st.write('Use of IP: ' + str(numerical_values['use_of_ip_address']))
    st.write('Special Characters: ' + str(numerical_values['sum_count_special_chars']))
    st.write('URL With https: '  + str(numerical_values['https']))
    st.write('Use of Digits: ' + str(numerical_values['digits']))
    st.write('Letters count: '  + str(numerical_values['letters']))
    st.write('Shortening URL service: ' + str(numerical_values['Shortining_Service']))
    st.write('Google Index: ' + str(numerical_values['google_index']))
    st.write('Domain Length: '  + str(numerical_values['domain_length']))
    return

# Function to predict whether the URL is malicious or not
def model1_predict(url):
    if url != "":
        #if validators.url(url):
            numerical_values = get_url(url)
            prediction_int = model.predict(np.array(list(numerical_values.values())).reshape(1, -1))[0]
            if prediction_int == 0:
                #st.write("letters count" + numerical_values.letters_count)
                st.success('URL is not malicious')
            else: 
                st.error('URl is a malicious') 

        #else: 
            #st.error('Not a valid URL !')
    else: 
        st.error('Please enter URL !')

# Creating a form to input the URL and submit for prediction
with st.form("my_form"):
    url= st.text_input(label="Enter the URL", placeholder="www.example.com")
    submitted = st.form_submit_button("Predict")
    if submitted:
       model1_predict(url)

