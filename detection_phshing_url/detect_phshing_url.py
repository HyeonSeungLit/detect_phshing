import re
import requests
from bs4 import BeautifulSoup
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# URL 분석 함수
def analyze_url(url):
    features = {
        'length': len(url),
        'num_special_chars': len(re.findall(r'\W', url)),
        'num_digits': len(re.findall(r'\d', url)),
        'has_ip': int(re.match(r'^\d+\.\d+\.\d+\.\d+$', url) is not None),
        # 의심스러운 도메인 이름 분석 추가
        'suspicious_domain': int(any(keyword in url for keyword in ['login', 'secure', 'update', 'bank']))
    }
    return features

def analyze_page_content(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        features = {
            'num_forms': len(soup.find_all('form')),
            'num_iframes': len(soup.find_all('iframe')),
            'has_login_form': int(bool(soup.find('input', {'type': 'password'}))),
            # 의심스러운 키워드 분석 추가
            'suspicious_keywords': int(any(keyword in soup.text.lower() for keyword in ['password', 'credit card', 'social security']))
        }
        return features
    except requests.exceptions.RequestException:
        return None

# 데이터셋 생성 함수 (예시 데이터)
def create_dataset():
    X, y = [], []
    # URL과 페이지 특징을 추출하여 데이터셋 생성
    phishing_urls = ['http://phishingsite.com/login', 'http://secure-update.com']
    legitimate_urls = ['http://example.com', 'http://safe-site.org']
    
    for url in phishing_urls:
        url_features = analyze_url(url)
        page_features = analyze_page_content(url)
        if page_features:
            features = {**url_features, **page_features}
            X.append([features[feature] for feature in sorted(features)])
            y.append(1)
    
    for url in legitimate_urls:
        url_features = analyze_url(url)
        page_features = analyze_page_content(url)
        if page_features:
            features = {**url_features, **page_features}
            X.append([features[feature] for feature in sorted(features)])
            y.append(0)
    
    return X, y

def train_model():
    X, y = create_dataset()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))
    
    joblib.dump(model, 'phishing_model.pkl')

# 피싱 사이트 여부 판단 함수
def is_phishing_site(url, model):
    url_features = analyze_url(url)
    page_features = analyze_page_content(url)
    
    if not page_features:
        return False
    
    features = {**url_features, **page_features}
    feature_vector = [features[feature] for feature in sorted(features)]
    
    prediction = model.predict([feature_vector])[0]
    return prediction == 1

# 메인 함수
def main():
    train_model()  # 처음 실행 시 모델 학습
    model = joblib.load('phishing_model.pkl')
    
    url = input("Enter the URL to check: ")
    if is_phishing_site(url, model):
        print("Warning: This site is likely a phishing site!")
    else:
        print("This site appears to be safe.")

if __name__ == "__main__":
    main()
