import streamlit as st
import datetime
import re
from urllib.parse import urlparse
import requests
import whois
import tldextract
import validators

# --- Constants for Phishing Detection ---

SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.click', '.live', '.shop', '.site', '.tk', '.ml', '.ga', '.cf', '.gq', 
    '.bid', '.trade', '.party', '.loan', '.download', '.account', '.win'
]

PHISHING_KEYWORDS = [
    'login', 'verify', 'secure', 'update', 'account', 'bank', 'confirm', 'signin', 'webscr', 'password', 'portal'
]

POPULAR_BRANDS = [
    'google', 'paypal', 'microsoft', 'facebook', 'instagram', 'amazon', 'apple', 'netflix', 'ebay', 'twitter',
    'whatsapp', 'telegram', 'linkedin', 'outlook', 'appleid', 'samsung', 'vodafone', 'att', 'tmobile', 'bankofamerica'
]

RISK_THRESHOLDS = {
    'low': 20,
    'medium': 50
}

MAX_NORMAL_URL_LENGTH = 70
MAX_NORMAL_SUBDOMAINS = 3
ESTABLISHED_DOMAIN_AGE_DAYS = 180

# --- Helper Functions ---

def get_domain_from_url(url):
    extracted = tldextract.extract(url)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return None

def check_whois_age(domain):
    score = 0
    reasons = []
    if not domain:
        reasons.append("N/A: Não foi possível extrair o domínio para verificação WHOIS.")
        return score, reasons

    try:
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date

            age_days = (datetime.datetime.now() - creation_date).days

            if age_days < ESTABLISHED_DOMAIN_AGE_DAYS:
                score += 30
                reasons.append(f"Risco ALTO: Domínio muito recente ({age_days} dias). Criado em {creation_date.strftime('%Y-%m-%d')}.")
            elif age_days < 365:
                score += 10
                reasons.append(f"Risco MODERADO: Domínio relativamente recente ({age_days} dias). Criado em {creation_date.strftime('%Y-%m-%d')}.")
            else:
                reasons.append(f"Seguro: Domínio estabelecido (criado em {creation_date.strftime('%Y-%m-%d')}).")
        else:
            score += 20
            reasons.append("Risco MÉDIO: Data de criação do domínio não encontrada no WHOIS.")
    except Exception as e:
        score += 15
        reasons.append(f"Risco MODERADO: Falha na consulta WHOIS ({e}). Não foi possível verificar a idade do domínio.")

    return score, reasons

def check_ssl_certificate(url):
    score = 0
    reasons = []

    if not url.startswith('https://'):
        score += 40
        reasons.append("Risco ALTO: Ausência de certificado SSL (URL não usa HTTPS).")
        return score, reasons

    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        if response.status_code == 200:
            reasons.append("Seguro: Certificado SSL presente (HTTPS).")
            reasons.append("Informação: Detalhes do SSL (emissor, validade) não verificados a fundo nesta etapa.")
        else:
            score += 20
            reasons.append(f"Risco MÉDIO: HTTPS presente, mas falha na conexão ou status inesperado ({response.status_code}).")
    except requests.exceptions.SSLError:
        score += 50
        reasons.append("Risco ALTO: Erro no certificado SSL (inválido ou auto-assinado).")
    except requests.exceptions.ConnectionError as e:
        score += 30
        reasons.append(f"Risco ALTO: Falha ao conectar (mesmo com HTTPS). Erro: {e}")
    except requests.exceptions.Timeout:
        score += 15
        reasons.append("Risco MÉDIO: Requisição HTTPS expirou.")
    except Exception as e:
        score += 10
        reasons.append(f"Risco BAIXO: Erro inesperado ao verificar SSL ({e}).")

    return score, reasons

def analyze_url_structure(url):
    score = 0
    reasons = []
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path

    if len(url) > MAX_NORMAL_URL_LENGTH:
        score += 10
        reasons.append(f"Risco BAIXO: URL muito longa ({len(url)} caracteres).")

    if domain.count('-') > 3:
        score += 10
        reasons.append("Risco BAIXO: Muitos hífens no nome do domínio.")

    extracted = tldextract.extract(url)
    subdomains_count = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    if subdomains_count > MAX_NORMAL_SUBDOMAINS:
        score += 15
        reasons.append(f"Risco MÉDIO: Muitos subdomínios ({subdomains_count}).")

    if re.search(r'\d', extracted.domain):
        score += 15
        reasons.append("Risco MÉDIO: Presença de números no nome do domínio principal.")

    for keyword in PHISHING_KEYWORDS:
        if keyword in domain.lower() or keyword in path.lower():
            score += 20
            reasons.append(f"Risco ALTO: Palavra-chave suspeita encontrada na URL ('{keyword}').")
            break

    return score, reasons

def check_suspicious_tld(url):
    score = 0
    reasons = []
    extracted = tldextract.extract(url)
    tld = f".{extracted.suffix}"
    if tld.lower() in SUSPICIOUS_TLDS:
        score += 25
        reasons.append(f"Risco ALTO: TLD suspeito encontrado ('{tld}').")
    return score, reasons

def check_typosquatting(url):
    score = 0
    reasons = []
    domain = get_domain_from_url(url)
    if not domain:
        reasons.append("N/A: Não foi possível extrair o domínio para verificação de typosquatting.")
        return score, reasons

    extracted = tldextract.extract(url)
    domain_without_tld = extracted.domain.lower()

    for brand in POPULAR_BRANDS:
        if brand in domain_without_tld and brand != domain_without_tld:
            score += 40
            reasons.append(f"Risco ALTO: Potencial typosquatting detectado (domínio '{domain_without_tld}' similar a '{brand}').")
            return score, reasons
        
        # Heurística de substituição básica (0 -> o, 1 -> i, l -> i)
        norm_domain = domain_without_tld.replace('0','o').replace('1','i').replace('l','i')
        if any(char in domain_without_tld for char in ['0', '1', 'l']) and brand in norm_domain:
             score += 30
             reasons.append(f"Risco ALTO: Potencial typosquatting com substituição de caracteres.")
             return score, reasons

    return score, reasons

def check_redirects(url):
    score = 0
    reasons = []
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        if response.history:
            original_domain = urlparse(url).netloc
            final_domain = urlparse(response.url).netloc
            if original_domain != final_domain:
                score += 35
                reasons.append(f"Risco ALTO: Redireciona para um domínio diferente: '{final_domain}'.")
            else:
                reasons.append("Informação: Redirecionamento interno detectado.")
        else:
            reasons.append("Seguro: Nenhum redirecionamento externo detectado.")
    except requests.exceptions.RequestException as e:
        score += 10
        reasons.append(f"Risco BAIXO: Falha ao verificar redirecionamentos ({e}).")
    return score, reasons

def calculate_phishing_score(url):
    if not validators.url(url):
        return 100, ["ERRO: A URL fornecida é inválida."]
    
    total_score = 0
    all_reasons = []
    
    domain = get_domain_from_url(url)
    
    s1, r1 = check_whois_age(domain)
    s2, r2 = check_ssl_certificate(url)
    s3, r3 = analyze_url_structure(url)
    s4, r4 = check_suspicious_tld(url)
    s5, r5 = check_typosquatting(url)
    s6, r6 = check_redirects(url)
    
    total_score = min(s1 + s2 + s3 + s4 + s5 + s6, 100)
    all_reasons.extend(r1 + r2 + r3 + r4 + r5 + r6)
    
    return total_score, all_reasons

def get_risk_level(score):
    if score >= RISK_THRESHOLDS['medium']: return "ALTO"
    elif score >= RISK_THRESHOLDS['low']: return "MÉDIO"
    return "BAIXO"

# --- Streamlit App Layout ---

st.set_page_config(page_title="Analisador de Risco de Phishing", layout="centered")
st.title("🕵️‍♂️ Analisador de Risco de Phishing de URL")
st.markdown("Digite uma URL para avaliar seu risco. **Esta é uma ferramenta auxiliar.**")

user_url = st.text_input("URL para análise:", "https://www.example.com")

if st.button("Analisar URL"):
    if user_url:
        with st.spinner('Analisando...'):
            score, reasons = calculate_phishing_score(user_url)
            risk_level = get_risk_level(score)

        st.subheader("--- Resultado ---")
        st.write(f"**URL:** {user_url}")
        st.write(f"**Score:** {score}/100")
        
        color = 'red' if risk_level == 'ALTO' else ('orange' if risk_level == 'MÉDIO' else 'green')
        st.markdown(f"**Nível de Risco:** <span style='color:{color}; font-weight:bold;'>{risk_level}</span>", unsafe_allow_html=True)

        st.subheader("--- Motivos ---")
        for reason in reasons:
            st.markdown(f"- {reason}")

        if score >= RISK_THRESHOLDS['medium']:
            st.error("Recomendação: **NÃO clique nesta URL.**")
        elif score >= RISK_THRESHOLDS['low']:
            st.warning("Recomendação: **Prossiga com cautela.**")
        else:
            st.success("Recomendação: **Parece seguro.**")
    else:
        st.warning("Por favor, digite uma URL.")
