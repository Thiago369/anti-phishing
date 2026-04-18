
"""### Projeto de Análise de Risco de Phishing de URL

Este notebook Python tem como objetivo receber uma URL do usuário e gerar um "score de risco de phishing" (de 0 a 100), acompanhado de uma explicação detalhada dos motivos que contribuíram para o score. A análise será baseada em diversos fatores, incluindo:

1.  **Idade do Domínio (WHOIS)**: Domínios recém-criados podem indicar maior risco.
2.  **Certificado SSL**: Presença, emissor e validade do certificado. Certificados muito recentes também podem ser um fator de risco moderado.
3.  **Estrutura da URL**: Análise de características como comprimento, número de hífens, subdomínios excessivos, uso de números no domínio e presença de palavras-chave suspeitas.
4.  **TLD (Top-Level Domain) Suspeito**: Verificação contra uma lista de TLDs comumente associados a golpes de phishing.
5.  **Typosquatting**: Comparação do domínio com nomes de marcas famosas para identificar possíveis tentativas de falsificação.
6.  **Redirecionamentos**: Verificação se a URL redireciona para um domínio diferente do original.

Ao final da análise, será exibido o score de risco, uma classificação (Baixo, Médio, Alto) e uma lista de todos os motivos identificados, juntamente com uma recomendação final.
"""







import datetime
import re
from urllib.parse import urlparse
import requests
import tldextract
import whois

# --- Constants for Phishing Detection ---

# Suspicious TLDs (Top-Level Domains)
SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.click', '.live', '.shop', '.site', '.tk', '.ml', '.ga', '.cf', '.gq', # Free domains
    '.bid', '.trade', '.party', '.loan', '.download', '.account', '.win'
]

# Keywords often found in phishing URLs
PHISHING_KEYWORDS = [
    'login', 'verify', 'secure', 'update', 'account', 'bank', 'confirm', 'signin', 'webscr', 'password', 'portal'
]

# Popular brand names for typosquatting checks
POPULAR_BRANDS = [
    'google', 'paypal', 'microsoft', 'facebook', 'instagram', 'amazon', 'apple', 'netflix', 'ebay', 'twitter',
    'whatsapp', 'telegram', 'linkedin', 'outlook', 'appleid', 'samsung', 'vodafone', 'att', 'tmobile', 'bankofamerica'
]

# Thresholds for risk scoring
RISK_THRESHOLDS = {
    'low': 20,
    'medium': 50
}

# Max URL length for typical legitimate sites
MAX_NORMAL_URL_LENGTH = 70

# Max subdomains considered normal
MAX_NORMAL_SUBDOMAINS = 3

# Min days for a domain to be considered 'established'
ESTABLISHED_DOMAIN_AGE_DAYS = 180

def get_domain_from_url(url):
    """Extracts the main domain (e.g., example.com from www.example.com/path) from a URL."""
    extracted = tldextract.extract(url)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return None

def check_whois_age(domain):
    """Checks the WHOIS record for domain creation date and calculates age.
       Returns risk score and reasons related to domain age."""
    score = 0
    reasons = []
    if not domain:
        reasons.append("N/A: Não foi possível extrair o domínio para verificação WHOIS.")
        return score, reasons

    try:
        w = whois.whois(domain)

        if w.creation_date:
            # whois.whois can return a list of dates, take the first one
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date

            age_days = (datetime.datetime.now() - creation_date).days

            if age_days < ESTABLISHED_DOMAIN_AGE_DAYS: # e.g., less than 6 months
                score += 30
                reasons.append(f"Risco ALTO: Domínio muito recente ({age_days} dias). Criado em {creation_date.strftime('%Y-%m-%d')}.")
            elif age_days < 365: # e.g., less than 1 year
                score += 10
                reasons.append(f"Risco MODERADO: Domínio relativamente recente ({age_days} dias). Criado em {creation_date.strftime('%Y-%m-%d')}.")
            else:
                reasons.append(f"Seguro: Domínio estabelecido (criado em {creation_date.strftime('%Y-%m-%d')}).")
        else:
            score += 20
            reasons.append("Risco MÉDIO: Data de criação do domínio não encontrada no WHOIS.")

    except Exception as e:
        score += 15 # Moderate risk if WHOIS lookup fails
        reasons.append(f"Risco MODERADO: Falha na consulta WHOIS ({e}). Não foi possível verificar a idade do domínio.")

    return score, reasons

def check_ssl_certificate(url):
    """Checks for SSL certificate presence. Note: Detailed SSL info (issuer, validity, age)
       is complex to get directly with 'requests' without deeper 'ssl' module usage.
       This function primarily checks for HTTPS and basic connectivity."""
    score = 0
    reasons = []

    if not url.startswith('https://'):
        score += 40
        reasons.append("Risco ALTO: Ausência de certificado SSL (URL não usa HTTPS).")
        return score, reasons

    try:
        # Try to make a HEAD request to avoid downloading content, just check connection
        response = requests.head(url, timeout=5, allow_redirects=True)
        if response.status_code == 200:
            reasons.append("Seguro: Certificado SSL presente (HTTPS).")
            # More advanced SSL checks would go here, requiring 'ssl' and 'socket' modules
            # For example, to get issuer and validity, you'd need to connect to the socket,
            # wrap it with SSL, and then inspect the certificate.
            # This is beyond a simple 'requests' call.
            reasons.append("Informação: Detalhes do SSL (emissor, validade) não verificados a fundo nesta etapa.")
        else:
            # If HTTPS is used but request fails, it might still indicate issues
            score += 20
            reasons.append(f"Risco MÉDIO: HTTPS presente, mas falha na conexão ou status inesperado ({response.status_code}).")

    except requests.exceptions.SSLError as e:
        score += 50
        reasons.append(f"Risco ALTO: Erro no certificado SSL (inválido ou auto-assinado): {e}.")
    except requests.exceptions.ConnectionError as e:
        score += 30
        reasons.append(f"Risco ALTO: Falha ao conectar (mesmo com HTTPS), possível problema de rede ou domínio falso: {e}.")
    except requests.exceptions.Timeout:
        score += 15
        reasons.append("Risco MÉDIO: Requisição HTTPS expirou, possível servidor lento ou inexistente.")
    except Exception as e:
        score += 10
        reasons.append(f"Risco BAIXO: Erro inesperado ao verificar SSL ({e}).")

    return score, reasons

def analyze_url_structure(url):
    """Analyzes various aspects of the URL structure for suspicious patterns."""
    score = 0
    reasons = []

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path

    # 1. URL Length
    if len(url) > MAX_NORMAL_URL_LENGTH:
        score += 10
        reasons.append(f"Risco BAIXO: URL muito longa ({len(url)} caracteres).")

    # 2. Many Hyphens in Domain
    if domain.count('-') > 3: # Arbitrary threshold, adjust as needed
        score += 10
        reasons.append("Risco BAIXO: Muitos hífens no nome do domínio.")

    # 3. Many Subdomains
    # tldextract handles this well by giving 'subdomain'
    extracted = tldextract.extract(url)
    subdomains_count = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    if subdomains_count > MAX_NORMAL_SUBDOMAINS:
        score += 15
        reasons.append(f"Risco MÉDIO: Muitos subdomínios ({subdomains_count}).")

    # 4. Numbers in Domain (e.g., paypal123.com)
    if re.search(r'\d', extracted.domain): # Check for digits in the main domain part
        score += 15
        reasons.append("Risco MÉDIO: Presença de números no nome do domínio principal.")

    # 5. Suspicious Keywords in Domain or Path
    for keyword in PHISHING_KEYWORDS:
        if keyword in domain.lower() or keyword in path.lower():
            score += 20
            reasons.append(f"Risco ALTO: Palavra-chave suspeita encontrada na URL ('{keyword}').")
            break # Add only once per URL, even if multiple keywords exist

    return score, reasons

def check_suspicious_tld(url):
    """Checks if the URL uses a Top-Level Domain (TLD) known for phishing."""
    score = 0
    reasons = []

    extracted = tldextract.extract(url)
    tld = f".{extracted.suffix}"

    if tld.lower() in SUSPICIOUS_TLDS:
        score += 25
        reasons.append(f"Risco ALTO: TLD suspeito encontrado ('{tld}').")

    return score, reasons

def check_typosquatting(url):
    """Compares the domain with a list of popular brands to detect typosquatting."
       Uses a simplified substring check for initial implementation.
    """
    score = 0
    reasons = []

    domain = get_domain_from_url(url)
    if not domain:
        reasons.append("N/A: Não foi possível extrair o domínio para verificação de typosquatting.")
        return score, reasons

    # Remove the TLD for comparison (e.g., 'google' from 'google.com')
    extracted = tldextract.extract(url)
    domain_without_tld = extracted.domain.lower()

    for brand in POPULAR_BRANDS:
        # Simple check: if a brand name is very similar or contained with slight modification
        # This can be improved with Levenshtein distance or fuzzy matching libraries
        if brand in domain_without_tld and brand != domain_without_tld: # e.g. 'googl' in 'googleservice'
            score += 40
            reasons.append(f"Risco ALTO: Potencial typosquatting detectado (domínio '{domain_without_tld}' é similar a '{brand}').")
            return score, reasons # Only need one match

        # Check for common substitutions (e.g., 'l' for 'I', '0' for 'o')
        # This is a very basic heuristic
        if any(char in domain_without_tld for char in ['0', '1', 'l']) and brand in domain_without_tld.replace('0','o').replace('1','i').replace('l','i'):
             score += 30
             reasons.append(f"Risco ALTO: Potencial typosquatting com substituição de caracteres (domínio '{domain_without_tld}' similar a '{brand}').")
             return score, reasons

    return score, reasons

def check_redirects(url):
    """Checks if the URL redirects to a different domain."""
    score = 0
    reasons = []

    try:
        # Make a GET request, allow redirects
        response = requests.get(url, timeout=5, allow_redirects=True)

        if response.history: # If there's a history, a redirect occurred
            original_domain = urlparse(url).netloc
            final_url = response.url
            final_domain = urlparse(final_url).netloc

            if original_domain != final_domain:
                score += 35
                reasons.append(f"Risco ALTO: A URL original redireciona para um domínio diferente: '{final_domain}'.")
            else:
                reasons.append("Informação: Redirecionamento interno detectado, mas para o mesmo domínio.")
        else:
            reasons.append("Seguro: Nenhum redirecionamento externo detectado.")

    except requests.exceptions.RequestException as e:
        score += 10
        reasons.append(f"Risco BAIXO: Falha ao verificar redirecionamentos ({e}).")

    return score, reasons

def calculate_phishing_score(url):
    """Calculates a phishing risk score for a given URL based on various factors.
       Returns the total score and a list of detailed reasons."""
    total_score = 0
    all_reasons = []

    # Ensure URL has a scheme for requests (defaults to http if missing)
    if not urlparse(url).scheme:
        url = "http://" + url # requests will handle redirects to https if applicable

    # Basic URL validation after ensuring a scheme
    if not validators.url(url):
        return 100, [f"ERRO: A URL fornecida é inválida ou não suportada: {url}"]

    # Factor 1: WHOIS Age
    domain = get_domain_from_url(url)
    whois_score, whois_reasons = check_whois_age(domain)
    total_score += whois_score
    all_reasons.extend(whois_reasons)

    # Factor 2: SSL Certificate
    ssl_score, ssl_reasons = check_ssl_certificate(url)
    total_score += ssl_score
    all_reasons.extend(ssl_reasons)

    # Factor 3: URL Structure
    url_struct_score, url_struct_reasons = analyze_url_structure(url)
    total_score += url_struct_score
    all_reasons.extend(url_struct_reasons)

    # Factor 4: Suspicious TLD
    tld_score, tld_reasons = check_suspicious_tld(url)
    total_score += tld_score
    all_reasons.extend(tld_reasons)

    # Factor 5: Typosquatting
    typo_score, typo_reasons = check_typosquatting(url)
    total_score += typo_score
    all_reasons.extend(typo_reasons)

    # Factor 6: Redirects
    redirect_score, redirect_reasons = check_redirects(url)
    total_score += redirect_score
    all_reasons.extend(redirect_reasons)

    # Cap the score at 100
    total_score = min(total_score, 100)

    return total_score, all_reasons

def get_risk_level(score):
    """Determines the risk level based on the score."""
    if score >= RISK_THRESHOLDS['medium']:
        return "ALTO"
    elif score >= RISK_THRESHOLDS['low']:
        return "MÉDIO"
    else:
        return "BAIXO"

def get_final_recommendation(score):
    """Provides a final recommendation based on the risk score."""
    if score >= RISK_THRESHOLDS['medium']:
        return "Recomendação: **NÃO clique nesta URL.** É altamente provável que seja um ataque de phishing."
    elif score >= RISK_THRESHOLDS['low']:
        return "Recomendação: **Prossiga com extrema cautela.** A URL apresenta múltiplos sinais de alerta."
    else:
        return "Recomendação: **Parece seguro, mas sempre use o bom senso.**"


    print("\nAnalisando URL... Por favor, aguarde.")
    score, reasons = calculate_phishing_score(user_url)
    risk_level = get_risk_level(score)
    recommendation = get_final_recommendation(score)

    print("\n--- Resultado da Análise ---")
    print(f"URL Analisada: {user_url}")
    print(f"Score de Risco de Phishing: {score}/100")
    print(f"Nível de Risco: {risk_level}")

    print("\n--- Motivos Detectados ---")
    if reasons:
        for reason in reasons:
            print(f"- {reason}")
    else:
        print("Nenhum motivo específico de risco detectado.")

    print(f"\n{recommendation}")
