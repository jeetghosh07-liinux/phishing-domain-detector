"""Content and HTML analysis engine"""

from typing import Dict, List, Set, Tuple
import re
import logging
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class ContentAnalyzer:
    """Analyze HTML content and text similarity"""
    
    # Common authentication-related patterns
    AUTH_KEYWORDS = {
        'password', 'username', 'email', 'login', 'signin', 'verify',
        'confirm', 'credential', 'authenticate', 'token', 'captcha',
        'authorization', 'permission', 'access', 'account', 'profile'
    }
    
    def __init__(self):
        pass

    def extract_text_fingerprint(self, html: str) -> str:
        """
        Extract visible text from HTML, normalized
        
        Returns:
            Cleaned and normalized text
        """
        try:
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(html, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Get text
            text = soup.get_text()
            
            # Normalize whitespace
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = ' '.join(chunk for chunk in chunks if chunk)
            
            return text
        except Exception as e:
            logger.error(f"Error extracting text: {e}")
            return ""

    def extract_dom_fingerprint(self, html: str) -> Dict[str, any]:
        """
        Extract DOM structure fingerprint from HTML
        
        Returns:
            Dictionary with structural features
        """
        try:
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(html, 'html.parser')
            
            fingerprint = {
                "title": soup.title.string if soup.title else "",
                "num_forms": len(soup.find_all('form')),
                "num_inputs": len(soup.find_all('input')),
                "num_buttons": len(soup.find_all('button')),
                "num_links": len(soup.find_all('a')),
                "num_images": len(soup.find_all('img')),
                "num_scripts": len(soup.find_all('script')),
                "num_stylesheets": len(soup.find_all('link', rel='stylesheet')),
                "num_total_tags": len(soup.find_all()),
                "num_divs": len(soup.find_all('div')),
                "num_headings": len(soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])),
            }
            
            # Analyze form structure
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                fingerprint[f"form_inputs"] = len(inputs)
                fingerprint[f"password_inputs"] = len([i for i in inputs if i.get('type', '').lower() == 'password'])
                fingerprint[f"email_inputs"] = len([i for i in inputs if i.get('type', '').lower() == 'email'])
                fingerprint[f"text_inputs"] = len([i for i in inputs if i.get('type', '').lower() in ['text', '']])
            
            # Extract meta information
            fingerprint["meta_tags"] = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    fingerprint["meta_tags"][name] = content[:100]  # Truncate
            
            return fingerprint
        except Exception as e:
            logger.error(f"Error extracting DOM fingerprint: {e}")
            return {}

    def calculate_text_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two text blocks (0-1)
        
        Uses TF-IDF + cosine similarity approach
        """
        if not text1 or not text2:
            return 0.0
        
        # Normalize texts
        t1 = self._normalize_text(text1)
        t2 = self._normalize_text(text2)
        
        if not t1 or not t2:
            return 0.0
        
        # Tokenize
        tokens1 = set(t1.split())
        tokens2 = set(t2.split())
        
        if not tokens1 or not tokens2:
            return 0.0
        
        # Jaccard similarity
        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)
        jaccard = intersection / union if union > 0 else 0.0
        
        # Also calculate token overlap ratio
        overlap_ratio = intersection / min(len(tokens1), len(tokens2)) if min(len(tokens1), len(tokens2)) > 0 else 0.0
        
        # Combined score (prefer overlap ratio for phishing detection)
        combined = jaccard * 0.3 + overlap_ratio * 0.7
        
        return min(1.0, max(0.0, combined))

    def calculate_dom_similarity(self, dom1: Dict, dom2: Dict) -> float:
        """
        Calculate similarity between DOM structures (0-1)
        """
        if not dom1 or not dom2:
            return 0.0
        
        scores = []
        
        # Compare numeric features
        numeric_keys = [
            'num_forms', 'num_inputs', 'num_buttons', 'num_links',
            'num_images', 'num_scripts', 'num_stylesheets'
        ]
        
        for key in numeric_keys:
            val1 = dom1.get(key, 0)
            val2 = dom2.get(key, 0)
            
            if val1 + val2 > 0:
                # Normalized difference
                diff = abs(val1 - val2) / (val1 + val2)
                similarity = 1.0 - min(1.0, diff)
                scores.append(similarity)
        
        # Compare titles
        title1 = dom1.get('title', '').lower()
        title2 = dom2.get('title', '').lower()
        if title1 and title2:
            title_similarity = self._string_similarity(title1, title2)
            scores.append(title_similarity)
        
        # Average the scores
        if scores:
            return sum(scores) / len(scores)
        else:
            return 0.5  # Neutral if no comparable features

    def detect_login_form(self, html: str) -> Tuple[bool, float, Dict[str, any]]:
        """
        Detect if page contains authentication/login form
        
        Returns:
            (has_login_form, confidence_score, details)
        """
        try:
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(html, 'html.parser')
            
            details = {
                "has_password_input": False,
                "has_email_input": False,
                "has_username_input": False,
                "has_login_button": False,
                "auth_keywords_found": [],
                "form_count": 0,
            }
            
            # Check for forms
            forms = soup.find_all('form')
            details["form_count"] = len(forms)
            
            if len(forms) == 0:
                return False, 0.0, details
            
            for form in forms:
                # Check for input types
                inputs = form.find_all('input')
                for inp in inputs:
                    input_type = inp.get('type', '').lower()
                    input_name = inp.get('name', '').lower()
                    
                    if input_type == 'password':
                        details["has_password_input"] = True
                    if input_type == 'email' or 'email' in input_name:
                        details["has_email_input"] = True
                    if input_type in ['text', ''] and any(
                        x in input_name for x in ['user', 'username', 'login', 'id']
                    ):
                        details["has_username_input"] = True
                
                # Check for login buttons
                buttons = form.find_all('button')
                for btn in buttons:
                    btn_text = (btn.get_text() or "").lower()
                    if any(x in btn_text for x in ['login', 'signin', 'submit', 'verify', 'confirm']):
                        details["has_login_button"] = True
            
            # Check for authentication keywords in page text
            text = soup.get_text().lower()
            for keyword in self.AUTH_KEYWORDS:
                if keyword in text:
                    details["auth_keywords_found"].append(keyword)
            
            # Calculate confidence score
            indicators = sum([
                details["has_password_input"],
                details["has_email_input"],
                details["has_username_input"],
                details["has_login_button"],
                len(details["auth_keywords_found"]) > 2,
            ])
            
            confidence = min(1.0, indicators / 5.0)
            has_login = confidence > 0.3
            
            return has_login, confidence, details
        except Exception as e:
            logger.error(f"Error detecting login form: {e}")
            return False, 0.0, {}

    def extract_metadata(self, html: str) -> Dict[str, str]:
        """
        Extract metadata from HTML
        """
        try:
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(html, 'html.parser')
            metadata = {}
            
            # Title
            if soup.title:
                metadata['title'] = soup.title.string or ""
            
            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name:
                    metadata[f'meta_{name}'] = content[:200]
            
            # Description
            desc_meta = soup.find('meta', attrs={'name': 'description'})
            if desc_meta:
                metadata['description'] = desc_meta.get('content', '')
            
            # Keywords
            keywords_meta = soup.find('meta', attrs={'name': 'keywords'})
            if keywords_meta:
                metadata['keywords'] = keywords_meta.get('content', '')
            
            return metadata
        except Exception as e:
            logger.error(f"Error extracting metadata: {e}")
            return {}

    def _normalize_text(self, text: str) -> str:
        """
        Normalize text for comparison
        """
        # Convert to lowercase
        text = text.lower()
        
        # Remove URLs
        text = re.sub(r'http\S+|www\S+', '', text)
        
        # Remove punctuation
        text = re.sub(r'[^\w\s]', ' ', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text

    def _string_similarity(self, s1: str, s2: str) -> float:
        """
        Simple string similarity using Jaccard index
        """
        if not s1 or not s2:
            return 0.0
        
        if s1 == s2:
            return 1.0
        
        # Character-level similarity
        chars1 = set(s1)
        chars2 = set(s2)
        
        intersection = len(chars1 & chars2)
        union = len(chars1 | chars2)
        
        return intersection / union if union > 0 else 0.0

    def extract_resources(self, html: str, base_url: str = "") -> Dict[str, List[str]]:
        """
        Extract external resources (scripts, stylesheets, images)
        """
        try:
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(html, 'html.parser')
            resources = {
                "scripts": [],
                "stylesheets": [],
                "images": [],
                "links": [],
            }
            
            # Scripts
            for script in soup.find_all('script'):
                src = script.get('src', '')
                if src:
                    resources["scripts"].append(src)
            
            # Stylesheets
            for link in soup.find_all('link', rel='stylesheet'):
                href = link.get('href', '')
                if href:
                    resources["stylesheets"].append(href)
            
            # Images
            for img in soup.find_all('img'):
                src = img.get('src', '')
                if src:
                    resources["images"].append(src)
            
            # Links
            for link in soup.find_all('a', limit=20):  # Limit to first 20
                href = link.get('href', '')
                if href and href.startswith('http'):
                    resources["links"].append(href)
            
            return resources
        except Exception as e:
            logger.error(f"Error extracting resources: {e}")
            return {"scripts": [], "stylesheets": [], "images": [], "links": []}
