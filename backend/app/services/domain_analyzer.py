"""Domain intelligence and analysis engine"""

import re
from urllib.parse import urlparse
from typing import Tuple, Dict, List
import math
import logging

logger = logging.getLogger(__name__)


class DomainAnalyzer:
    """Analyze domain characteristics and similarity"""
    
    # Suspicious keywords commonly found in phishing domains
    SUSPICIOUS_KEYWORDS = {
        "verify", "confirm", "validate", "update", "alert", "urgent",
        "secure", "login", "signin", "account", "password", "auth",
        "security", "confirm", "urgent", "action", "required", "click",
        "support", "help", "service", "official", "admin", "panel",
        "invoice", "receipt", "billing", "payment", "transaction",
        "confirm", "verify", "proof", "resume"
    }
    
    # Common homoglyphs (visual lookalikes)
    HOMOGLYPHS = {
        '0': 'o',  # zero to o
        '1': 'l',  # one to l
        '5': 's',  # five to s
        '8': 'b',  # eight to b
    }
    
    def __init__(self):
        self.suspicious_keywords = self.SUSPICIOUS_KEYWORDS

    def parse_url(self, url: str) -> Tuple[str, str, str]:
        """
        Parse URL and extract domain components
        
        Returns:
            (domain, subdomain, tld)
        """
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
            hostname = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            
            parts = hostname.split('.')
            
            if len(parts) >= 2:
                tld = parts[-1]
                domain = parts[-2] + '.' + tld
                subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
            else:
                domain = hostname
                tld = ''
                subdomain = ''
            
            return domain, subdomain, tld
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return '', '', ''

    def extract_domain_features(self, domain: str) -> Dict[str, any]:
        """
        Extract domain-level features
        
        Features:
        - url_length
        - num_hyphens
        - num_digits
        - num_subdomains
        - character_entropy
        - has_https
        - has_suspicious_keywords
        """
        parts = domain.split('.')
        
        features = {
            "domain_length": len(domain),
            "num_hyphens": domain.count('-'),
            "num_digits": sum(1 for c in domain if c.isdigit()),
            "num_dots": domain.count('.'),
            "num_subdomains": max(0, len(parts) - 2),
            "char_entropy": self._calculate_entropy(domain),
            "has_digits": any(c.isdigit() for c in domain),
            "has_hyphens": '-' in domain,
            "starts_with_digit": domain[0].isdigit() if domain else False,
            "vowel_ratio": self._calculate_vowel_ratio(domain),
        }
        
        return features

    def detect_suspicious_keywords(self, text: str) -> Tuple[int, float]:
        """
        Detect suspicious keywords in domain or text
        
        Returns:
            (count, score 0-1)
        """
        text_lower = text.lower()
        count = 0
        
        for keyword in self.suspicious_keywords:
            # Use word boundaries for more accurate matching
            pattern = r'\b' + re.escape(keyword) + r'\b'
            matches = re.findall(pattern, text_lower)
            count += len(matches)
        
        # Normalize score
        score = min(count / 5.0, 1.0)  # Scale: each keyword adds 0.2, max 1.0
        
        return count, score

    def calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """
        Calculate similarity between two domains (0-1)
        
        Combines:
        - Levenshtein distance
        - Jaro-Winkler similarity
        - Token-based similarity
        """
        # Normalize
        d1 = domain1.lower().replace('www.', '')
        d2 = domain2.lower().replace('www.', '')
        
        if d1 == d2:
            return 1.0
        
        # Levenshtein-based similarity
        lev_sim = self._levenshtein_similarity(d1, d2)
        
        # Jaro-Winkler similarity
        jaro_sim = self._jaro_winkler_similarity(d1, d2)
        
        # N-gram based similarity (character-level)
        ngram_sim = self._ngram_similarity(d1, d2, n=2)
        
        # Token-based similarity (domain parts)
        token_sim = self._token_similarity(d1, d2)
        
        # Weighted average
        combined_score = (
            lev_sim * 0.3 +
            jaro_sim * 0.3 +
            ngram_sim * 0.2 +
            token_sim * 0.2
        )
        
        return combined_score

    def _levenshtein_similarity(self, s1: str, s2: str) -> float:
        """Levenshtein distance based similarity (0-1)"""
        if not s1 or not s2:
            return 0.0
        
        # Dynamic programming for Levenshtein distance
        m, n = len(s1), len(s2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j
        
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if s1[i-1] == s2[j-1]:
                    dp[i][j] = dp[i-1][j-1]
                else:
                    dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
        
        distance = dp[m][n]
        max_len = max(len(s1), len(s2))
        similarity = 1.0 - (distance / max_len)
        
        return max(0.0, min(1.0, similarity))

    def _jaro_winkler_similarity(self, s1: str, s2: str) -> float:
        """Jaro-Winkler similarity (0-1)"""
        if s1 == s2:
            return 1.0
        
        len1, len2 = len(s1), len(s2)
        if len1 == 0 and len2 == 0:
            return 1.0
        if len1 == 0 or len2 == 0:
            return 0.0
        
        match_distance = max(len1, len2) // 2 - 1
        if match_distance < 0:
            match_distance = 0
        
        s1_matches = [False] * len1
        s2_matches = [False] * len2
        
        matches = 0
        transpositions = 0
        
        for i in range(len1):
            start = max(0, i - match_distance)
            end = min(i + match_distance + 1, len2)
            
            for j in range(start, end):
                if s2_matches[j] or s1[i] != s2[j]:
                    continue
                s1_matches[i] = True
                s2_matches[j] = True
                matches += 1
                break
        
        if matches == 0:
            return 0.0
        
        k = 0
        for i in range(len1):
            if not s1_matches[i]:
                continue
            while not s2_matches[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1
        
        jaro = (matches / len1 + matches / len2 +
                (matches - transpositions / 2) / matches) / 3.0
        
        # Jaro-Winkler: add bonus for common prefix
        prefix = 0
        for i in range(min(len(s1), len(s2))):
            if s1[i] == s2[i]:
                prefix += 1
            else:
                break
        prefix = min(4, prefix)
        
        jaro_winkler = jaro + prefix * 0.1 * (1.0 - jaro)
        
        return max(0.0, min(1.0, jaro_winkler))

    def _ngram_similarity(self, s1: str, s2: str, n: int = 2) -> float:
        """N-gram based similarity"""
        if len(s1) < n or len(s2) < n:
            return self._levenshtein_similarity(s1, s2)
        
        ngrams1 = set(s1[i:i+n] for i in range(len(s1) - n + 1))
        ngrams2 = set(s2[i:i+n] for i in range(len(s2) - n + 1))
        
        if not ngrams1 or not ngrams2:
            return 0.0
        
        intersection = len(ngrams1 & ngrams2)
        union = len(ngrams1 | ngrams2)
        
        return intersection / union if union > 0 else 0.0

    def _token_similarity(self, domain1: str, domain2: str) -> float:
        """Similarity based on domain parts (tokens)"""
        parts1 = set(domain1.replace('-', '.').split('.'))
        parts2 = set(domain2.replace('-', '.').split('.'))
        
        if not parts1 or not parts2:
            return 0.0
        
        intersection = len(parts1 & parts2)
        union = len(parts1 | parts2)
        
        return intersection / union if union > 0 else 0.0

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text (indicator of randomness)"""
        if not text:
            return 0.0
        
        entropy = 0.0
        for char in set(text):
            p_char = text.count(char) / len(text)
            entropy -= p_char * math.log2(p_char)
        
        # Normalize to 0-1
        max_entropy = math.log2(len(set(text))) if len(set(text)) > 1 else 1.0
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
        
        return min(1.0, max(0.0, normalized_entropy))

    def _calculate_vowel_ratio(self, text: str) -> float:
        """Calculate ratio of vowels in text"""
        if not text:
            return 0.0
        vowels = sum(1 for c in text.lower() if c in 'aeiou')
        return vowels / len(text)

    def detect_homoglyphs(self, domain1: str, domain2: str) -> float:
        """
        Detect visual lookalikes using homoglyphs
        
        Returns:
            Similarity score (0-1) considering homoglyph substitutions
        """
        d1 = domain1.lower()
        d2 = domain2.lower()
        
        # Try replacing homoglyphs in domain1 and check similarity with domain2
        for original, replacement in self.HOMOGLYPHS.items():
            homoglyph_variant = d1.replace(original, replacement)
            if homoglyph_variant == d2:
                return 0.95  # Very high similarity due to homoglyph
        
        # Also check reverse
        for original, replacement in self.HOMOGLYPHS.items():
            homoglyph_variant = d2.replace(original, replacement)
            if homoglyph_variant == d1:
                return 0.95
        
        return 0.0

    def calculate_domain_score(self, candidate_domain: str, reference_domain: str) -> Dict[str, float]:
        """
        Calculate comprehensive domain similarity score
        
        Returns:
            Dictionary with similarity_score and detailed metrics
        """
        # Basic similarity
        similarity = self.calculate_domain_similarity(candidate_domain, reference_domain)
        
        # Homoglyph detection
        homoglyph_score = self.detect_homoglyphs(candidate_domain, reference_domain)
        similarity = max(similarity, homoglyph_score)
        
        # Extract features
        features = self.extract_domain_features(candidate_domain)
        
        # Suspicious keyword detection
        keyword_count, keyword_score = self.detect_suspicious_keywords(candidate_domain)
        
        # Check for typosquatting indicators
        typosquat_indicators = self._check_typosquat_indicators(
            candidate_domain, reference_domain
        )
        
        return {
            "similarity_score": similarity,
            "homoglyph_score": homoglyph_score,
            "keyword_score": keyword_score,
            "keyword_count": keyword_count,
            "typosquat_indicators": typosquat_indicators,
            "domain_features": features,
        }

    def _check_typosquat_indicators(self, candidate: str, reference: str) -> List[str]:
        """
        Check for common typosquatting patterns
        """
        indicators = []
        cand_clean = candidate.lower().replace('www.', '').replace('http://', '').replace('https://', '')
        ref_clean = reference.lower().replace('www.', '').replace('http://', '').replace('https://', '')
        
        # Character substitution
        if self._are_similar_with_substitutions(cand_clean, ref_clean):
            indicators.append("character_substitution")
        
        # Hyphen insertion
        if cand_clean.replace('-', '') == ref_clean.replace('-', ''):
            indicators.append("hyphen_insertion")
        
        # Subdomain confusion
        if cand_clean.replace('.', '-') == ref_clean.replace('.', '-'):
            indicators.append("subdomain_confusion")
        
        # Similar prefix
        if cand_clean.startswith(ref_clean[:len(ref_clean)//2]):
            indicators.append("similar_prefix")
        
        # Additional TLD
        if cand_clean.startswith(ref_clean + '-') or cand_clean.startswith(ref_clean + '.'):
            indicators.append("additional_tld")
        
        return indicators

    def _are_similar_with_substitutions(self, s1: str, s2: str, threshold: float = 0.85) -> bool:
        """Check if strings are similar even with single-character substitutions"""
        return self.calculate_domain_similarity(s1, s2) > threshold
