"""Visual similarity analysis and screenshot comparison"""

import logging
import asyncio
from typing import Optional, Tuple, Dict
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class VisualAnalyzer:
    """Analyze visual similarity between screenshots"""
    
    def __init__(self):
        self.screenshot_dir = Path("screenshots")
        self.screenshot_dir.mkdir(exist_ok=True)
    
    async def capture_screenshot(self, url: str, timeout: int = 30000) -> Optional[str]:
        """
        Capture webpage screenshot using Playwright
        
        Returns:
            Path to saved screenshot or None if failed
        """
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=True,
                )
                page = await context.new_page()
                
                try:
                    # Navigate with timeout
                    await page.goto(url, wait_until="load", timeout=timeout)
                    
                    # Wait for content to stabilize
                    await asyncio.sleep(1)
                    
                    # Generate filename
                    import hashlib
                    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
                    screenshot_path = self.screenshot_dir / f"{url_hash}.png"
                    
                    # Take screenshot
                    await page.screenshot(path=str(screenshot_path), full_page=False)
                    
                    logger.info(f"Screenshot saved: {screenshot_path}")
                    return str(screenshot_path)
                
                except asyncio.TimeoutError:
                    logger.warning(f"Screenshot timeout for {url}")
                    return None
                except Exception as e:
                    logger.error(f"Error capturing screenshot for {url}: {e}")
                    return None
                finally:
                    await context.close()
                    await browser.close()
        
        except ImportError:
            logger.error("Playwright not installed")
            return None
        except Exception as e:
            logger.error(f"Error in screenshot capture: {e}")
            return None

    def calculate_visual_similarity(self, img_path1: str, img_path2: str) -> float:
        """
        Calculate visual similarity between two images (0-1)
        
        Uses perceptual hashing as baseline
        """
        try:
            from PIL import Image
            import imagehash
            
            # Load images
            img1 = Image.open(img_path1)
            img2 = Image.open(img_path2)
            
            # Calculate perceptual hashes
            hash1 = imagehash.phash(img1)
            hash2 = imagehash.phash(img2)
            
            # Calculate distance (0-64 for 8x8 hash)
            distance = hash1 - hash2
            
            # Convert to similarity (0-1)
            # Max distance is 64
            similarity = 1.0 - (distance / 64.0)
            
            return max(0.0, min(1.0, similarity))
        
        except Exception as e:
            logger.error(f"Error calculating visual similarity: {e}")
            return 0.0

    def extract_visual_features(self, img_path: str) -> Dict[str, any]:
        """
        Extract visual features from image
        """
        try:
            from PIL import Image
            import numpy as np
            
            img = Image.open(img_path)
            
            features = {
                "width": img.width,
                "height": img.height,
                "aspect_ratio": img.width / img.height if img.height > 0 else 0,
                "format": img.format,
            }
            
            # Calculate dominant colors (simple histogram)
            if img.mode == 'RGB' or img.mode == 'RGBA':
                # Resize for faster processing
                small_img = img.resize((50, 50))
                pixels = np.array(small_img)
                
                # Get average color
                if len(pixels.shape) == 3:
                    avg_color = pixels.mean(axis=(0, 1))
                    features["avg_color_r"] = float(avg_color[0])
                    features["avg_color_g"] = float(avg_color[1])
                    features["avg_color_b"] = float(avg_color[2])
            
            return features
        
        except Exception as e:
            logger.error(f"Error extracting visual features: {e}")
            return {}

    def generate_phash(self, img_path: str) -> Optional[str]:
        """
        Generate perceptual hash of image
        """
        try:
            from PIL import Image
            import imagehash
            
            img = Image.open(img_path)
            phash = imagehash.phash(img)
            
            return str(phash)
        
        except Exception as e:
            logger.error(f"Error generating phash: {e}")
            return None

    def compare_screenshots_advanced(self, img_path1: str, img_path2: str) -> Dict[str, float]:
        """
        Advanced screenshot comparison using multiple methods
        
        Returns:
            Dictionary with multiple similarity scores
        """
        try:
            from PIL import Image
            import imagehash
            import numpy as np
            
            img1 = Image.open(img_path1).convert('RGB')
            img2 = Image.open(img_path2).convert('RGB')
            
            # Resize to same dimensions for comparison
            target_size = (256, 256)
            img1_resized = img1.resize(target_size)
            img2_resized = img2.resize(target_size)
            
            # Perceptual hash similarity
            hash1 = imagehash.phash(img1_resized)
            hash2 = imagehash.phash(img2_resized)
            phash_distance = hash1 - hash2
            phash_similarity = 1.0 - (phash_distance / 64.0)
            
            # Difference hash similarity
            dhash1 = imagehash.dhash(img1_resized)
            dhash2 = imagehash.dhash(img2_resized)
            dhash_distance = dhash1 - dhash2
            dhash_similarity = 1.0 - (dhash_distance / 64.0)
            
            # Average hash similarity
            ahash1 = imagehash.average_hash(img1_resized)
            ahash2 = imagehash.average_hash(img2_resized)
            ahash_distance = ahash1 - ahash2
            ahash_similarity = 1.0 - (ahash_distance / 64.0)
            
            # Pixel-level comparison (simple MSE)
            arr1 = np.array(img1_resized, dtype=np.float32)
            arr2 = np.array(img2_resized, dtype=np.float32)
            
            mse = np.mean((arr1 - arr2) ** 2)
            # Normalize MSE to 0-1 similarity (max MSE ~65536)
            mse_similarity = 1.0 - (mse / 65536.0)
            mse_similarity = max(0.0, min(1.0, mse_similarity))
            
            # Weighted average
            combined_similarity = (
                phash_similarity * 0.4 +
                dhash_similarity * 0.3 +
                ahash_similarity * 0.2 +
                mse_similarity * 0.1
            )
            
            return {
                "phash_similarity": max(0.0, min(1.0, phash_similarity)),
                "dhash_similarity": max(0.0, min(1.0, dhash_similarity)),
                "ahash_similarity": max(0.0, min(1.0, ahash_similarity)),
                "mse_similarity": mse_similarity,
                "combined_similarity": max(0.0, min(1.0, combined_similarity)),
            }
        
        except Exception as e:
            logger.error(f"Error in advanced screenshot comparison: {e}")
            return {
                "phash_similarity": 0.0,
                "dhash_similarity": 0.0,
                "ahash_similarity": 0.0,
                "mse_similarity": 0.0,
                "combined_similarity": 0.0,
            }

    def detect_layout_similarity(self, img_path1: str, img_path2: str) -> float:
        """
        Detect layout similarity by analyzing image structure
        """
        try:
            from PIL import Image
            import numpy as np
            
            img1 = Image.open(img_path1).convert('L')  # Grayscale
            img2 = Image.open(img_path2).convert('L')
            
            # Resize to same size
            size = (200, 200)
            img1 = img1.resize(size)
            img2 = img2.resize(size)
            
            # Convert to numpy arrays
            arr1 = np.array(img1, dtype=np.float32)
            arr2 = np.array(img2, dtype=np.float32)
            
            # Normalize
            arr1 = (arr1 - arr1.mean()) / (arr1.std() + 1e-8)
            arr2 = (arr2 - arr2.mean()) / (arr2.std() + 1e-8)
            
            # Calculate correlation coefficient (layout similarity)
            correlation = np.mean(arr1 * arr2)
            correlation = (correlation + 1) / 2  # Convert from [-1,1] to [0,1]
            
            return max(0.0, min(1.0, correlation))
        
        except Exception as e:
            logger.error(f"Error detecting layout similarity: {e}")
            return 0.0

    def extract_edge_features(self, img_path: str) -> Dict[str, float]:
        """
        Extract edge-based features for structural analysis
        """
        try:
            from PIL import Image
            import numpy as np
            from scipy import ndimage
            
            img = Image.open(img_path).convert('L')
            arr = np.array(img, dtype=np.float32)
            
            # Detect edges using Sobel
            sx = ndimage.sobel(arr, axis=0)
            sy = ndimage.sobel(arr, axis=1)
            edges = np.sqrt(sx**2 + sy**2)
            
            # Calculate edge statistics
            features = {
                "edge_density": float(np.mean(edges > 50)),  # Percentage of edge pixels
                "edge_variance": float(np.var(edges)),
                "horizontal_edges": float(np.mean(np.abs(sx))),
                "vertical_edges": float(np.mean(np.abs(sy))),
            }
            
            return features
        
        except Exception as e:
            logger.error(f"Error extracting edge features: {e}")
            return {}
