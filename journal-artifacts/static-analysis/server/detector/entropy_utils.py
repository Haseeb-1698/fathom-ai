"""
Professional entropy calculations with scipy fallback
Replaces all custom Shannon entropy implementations
"""

from typing import Union

# Try to import scipy for professional calculations
try:
    import numpy as np
    from scipy.stats import entropy
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


def calculate_shannon_entropy(data: Union[bytes, bytearray]) -> float:
    """
    Calculate Shannon entropy using scipy if available, otherwise fallback
    
    Args:
        data: Byte data to analyze
        
    Returns:
        Shannon entropy in bits (base 2)
    """
    if not data:
        return 0.0
    
    if SCIPY_AVAILABLE:
        try:
            # Count byte frequencies (0-255)
            counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            
            # Remove zero counts for efficiency
            counts = counts[counts > 0]
            
            # Calculate Shannon entropy using scipy (base 2 for bits)
            return float(entropy(counts, base=2))
            
        except Exception:
            pass  # Fall through to manual calculation
    
    # Fallback manual calculation (optimized)
    import math
    from collections import Counter
    
    total = len(data)
    counts = Counter(data)
    
    # Calculate Shannon entropy manually
    return float(-sum((c/total) * math.log2(c/total) for c in counts.values()))


def calculate_entropy_from_frequencies(frequencies: list) -> float:
    """
    Calculate entropy from pre-computed frequency counts
    
    Args:
        frequencies: List of frequency counts
        
    Returns:
        Shannon entropy in bits (base 2)
    """
    if not frequencies:
        return 0.0
    
    if SCIPY_AVAILABLE:
        try:
            # Convert to numpy array and remove zeros
            freq_array = np.array(frequencies)
            freq_array = freq_array[freq_array > 0]
            
            # Calculate entropy using scipy
            return float(entropy(freq_array, base=2))
            
        except Exception:
            pass  # Fall through to manual calculation
    
    # Fallback manual calculation
    import math
    
    total = sum(frequencies)
    if total <= 0:
        return 0.0
    
    h = 0.0
    for c in frequencies:
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    
    return float(h)


def is_high_entropy(data: Union[bytes, bytearray], threshold: float = 7.5) -> bool:
    """
    Check if data has high entropy (typically indicates compression/encryption)
    
    Args:
        data: Byte data to analyze
        threshold: Entropy threshold (default 7.5 bits)
        
    Returns:
        True if entropy is above threshold
    """
    return calculate_shannon_entropy(data) >= threshold


# Backward compatibility aliases
shannon_entropy = calculate_shannon_entropy