"""Shared helpers for the MAVIS anomaly models."""
import numpy as np

DEFAULT_BATCH = 100_000


def to_numpy(X, dtype=np.float32):
    """Accept a DataFrame or array-like and return a 2-D numpy array."""
    arr = X.to_numpy() if hasattr(X, 'to_numpy') else np.asarray(X)
    arr = np.asarray(arr, dtype=dtype)
    return arr.reshape(1, -1) if arr.ndim == 1 else arr


def batched(fn, X, batch_size=DEFAULT_BATCH):
    """Apply fn to row batches of X and concatenate into one 1-D float array."""
    arr = to_numpy(X)
    if len(arr) == 0:
        return np.zeros(0, dtype=np.float64)
    out = [np.asarray(fn(arr[i:i + batch_size]), dtype=np.float64).ravel()
           for i in range(0, len(arr), batch_size)]
    return np.concatenate(out)
