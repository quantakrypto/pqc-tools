import os
import logging

rsa_config = {"rotate_days": 90}

def generate_report(ec_metrics):
    summary = f"ec metrics: {ec_metrics}"
    return summary

ALGORITHMS = ["HS256"]  # HMAC, symmetric — not a classical asymmetric alg
