#!/usr/bin/env python3
import secrets
from cryptography.fernet import Fernet

print(f"SECRET_KEY={secrets.token_urlsafe(48)}")
print(f"PSK_ENCRYPTION_KEY={Fernet.generate_key().decode('ascii')}")
