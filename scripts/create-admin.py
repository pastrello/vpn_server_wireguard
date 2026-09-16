#!/usr/bin/env python3
from pathlib import Path
import getpass
import sys

# Garante que a raiz do projeto (/opt/vpnhub) entre no sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vpnhub import create_app
from vpnhub.models import db, User
from vpnhub.security import hash_password


app = create_app()

with app.app_context():
    username = input("Usuário administrador: ").strip()

    if User.query.filter_by(username=username).first():
        raise SystemExit("Usuário já existe.")

    password = getpass.getpass("Senha: ")
    password2 = getpass.getpass("Repita a senha: ")

    if password != password2:
        raise SystemExit("As senhas não conferem.")

    if len(password) < 8:
        raise SystemExit("Use uma senha com pelo menos 8 caracteres.")

    row = User(
        username=username,
        password_hash=hash_password(password),
    )

    db.session.add(row)
    db.session.commit()

    print("Administrador criado com sucesso.")
