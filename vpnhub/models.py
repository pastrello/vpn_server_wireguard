from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Site(db.Model):
    __tablename__ = "sites"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), unique=True, nullable=False, index=True)
    vpn_cidr = db.Column(db.String(64), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    networks = db.relationship(
        "Network",
        back_populates="site",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    peers = db.relationship(
        "Peer",
        back_populates="site",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Network(db.Model):
    __tablename__ = "networks"

    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(
        db.Integer,
        db.ForeignKey("sites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cidr = db.Column(db.String(64), nullable=False, index=True)
    translated_cidr = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    site = db.relationship("Site", back_populates="networks")


class Peer(db.Model):
    __tablename__ = "peers"

    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(
        db.Integer,
        db.ForeignKey("sites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name = db.Column(db.String(160), nullable=False)
    peer_type = db.Column(db.String(20), nullable=False, default="client")

    public_key = db.Column(db.String(128), unique=True, nullable=False, index=True)
    preshared_key_enc = db.Column(db.Text, nullable=True)
    assigned_ip = db.Column(db.String(64), unique=True, nullable=False, index=True)

    enabled = db.Column(db.Boolean, default=True, nullable=False)

    latest_handshake = db.Column(db.DateTime, nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    rx_bytes = db.Column(db.BigInteger, default=0, nullable=False)
    tx_bytes = db.Column(db.BigInteger, default=0, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    site = db.relationship("Site", back_populates="peers")


class AdminPeer(db.Model):
    __tablename__ = "admin_peers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)

    public_key = db.Column(db.String(128), unique=True, nullable=False, index=True)
    preshared_key_enc = db.Column(db.Text, nullable=True)
    assigned_ip = db.Column(db.String(64), unique=True, nullable=False, index=True)

    enabled = db.Column(db.Boolean, default=True, nullable=False)

    latest_handshake = db.Column(db.DateTime, nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    rx_bytes = db.Column(db.BigInteger, default=0, nullable=False)
    tx_bytes = db.Column(db.BigInteger, default=0, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
