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


class VPNInstance(db.Model):
    __tablename__ = "vpn_instances"
    __table_args__ = (
        db.Index(
            "uq_default_vpn_instance",
            "is_default",
            unique=True,
            postgresql_where=db.text("is_default = true"),
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    interface_name = db.Column(db.String(32), unique=True, nullable=False)
    endpoint = db.Column(db.String(255), nullable=False)
    listen_port = db.Column(db.Integer, unique=True, nullable=False)
    vpn_pool = db.Column(db.String(64), nullable=False)
    server_address = db.Column(db.String(64), nullable=False)
    server_public_key = db.Column(db.String(128), nullable=False)
    private_key_path = db.Column(db.String(255), nullable=False)
    route_protocol = db.Column(db.Integer, nullable=False, default=186)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    is_default = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    sites = db.relationship("Site", back_populates="vpn_instance")
    admin_peers = db.relationship("AdminPeer", back_populates="vpn_instance")


class Site(db.Model):
    __tablename__ = "sites"
    __table_args__ = (
        db.UniqueConstraint(
            "vpn_instance_id",
            "name",
            name="uq_site_name_per_instance",
        ),
        db.UniqueConstraint(
            "vpn_instance_id",
            "vpn_cidr",
            name="uq_site_cidr_per_instance",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    vpn_instance_id = db.Column(
        db.Integer,
        db.ForeignKey("vpn_instances.id"),
        nullable=False,
        index=True,
    )
    name = db.Column(db.String(160), nullable=False, index=True)
    vpn_cidr = db.Column(db.String(64), nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    vpn_instance = db.relationship("VPNInstance", back_populates="sites")
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
    __table_args__ = (
        db.Index(
            "uq_active_gateway_per_site",
            "site_id",
            unique=True,
            postgresql_where=db.text(
                "peer_type = 'gateway' AND enabled = true"
            ),
        ),
        db.UniqueConstraint(
            "site_id",
            "assigned_ip",
            name="uq_peer_ip_per_site",
        ),
    )

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
    assigned_ip = db.Column(db.String(64), nullable=False, index=True)

    enabled = db.Column(db.Boolean, default=True, nullable=False)

    latest_handshake = db.Column(db.DateTime, nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    rx_bytes = db.Column(db.BigInteger, default=0, nullable=False)
    tx_bytes = db.Column(db.BigInteger, default=0, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    site = db.relationship("Site", back_populates="peers")


class AdminPeer(db.Model):
    __tablename__ = "admin_peers"
    __table_args__ = (
        db.UniqueConstraint(
            "vpn_instance_id",
            "assigned_ip",
            name="uq_admin_peer_ip_per_instance",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    vpn_instance_id = db.Column(
        db.Integer,
        db.ForeignKey("vpn_instances.id"),
        nullable=False,
        index=True,
    )
    name = db.Column(db.String(160), nullable=False)

    public_key = db.Column(db.String(128), unique=True, nullable=False, index=True)
    preshared_key_enc = db.Column(db.Text, nullable=True)
    assigned_ip = db.Column(db.String(64), nullable=False, index=True)

    enabled = db.Column(db.Boolean, default=True, nullable=False)

    latest_handshake = db.Column(db.DateTime, nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    rx_bytes = db.Column(db.BigInteger, default=0, nullable=False)
    tx_bytes = db.Column(db.BigInteger, default=0, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    vpn_instance = db.relationship("VPNInstance", back_populates="admin_peers")
