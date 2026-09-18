import io
import ipaddress

import qrcode
from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import login_required

from .crypto import encrypt_psk
from .ephemeral import read_config, store_config
from .ipam import allocate_admin_ip, allocate_peer_ip, allocate_site_cidr
from .models import AdminPeer, Network, Peer, Site, db
from .sync import (
    reconcile,
    site_status_counts,
    status_snapshot,
)
from .wireguard import (
    generate_keypair,
    generate_psk,
    render_admin_peer_config,
    render_site_peer_config,
)

bp = Blueprint("main", __name__)


def _safe_name(name: str) -> str:
    return (
        name.lower()
        .replace(" ", "-")
        .replace("/", "-")
        .replace("\\", "-")
    )


def _flash_reconcile_result(result: dict):
    if result.get("dry_run"):
        flash(
            "Alteração validada. Controller está em DRY-RUN; "
            "o plano de dados não foi alterado.",
            "warning",
        )
    else:
        flash("WireGuard sincronizado.", "success")

    for warning in result.get("warnings", []):
        flash(warning, "warning")


def _restore_controller_after_rollback():
    try:
        reconcile()
    except Exception:
        pass


def _commit_with_reconcile(success_message: str):
    try:
        db.session.flush()
        result = reconcile()
        db.session.commit()
        flash(success_message, "success")
        _flash_reconcile_result(result)
        return True
    except Exception as exc:
        db.session.rollback()
        _restore_controller_after_rollback()
        flash(
            f"Alteração cancelada porque a sincronização falhou: {exc}",
            "danger",
        )
        return False


@bp.route("/")
@login_required
def dashboard():
    snapshot = status_snapshot()
    sites = Site.query.order_by(Site.name).all()
    admins = AdminPeer.query.order_by(AdminPeer.name).all()

    stats = {
        "sites": len(sites),
        "networks": Network.query.count(),
        "peers": Peer.query.count() + len(admins),
        **snapshot["counts"],
    }

    site_counts = {
        site.id: site_status_counts(site)
        for site in sites
    }

    return render_template(
        "dashboard.html",
        sites=sites,
        admins=admins,
        stats=stats,
        site_counts=site_counts,
        controller=snapshot["health"],
    )


@bp.route("/status")
@login_required
def status_page():
    return render_template(
        "status.html",
        snapshot=status_snapshot(),
    )


@bp.route("/status/data")
@login_required
def status_data():
    return jsonify(status_snapshot())


@bp.route("/system/reconcile", methods=["POST"])
@login_required
def system_reconcile():
    try:
        result = reconcile()
        _flash_reconcile_result(result)
    except Exception as exc:
        flash(f"Falha ao reconciliar: {exc}", "danger")

    return redirect(
        request.referrer or url_for("main.dashboard")
    )


@bp.route("/sites/new", methods=["GET", "POST"])
@login_required
def site_new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()

        if not name:
            flash("Informe o nome do Site.", "danger")
            return redirect(url_for("main.site_new"))

        if Site.query.filter_by(name=name).first():
            flash("Já existe um Site com esse nome.", "danger")
            return redirect(url_for("main.site_new"))

        site = Site(
            name=name,
            vpn_cidr=allocate_site_cidr(),
        )
        db.session.add(site)

        if _commit_with_reconcile(
            f"Site '{name}' criado."
        ):
            return redirect(
                url_for("main.site_detail", site_id=site.id)
            )

    return render_template("site_new.html")


@bp.route("/sites/<int:site_id>")
@login_required
def site_detail(site_id):
    status_snapshot()
    site = db.get_or_404(Site, site_id)
    return render_template("site_detail.html", site=site)


@bp.route("/sites/<int:site_id>/delete", methods=["POST"])
@login_required
def site_delete(site_id):
    site = db.get_or_404(Site, site_id)
    name = site.name
    db.session.delete(site)

    _commit_with_reconcile(
        f"Site '{name}' e seus Networks/Peers foram excluídos."
    )
    return redirect(url_for("main.dashboard"))


@bp.route("/sites/<int:site_id>/networks/new", methods=["POST"])
@login_required
def network_new(site_id):
    site = db.get_or_404(Site, site_id)
    cidr = request.form.get("cidr", "").strip()

    try:
        new_net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        flash("Network inválida.", "danger")
        return redirect(
            url_for("main.site_detail", site_id=site.id)
        )

    if new_net.version != 4:
        flash("A v0.4 aceita apenas IPv4 nas Networks.", "danger")
        return redirect(
            url_for("main.site_detail", site_id=site.id)
        )

    for row in Network.query.all():
        old_net = ipaddress.ip_network(row.cidr, strict=False)

        if row.site_id == site.id and new_net == old_net:
            flash("Essa Network já existe neste Site.", "warning")
            return redirect(
                url_for("main.site_detail", site_id=site.id)
            )

        if row.site_id != site.id and new_net.overlaps(old_net):
            flash(
                f"A rede {new_net} conflita com {old_net}, "
                f"já usada no Site '{row.site.name}'. "
                "Networks sobrepostas ainda não são suportadas.",
                "danger",
            )
            return redirect(
                url_for("main.site_detail", site_id=site.id)
            )

    row = Network(
        site_id=site.id,
        cidr=str(new_net),
    )
    db.session.add(row)

    changed = _commit_with_reconcile(
        f"Network {row.cidr} adicionada."
    )
    if changed and AdminPeer.query.count():
        flash(
            "Admin Peers existentes não recebem novos AllowedIPs automaticamente "
            "no cliente. Use 'Regenerar config' nos Admin Peers que precisam "
            "acessar esta nova Network.",
            "warning",
        )
    return redirect(
        url_for("main.site_detail", site_id=site.id)
    )


@bp.route("/networks/<int:network_id>/delete", methods=["POST"])
@login_required
def network_delete(network_id):
    network = db.get_or_404(Network, network_id)
    site_id = network.site_id
    cidr = network.cidr
    db.session.delete(network)

    _commit_with_reconcile(f"Network {cidr} excluída.")
    return redirect(
        url_for("main.site_detail", site_id=site_id)
    )


@bp.route("/sites/<int:site_id>/peers/new", methods=["GET", "POST"])
@login_required
def peer_new(site_id):
    site = db.get_or_404(Site, site_id)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        peer_type = request.form.get("peer_type", "client").strip()

        if not name:
            flash("Informe o nome do Peer.", "danger")
            return redirect(
                url_for("main.peer_new", site_id=site.id)
            )

        if peer_type not in ("gateway", "client"):
            abort(400)

        if peer_type == "gateway":
            gateway = Peer.query.filter_by(
                site_id=site.id,
                peer_type="gateway",
                enabled=True,
            ).first()

            if gateway:
                flash(
                    f"O Site já possui o Gateway ativo '{gateway.name}'. "
                    "A v0.4 permite um Gateway ativo por Site.",
                    "warning",
                )
                return redirect(
                    url_for("main.peer_new", site_id=site.id)
                )

        try:
            private_key, public_key = generate_keypair()
            preshared_key = generate_psk()

            peer = Peer(
                site_id=site.id,
                name=name,
                peer_type=peer_type,
                public_key=public_key,
                preshared_key_enc=encrypt_psk(preshared_key),
                assigned_ip=allocate_peer_ip(site),
            )
            db.session.add(peer)
            db.session.flush()

            config = render_site_peer_config(
                peer,
                private_key,
                preshared_key,
            )

            result = reconcile()
            db.session.commit()

        except Exception as exc:
            db.session.rollback()
            _restore_controller_after_rollback()
            flash(
                f"Não foi possível criar o Peer: {exc}",
                "danger",
            )
            return redirect(
                url_for("main.peer_new", site_id=site.id)
            )

        session[f"peer_token_{peer.id}"] = store_config(config)
        flash(
            "Peer criado com keypair + PresharedKey.",
            "success",
        )
        _flash_reconcile_result(result)

        return redirect(
            url_for("main.peer_created", peer_id=peer.id)
        )

    return render_template("peer_new.html", site=site)


@bp.route("/peers/<int:peer_id>/created")
@login_required
def peer_created(peer_id):
    peer = db.get_or_404(Peer, peer_id)
    config = read_config(
        session.get(f"peer_token_{peer.id}")
    )
    return render_template(
        "peer_created.html",
        peer=peer,
        config=config,
    )


@bp.route("/peers/<int:peer_id>/download")
@login_required
def peer_download(peer_id):
    peer = db.get_or_404(Peer, peer_id)
    config = read_config(
        session.get(f"peer_token_{peer.id}")
    )

    if not config:
        abort(410)

    return Response(
        config,
        mimetype="text/plain",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_safe_name(peer.name)}.conf"'
            )
        },
    )


@bp.route("/peers/<int:peer_id>/qr.png")
@login_required
def peer_qr(peer_id):
    peer = db.get_or_404(Peer, peer_id)
    config = read_config(
        session.get(f"peer_token_{peer.id}")
    )

    if not config:
        abort(410)

    img = qrcode.make(config)
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    return Response(buf.getvalue(), mimetype="image/png")


@bp.route("/peers/<int:peer_id>/rekey", methods=["POST"])
@login_required
def peer_rekey(peer_id):
    peer = db.get_or_404(Peer, peer_id)

    try:
        private_key, public_key = generate_keypair()
        preshared_key = generate_psk()

        peer.public_key = public_key
        peer.preshared_key_enc = encrypt_psk(preshared_key)
        peer.latest_handshake = None
        peer.endpoint = None
        peer.rx_bytes = 0
        peer.tx_bytes = 0
        db.session.flush()

        config = render_site_peer_config(
            peer,
            private_key,
            preshared_key,
        )
        result = reconcile()
        db.session.commit()

    except Exception as exc:
        db.session.rollback()
        _restore_controller_after_rollback()
        flash(f"Falha ao regenerar o Peer: {exc}", "danger")
        return redirect(
            url_for("main.site_detail", site_id=peer.site_id)
        )

    session[f"peer_token_{peer.id}"] = store_config(config)
    flash(
        "Credenciais regeneradas. A configuração anterior deixou de ser válida.",
        "success",
    )
    _flash_reconcile_result(result)
    return redirect(
        url_for("main.peer_created", peer_id=peer.id)
    )


@bp.route("/peers/<int:peer_id>/delete", methods=["POST"])
@login_required
def peer_delete(peer_id):
    peer = db.get_or_404(Peer, peer_id)
    site_id = peer.site_id
    name = peer.name

    session.pop(f"peer_token_{peer.id}", None)
    db.session.delete(peer)

    _commit_with_reconcile(f"Peer '{name}' excluído.")
    return redirect(
        url_for("main.site_detail", site_id=site_id)
    )


@bp.route("/admin-peers/new", methods=["GET", "POST"])
@login_required
def admin_peer_new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()

        if not name:
            flash("Informe o nome do Admin Peer.", "danger")
            return redirect(url_for("main.admin_peer_new"))

        try:
            private_key, public_key = generate_keypair()
            preshared_key = generate_psk()

            peer = AdminPeer(
                name=name,
                public_key=public_key,
                preshared_key_enc=encrypt_psk(preshared_key),
                assigned_ip=allocate_admin_ip(),
            )
            db.session.add(peer)
            db.session.flush()

            config = render_admin_peer_config(
                peer,
                private_key,
                preshared_key,
            )
            result = reconcile()
            db.session.commit()

        except Exception as exc:
            db.session.rollback()
            _restore_controller_after_rollback()
            flash(
                f"Não foi possível criar o Admin Peer: {exc}",
                "danger",
            )
            return redirect(url_for("main.admin_peer_new"))

        session[f"admin_token_{peer.id}"] = store_config(config)
        flash(
            "Admin Peer criado com keypair + PresharedKey.",
            "success",
        )
        _flash_reconcile_result(result)

        return redirect(
            url_for("main.admin_peer_created", peer_id=peer.id)
        )

    return render_template("admin_peer_new.html")


@bp.route("/admin-peers/<int:peer_id>/created")
@login_required
def admin_peer_created(peer_id):
    peer = db.get_or_404(AdminPeer, peer_id)
    config = read_config(
        session.get(f"admin_token_{peer.id}")
    )
    return render_template(
        "admin_peer_created.html",
        peer=peer,
        config=config,
    )


@bp.route("/admin-peers/<int:peer_id>/download")
@login_required
def admin_peer_download(peer_id):
    peer = db.get_or_404(AdminPeer, peer_id)
    config = read_config(
        session.get(f"admin_token_{peer.id}")
    )

    if not config:
        abort(410)

    return Response(
        config,
        mimetype="text/plain",
        headers={
            "Content-Disposition": (
                f'attachment; filename="admin-{_safe_name(peer.name)}.conf"'
            )
        },
    )


@bp.route("/admin-peers/<int:peer_id>/qr.png")
@login_required
def admin_peer_qr(peer_id):
    peer = db.get_or_404(AdminPeer, peer_id)
    config = read_config(
        session.get(f"admin_token_{peer.id}")
    )

    if not config:
        abort(410)

    img = qrcode.make(config)
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    return Response(buf.getvalue(), mimetype="image/png")


@bp.route("/admin-peers/<int:peer_id>/rekey", methods=["POST"])
@login_required
def admin_peer_rekey(peer_id):
    peer = db.get_or_404(AdminPeer, peer_id)

    try:
        private_key, public_key = generate_keypair()
        preshared_key = generate_psk()

        peer.public_key = public_key
        peer.preshared_key_enc = encrypt_psk(preshared_key)
        peer.latest_handshake = None
        peer.endpoint = None
        peer.rx_bytes = 0
        peer.tx_bytes = 0
        db.session.flush()

        config = render_admin_peer_config(
            peer,
            private_key,
            preshared_key,
        )
        result = reconcile()
        db.session.commit()

    except Exception as exc:
        db.session.rollback()
        _restore_controller_after_rollback()
        flash(
            f"Falha ao regenerar o Admin Peer: {exc}",
            "danger",
        )
        return redirect(url_for("main.dashboard"))

    session[f"admin_token_{peer.id}"] = store_config(config)
    flash(
        "Admin Peer regenerado com as Networks atuais. "
        "A configuração anterior deixou de ser válida.",
        "success",
    )
    _flash_reconcile_result(result)
    return redirect(
        url_for("main.admin_peer_created", peer_id=peer.id)
    )


@bp.route("/admin-peers/<int:peer_id>/delete", methods=["POST"])
@login_required
def admin_peer_delete(peer_id):
    peer = db.get_or_404(AdminPeer, peer_id)
    name = peer.name

    session.pop(f"admin_token_{peer.id}", None)
    db.session.delete(peer)

    _commit_with_reconcile(
        f"Admin Peer '{name}' excluído."
    )
    return redirect(url_for("main.dashboard"))
