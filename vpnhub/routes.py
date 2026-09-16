import io
import ipaddress
import qrcode
from flask import Blueprint, Response, abort, flash, redirect, render_template, request, session, url_for
from flask_login import login_required
from .crypto import encrypt_psk
from .ephemeral import read_config, store_config
from .ipam import allocate_admin_ip, allocate_peer_ip, allocate_site_cidr
from .models import AdminPeer, Network, Peer, Site, db
from .sync import reconcile, refresh_status
from .wireguard import generate_keypair, generate_psk, render_admin_peer_config, render_site_peer_config

bp = Blueprint("main", __name__)


def _safe_name(name: str) -> str:
    return name.lower().replace(" ", "-").replace("/", "-").replace("\\", "-")


def _reconcile_with_flash():
    try:
        result = reconcile()
        if result.get("dry_run"):
            flash("Alteração salva. Controller está em DRY-RUN; WireGuard não foi alterado.", "warning")
        else:
            flash("WireGuard sincronizado.", "success")
        for warning in result.get("warnings", []):
            flash(warning, "warning")
        return True
    except Exception as exc:
        flash(f"Alteração salva no portal, mas a sincronização falhou: {exc}", "danger")
        return False


@bp.route("/")
@login_required
def dashboard():
    status = refresh_status()
    sites = Site.query.order_by(Site.name).all()
    admins = AdminPeer.query.order_by(AdminPeer.name).all()
    stats = {
        "sites": len(sites),
        "networks": Network.query.count(),
        "peers": Peer.query.count(),
        "admins": len(admins),
    }
    return render_template("dashboard.html", sites=sites, admins=admins, stats=stats, controller=status)


@bp.route("/system/reconcile", methods=["POST"])
@login_required
def system_reconcile():
    _reconcile_with_flash()
    return redirect(request.referrer or url_for("main.dashboard"))


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
        site = Site(name=name, vpn_cidr=allocate_site_cidr())
        db.session.add(site)
        db.session.commit()
        flash(f"Site '{site.name}' criado.", "success")
        _reconcile_with_flash()
        return redirect(url_for("main.site_detail", site_id=site.id))
    return render_template("site_new.html")


@bp.route("/sites/<int:site_id>")
@login_required
def site_detail(site_id):
    refresh_status()
    site = db.get_or_404(Site, site_id)
    return render_template("site_detail.html", site=site)


@bp.route("/sites/<int:site_id>/delete", methods=["POST"])
@login_required
def site_delete(site_id):
    site = db.get_or_404(Site, site_id)
    name = site.name
    db.session.delete(site)
    db.session.commit()
    flash(f"Site '{name}' e seus Networks/Peers foram excluídos.", "success")
    _reconcile_with_flash()
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
        return redirect(url_for("main.site_detail", site_id=site.id))
    if new_net.version != 4:
        flash("A v0.3 aceita apenas IPv4 nas Networks.", "danger")
        return redirect(url_for("main.site_detail", site_id=site.id))
    for row in Network.query.all():
        old_net = ipaddress.ip_network(row.cidr, strict=False)
        if row.site_id == site.id and new_net == old_net:
            flash("Essa Network já existe neste Site.", "warning")
            return redirect(url_for("main.site_detail", site_id=site.id))
        if row.site_id != site.id and new_net.overlaps(old_net):
            flash(f"A rede {new_net} conflita com {old_net}, já usada no Site '{row.site.name}'. Networks sobrepostas ainda não são suportadas.", "danger")
            return redirect(url_for("main.site_detail", site_id=site.id))
    row = Network(site_id=site.id, cidr=str(new_net))
    db.session.add(row)
    db.session.commit()
    flash(f"Network {row.cidr} adicionada.", "success")
    _reconcile_with_flash()
    return redirect(url_for("main.site_detail", site_id=site.id))


@bp.route("/networks/<int:network_id>/delete", methods=["POST"])
@login_required
def network_delete(network_id):
    network = db.get_or_404(Network, network_id)
    site_id, cidr = network.site_id, network.cidr
    db.session.delete(network)
    db.session.commit()
    flash(f"Network {cidr} excluída.", "success")
    _reconcile_with_flash()
    return redirect(url_for("main.site_detail", site_id=site_id))


@bp.route("/sites/<int:site_id>/peers/new", methods=["GET", "POST"])
@login_required
def peer_new(site_id):
    site = db.get_or_404(Site, site_id)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        peer_type = request.form.get("peer_type", "client").strip()
        if not name:
            flash("Informe o nome do Peer.", "danger")
            return redirect(url_for("main.peer_new", site_id=site.id))
        if peer_type not in ("gateway", "client"):
            abort(400)
        try:
            private_key, public_key = generate_keypair()
            preshared_key = generate_psk()
            peer = Peer(
                site_id=site.id, name=name, peer_type=peer_type,
                public_key=public_key, preshared_key_enc=encrypt_psk(preshared_key),
                assigned_ip=allocate_peer_ip(site),
            )
            db.session.add(peer)
            db.session.commit()
            config = render_site_peer_config(peer, private_key, preshared_key)
        except Exception as exc:
            db.session.rollback()
            flash(f"Não foi possível criar o Peer: {exc}", "danger")
            return redirect(url_for("main.peer_new", site_id=site.id))
        session[f"peer_token_{peer.id}"] = store_config(config)
        flash("Peer criado com keypair + PresharedKey.", "success")
        _reconcile_with_flash()
        return redirect(url_for("main.peer_created", peer_id=peer.id))
    return render_template("peer_new.html", site=site)


@bp.route("/peers/<int:peer_id>/created")
@login_required
def peer_created(peer_id):
    peer = db.get_or_404(Peer, peer_id)
    config = read_config(session.get(f"peer_token_{peer.id}"))
    return render_template("peer_created.html", peer=peer, config=config)


@bp.route("/peers/<int:peer_id>/download")
@login_required
def peer_download(peer_id):
    peer = db.get_or_404(Peer, peer_id)
    config = read_config(session.get(f"peer_token_{peer.id}"))
    if not config:
        abort(410)
    return Response(config, mimetype="text/plain", headers={"Content-Disposition": f'attachment; filename="{_safe_name(peer.name)}.conf"'})


@bp.route("/peers/<int:peer_id>/qr.png")
@login_required
def peer_qr(peer_id):
    peer = db.get_or_404(Peer, peer_id)
    config = read_config(session.get(f"peer_token_{peer.id}"))
    if not config:
        abort(410)
    img = qrcode.make(config)
    buf = io.BytesIO(); img.save(buf, format="PNG")
    return Response(buf.getvalue(), mimetype="image/png")


@bp.route("/peers/<int:peer_id>/delete", methods=["POST"])
@login_required
def peer_delete(peer_id):
    peer = db.get_or_404(Peer, peer_id)
    site_id, name = peer.site_id, peer.name
    session.pop(f"peer_token_{peer.id}", None)
    db.session.delete(peer)
    db.session.commit()
    flash(f"Peer '{name}' excluído.", "success")
    _reconcile_with_flash()
    return redirect(url_for("main.site_detail", site_id=site_id))


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
            peer = AdminPeer(name=name, public_key=public_key, preshared_key_enc=encrypt_psk(preshared_key), assigned_ip=allocate_admin_ip())
            db.session.add(peer)
            db.session.commit()
            config = render_admin_peer_config(peer, private_key, preshared_key)
        except Exception as exc:
            db.session.rollback()
            flash(f"Não foi possível criar o Admin Peer: {exc}", "danger")
            return redirect(url_for("main.admin_peer_new"))
        session[f"admin_token_{peer.id}"] = store_config(config)
        flash("Admin Peer criado com keypair + PresharedKey.", "success")
        _reconcile_with_flash()
        return redirect(url_for("main.admin_peer_created", peer_id=peer.id))
    return render_template("admin_peer_new.html")


@bp.route("/admin-peers/<int:peer_id>/created")
@login_required
def admin_peer_created(peer_id):
    peer = db.get_or_404(AdminPeer, peer_id)
    return render_template("admin_peer_created.html", peer=peer, config=read_config(session.get(f"admin_token_{peer.id}")))


@bp.route("/admin-peers/<int:peer_id>/download")
@login_required
def admin_peer_download(peer_id):
    peer = db.get_or_404(AdminPeer, peer_id)
    config = read_config(session.get(f"admin_token_{peer.id}"))
    if not config:
        abort(410)
    return Response(config, mimetype="text/plain", headers={"Content-Disposition": f'attachment; filename="admin-{_safe_name(peer.name)}.conf"'})


@bp.route("/admin-peers/<int:peer_id>/qr.png")
@login_required
def admin_peer_qr(peer_id):
    peer = db.get_or_404(AdminPeer, peer_id)
    config = read_config(session.get(f"admin_token_{peer.id}"))
    if not config:
        abort(410)
    img = qrcode.make(config)
    buf = io.BytesIO(); img.save(buf, format="PNG")
    return Response(buf.getvalue(), mimetype="image/png")


@bp.route("/admin-peers/<int:peer_id>/delete", methods=["POST"])
@login_required
def admin_peer_delete(peer_id):
    peer = db.get_or_404(AdminPeer, peer_id)
    name = peer.name
    session.pop(f"admin_token_{peer.id}", None)
    db.session.delete(peer)
    db.session.commit()
    flash(f"Admin Peer '{name}' excluído.", "success")
    _reconcile_with_flash()
    return redirect(url_for("main.dashboard"))
