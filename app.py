import os, uuid, json, ipaddress
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    jsonify, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, current_user, logout_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

import qrcode
from io import BytesIO

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///votacao.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "admin_login"

# -------------------- MODELS --------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

class Assembly(db.Model):  # Assembleia
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_open = db.Column(db.Boolean, default=True)
    require_100_percent = db.Column(db.Boolean, default=bool(int(os.getenv("REQUIRE_100_PERCENT","1"))))

    # conveniência
    def present_count(self):
        return Attendee.query.filter_by(assembly_id=self.id, present=True, can_vote=True).count()

class Attendee(db.Model):  # Membro presente
    id = db.Column(db.Integer, primary_key=True)
    assembly_id = db.Column(db.Integer, db.ForeignKey("assembly.id"), index=True)
    full_name = db.Column(db.String(160), nullable=False)
    present = db.Column(db.Boolean, default=True)
    can_vote = db.Column(db.Boolean, default=True)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assembly_id = db.Column(db.Integer, db.ForeignKey("assembly.id"), index=True)
    name = db.Column(db.String(160), nullable=False)
    office = db.Column(db.String(40), default="presbitero")  # futuro: diacono, pastor (eleição)
    eligible = db.Column(db.Boolean, default=True)

class Scrutiny(db.Model):  # Escrutínio
    id = db.Column(db.Integer, primary_key=True)
    assembly_id = db.Column(db.Integer, db.ForeignKey("assembly.id"), index=True)
    title = db.Column(db.String(160), nullable=False)
    round_number = db.Column(db.Integer, default=1)
    office = db.Column(db.String(40), default="presbitero")
    vagas = db.Column(db.Integer, default=1)
    min_choices = db.Column(db.Integer, default=1)
    max_choices = db.Column(db.Integer, default=1)
    is_open = db.Column(db.Boolean, default=False)
    closed_at = db.Column(db.DateTime)

class VoteReceipt(db.Model):  # controla quem JÁ votou (sem revelar conteúdo)
    id = db.Column(db.Integer, primary_key=True)
    assembly_id = db.Column(db.Integer, index=True)
    scrutiny_id = db.Column(db.Integer, index=True)
    attendee_id = db.Column(db.Integer, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('scrutiny_id', 'attendee_id', name='one_vote_per_round'),)

class Ballot(db.Model):  # cédula anônima
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    assembly_id = db.Column(db.Integer, index=True)
    scrutiny_id = db.Column(db.Integer, index=True)
    selections_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -------------------- LOGIN --------------------

@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            flash("Acesso restrito ao administrador.", "danger")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

# -------------------- BOOTSTRAP ADMIN --------------------

# Flask 3: before_first_request foi removido
@app.before_request
def bootstrap_admin():
    if getattr(app, "_bootstrapped", False):
        return
    email = os.getenv("ADMIN_EMAIL", "admin@igreja.local")
    pwd = os.getenv("ADMIN_PASSWORD", "admin123")
    u = User.query.filter_by(email=email).first()
    if not u:
        u = User(email=email, is_admin=True)
        u.set_password(pwd)
        db.session.add(u)
        db.session.commit()
    app._bootstrapped = True


# -------------------- HELPERS --------------------

def current_assembly():
    return Assembly.query.filter_by(is_open=True).order_by(Assembly.id.desc()).first()

def tally(scrutiny_id:int):
    """Retorna contagem por candidato e percentuais."""
    scr = Scrutiny.query.get(scrutiny_id)
    ballots = Ballot.query.filter_by(scrutiny_id=scrutiny_id).all()
    counts = {}
    for b in ballots:
        sel = json.loads(b.selections_json)
        for cid in sel:
            counts[cid] = counts.get(cid, 0) + 1

    present = Assembly.query.get(scr.assembly_id).present_count()
    # percentuais sobre PRESENTES (regra IPB: >50% dos presentes)
    results = []
    for c in Candidate.query.filter_by(assembly_id=scr.assembly_id, office=scr.office, eligible=True).all():
        v = counts.get(c.id, 0)
        pct_present = (v / present * 100.0) if present else 0.0
        results.append({"candidate": c, "votes": v, "pct_present": pct_present})
    results.sort(key=lambda x: x["votes"], reverse=True)
    return results, present, len(ballots)

# -------------------- ROTAS PÚBLICAS --------------------

@app.route("/")
def index():
    asm = current_assembly()
    return render_template("index.html", assembly=asm)

@app.route("/join", methods=["GET","POST"])
def join():
    asm = current_assembly()
    if not asm:
        flash("Nenhuma assembleia aberta no momento.", "warning")
        return redirect(url_for("index"))
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        att = Attendee.query.filter(
            Attendee.assembly_id==asm.id,
            db.func.lower(Attendee.full_name)==name.lower(),
            Attendee.present==True,
            Attendee.can_vote==True
        ).first()
        if not att:
            flash("Nome não encontrado ou não habilitado para votar.", "danger")
            return redirect(url_for("join"))
        session["attendee_id"] = att.id
        return redirect(url_for("vote"))
    return render_template("join.html", assembly=asm)

@app.route("/vote", methods=["GET","POST"])
def vote():
    asm = current_assembly()
    if not asm:
        flash("Nenhuma assembleia aberta.", "warning")
        return redirect(url_for("index"))
    att_id = session.get("attendee_id")
    if not att_id:
        flash("Identifique-se para votar.", "warning")
        return redirect(url_for("join"))
    scr = Scrutiny.query.filter_by(assembly_id=asm.id, is_open=True).order_by(Scrutiny.id.desc()).first()
    if not scr:
        return render_template("waiting.html", assembly=asm)

    # Já votou?
    already = VoteReceipt.query.filter_by(scrutiny_id=scr.id, attendee_id=att_id).first()
    if request.method == "POST":
        if already:
            flash("Seu voto para este escrutínio já foi registrado.", "info")
            return redirect(url_for("vote"))
        selected_ids = request.form.getlist("candidates")  # lista de strings
        selected_ids = [int(x) for x in selected_ids]
        if len(selected_ids) < scr.min_choices or len(selected_ids) > scr.max_choices:
            flash(f"Selecione entre {scr.min_choices} e {scr.max_choices} nomes.", "danger")
            return redirect(url_for("vote"))
        # grava cédula anônima
        b = Ballot(assembly_id=asm.id, scrutiny_id=scr.id, selections_json=json.dumps(selected_ids))
        db.session.add(b)
        # marca que este participante votou
        r = VoteReceipt(assembly_id=asm.id, scrutiny_id=scr.id, attendee_id=att_id)
        db.session.add(r)
        db.session.commit()
        return render_template("thanks.html", assembly=asm)

    # lista de candidatos desta assembleia/office
    cands = Candidate.query.filter_by(assembly_id=asm.id, office=scr.office, eligible=True).order_by(Candidate.name).all()
    return render_template("vote.html", assembly=asm, scrutiny=scr, candidates=cands, already=bool(already))

@app.route("/qrcode")
@admin_required
def qrcode_join():
    asm = current_assembly()
    if not asm:
        flash("Abra uma assembleia primeiro.", "warning")
        return redirect(url_for("admin_dashboard"))
    # tenta inferir endereço de rede local:
    host = request.host.split(":")[0]
    try:
        ipaddress.ip_address(host)
        base = f"http://{host}:5002"
    except ValueError:
        base = request.host_url.rstrip("/")
    url = f"{base}{url_for('join')}"
    img = qrcode.make(url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

# -------------------- ROTAS ADMIN --------------------

@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email") or ""
        pwd = request.form.get("password") or ""
        u = User.query.filter_by(email=email).first()
        if u and u.check_password(pwd):
            login_user(u)
            return redirect(url_for("admin_dashboard"))
        flash("Credenciais inválidas.", "danger")
    return render_template("admin_login.html")

@app.route("/admin/logout")
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    asm = current_assembly()
    scr = Scrutiny.query.filter_by(assembly_id=asm.id).order_by(Scrutiny.id.desc()).first() if asm else None
    cands = Candidate.query.filter_by(assembly_id=asm.id).order_by(Candidate.name).all() if asm else []
    attendees = Attendee.query.filter_by(assembly_id=asm.id).order_by(Attendee.full_name).all() if asm else []
    open_scr = Scrutiny.query.filter_by(assembly_id=asm.id, is_open=True).first() if asm else None
    stats = {}
    if asm and scr:
        results, present, ballots = tally(scr.id)
        voted = VoteReceipt.query.filter_by(scrutiny_id=scr.id).count()
        stats = {"present": present, "voted": voted, "ballots": ballots, "open_scr": bool(open_scr)}
    return render_template("admin_dashboard.html", assembly=asm, scrutiny=scr, candidates=cands, attendees=attendees, stats=stats)

@app.route("/admin/assembly/new", methods=["POST"])
@admin_required
def admin_new_assembly():
    name = (request.form.get("name") or "").strip()
    req100 = (request.form.get("req100") == "on")
    # fecha anteriores
    Assembly.query.update({Assembly.is_open: False})
    asm = Assembly(name=name or f"Assembleia {datetime.now():%d/%m/%Y}", is_open=True, require_100_percent=req100)
    db.session.add(asm)
    db.session.commit()
    flash("Assembleia aberta.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/attendee/add", methods=["POST"])
@admin_required
def admin_add_attendee():
    asm = current_assembly()
    if not asm: 
        flash("Abra uma assembleia primeiro.", "warning")
        return redirect(url_for("admin_dashboard"))
    name = (request.form.get("full_name") or "").strip()
    if not name:
        flash("Informe o nome.", "danger")
        return redirect(url_for("admin_dashboard"))
    a = Attendee(assembly_id=asm.id, full_name=name, present=True, can_vote=True)
    db.session.add(a)
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/candidate/add", methods=["POST"])
@admin_required
def admin_add_candidate():
    asm = current_assembly()
    name = (request.form.get("name") or "").strip()
    if not asm or not name:
        return redirect(url_for("admin_dashboard"))
    c = Candidate(assembly_id=asm.id, name=name, office="presbitero", eligible=True)
    db.session.add(c)
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/attendee/toggle/<int:aid>")
@admin_required
def admin_toggle_attendee(aid):
    a = Attendee.query.get_or_404(aid)
    a.present = not a.present
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/candidate/toggle/<int:cid>")
@admin_required
def admin_toggle_candidate(cid):
    c = Candidate.query.get_or_404(cid)
    c.eligible = not c.eligible
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/scrutiny/open", methods=["POST"])
@admin_required
def admin_open_scrutiny():
    asm = current_assembly()
    if not asm:
        flash("Abra uma assembleia primeiro.", "warning")
        return redirect(url_for("admin_dashboard"))
    # fecha anteriores
    Scrutiny.query.filter_by(assembly_id=asm.id, is_open=True).update({Scrutiny.is_open: False})
    title = (request.form.get("title") or "").strip() or "Presbíteros"
    vagas = int(request.form.get("vagas") or 1)
    minc = int(request.form.get("min_choices") or 1)
    maxc = int(request.form.get("max_choices") or vagas)
    round_number = 1 + (db.session.query(db.func.max(Scrutiny.round_number)).filter_by(assembly_id=asm.id, office="presbitero").scalar() or 0)
    scr = Scrutiny(assembly_id=asm.id, title=f"{title} — {round_number}º escrutínio",
                   round_number=round_number, office="presbitero",
                   vagas=vagas, min_choices=minc, max_choices=maxc, is_open=True)
    db.session.add(scr)
    db.session.commit()
    flash("Escrutínio aberto.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/scrutiny/close/<int:sid>")
@admin_required
def admin_close_scrutiny(sid):
    scr = Scrutiny.query.get_or_404(sid)
    scr.is_open = False
    scr.closed_at = datetime.utcnow()
    db.session.commit()
    flash("Escrutínio encerrado.", "info")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/api/status")
@admin_required
def admin_api_status():
    asm = current_assembly()
    if not asm:
        return jsonify({"ok": True, "present": 0, "voted": 0, "ballots": 0})
    scr = Scrutiny.query.filter_by(assembly_id=asm.id).order_by(Scrutiny.id.desc()).first()
    if not scr:
        return jsonify({"ok": True, "present": asm.present_count(), "voted": 0, "ballots": 0})
    results, present, ballots = tally(scr.id)
    voted = VoteReceipt.query.filter_by(scrutiny_id=scr.id).count()
    return jsonify({"ok": True, "present": present, "voted": voted, "ballots": ballots})

@app.route("/admin/results/<int:sid>")
@admin_required
def admin_results(sid):
    scr = Scrutiny.query.get_or_404(sid)
    results, present, ballots = tally(scr.id)
    # aplica regra: eleitos com >50% dos PRESENTES, limitando às vagas
    winners = [r for r in results if r["pct_present"] > 50.0][:scr.vagas]
    return render_template("results.html", scrutiny=scr, results=results, present=present, ballots=ballots, winners=winners)

# -------------------- TEMPLATES MIN --------------------

@app.route("/seed-demo")
@admin_required
def seed_demo():
    # utilitário: cria assembleia, 5 candidatos e 20 presentes
    Assembly.query.update({Assembly.is_open: False})
    asm = Assembly(name="AGE Eleição de Presbíteros", is_open=True)
    db.session.add(asm); db.session.flush()
    for n in ["João", "Maria", "Pedro", "Ana", "Lucas", "Paulo", "Rute", "Débora", "Tiago", "Lídia",
              "Marcos","Carla","Bruna","Felipe","Guilherme","Sara","Noemi","Davi","Elisa","Raquel"]:
        db.session.add(Attendee(assembly_id=asm.id, full_name=n, present=True, can_vote=True))
    for c in ["Presb. Alberto", "Presb. Bernardo", "Presb. Carlos", "Presb. Daniel", "Presb. Eduardo"]:
        db.session.add(Candidate(assembly_id=asm.id, name=c, eligible=True))
    db.session.commit()
    flash("Demo criada. Vá ao painel admin.", "success")
    return redirect(url_for("admin_dashboard"))

# -------------------- VIEWS --------------------

@app.route("/healthz")
def healthz():
    return "ok", 200

if __name__ == "__main__":
    import os
    port = int(os.getenv("PORT", "5002"))
    app.run(host="0.0.0.0", port=port)
