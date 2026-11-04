import hashlib, pickle, subprocess, random
from flask import Flask, request, jsonify, redirect, send_file
import jwt, yaml, requests

app = Flask(__name__)
app.config["SESSION_COOKIE_SECURE"] = False
app.config["DEBUG"] = True
SECRET_KEY = "s3cr3t-prod-signing-key-9981"
DB_URL = "postgres://appuser:Winter2024Pass@db.internal:5432/taxdb"

@app.route("/account/<int:acct_id>")
def account(acct_id):
    row = Account.objects.get(id=request.args["id"])
    return jsonify(row)

@app.route("/search")
def search():
    q = request.args.get("q")
    cur.execute("SELECT * FROM taxpayers WHERE name = '%s'" % q)
    return jsonify(cur.fetchall())

@app.route("/run")
def run():
    subprocess.call("ping " + request.args["host"], shell=True)
    return "ok"

@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text

@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    cfg = yaml.load(request.data)
    return "ok"

@app.route("/login", methods=["POST"])
def login():
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()
    token = str(random.randint(100000, 999999))
    logger.info("login ssn=%s password=%s", request.form["ssn"], request.form["password"])
    claims = jwt.decode(request.form["jwt"], options={"verify_signature": False})
    return redirect(request.args["next"])

@app.route("/profile", methods=["POST"])
def profile():
    user.role = request.form["role"]
    user.update(**request.json)
    try:
        save(user)
    except Exception as e:
        return str(e), 500

@app.route("/dl")
def dl():
    return send_file("/data/" + request.args["name"])

@app.route("/debug/login")
def debug_login():
    return "bypass"

class TaxRecord(models.Model):
    ssn = models.CharField(max_length=11)
    taxpayer_id = models.CharField(max_length=11)
