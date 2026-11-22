"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import sqlite3
from flask import Flask, g, jsonify, request, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import os 
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta
from functools import wraps

DATABASE = "recipes.db"

load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")

app = Flask(__name__)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if auth_header is None:
            return jsonify({"error": "Authorization header missing"}), 401

        parts = auth_header.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"error": "Invalid Authorization header format"}), 401

        token = parts[1]

        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired, please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        # pull identity out of the token and store on g
        g.user_id = payload.get("sub")
        g.role = payload.get("role")

        # call the original route
        return f(*args, **kwargs)

    return decorated


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }


@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))


@app.post("/recipes")
@token_required
def create_recipe():

    user_id = g.user_id
    
    data = request.get_json(silent=True)
    
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    
    db = get_db()
    
    try:
        owner_id = int(user_id)
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
                owner_id,
            ),
        )
        db.commit()
    
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
   
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201


@app.patch("/recipes/<int:recipe_id>")
@token_required
def update_recipe(recipe_id):
 
    user_id = g.user_id
    role = g.role

    db = get_db()

    recipe_row = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,)
    ).fetchone()

    if recipe_row is None:
        return jsonify({"error": "recipe not found"}), 404

    owner_id = recipe_row["owner_id"]

    if role == "admin":
        pass 
    
    elif str(owner_id) != str(user_id):
        return jsonify({"error": "forbidden"}), 403   

    data = request.get_json(silent=True)
    
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    fields, values = [], []
    
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    values.append(recipe_id)
    db = get_db()
    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))


@app.delete("/recipes/<int:recipe_id>")
@token_required
def delete_recipe(recipe_id):
    user_id = g.user_id
    role = g.role

    db = get_db()
    
    recipe_row = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,)
    ).fetchone()
    
    if recipe_row is None:
        return jsonify({"error": "recipe not found"}), 404
    
    owner_id = recipe_row["owner_id"]
    
    if role == "admin":
        pass 
        
    elif str(owner_id) != str(user_id):
        return jsonify({"error": "forbidden"}), 403  
    db = get_db()
    cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    return "", 204

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if (
        not data
        or not data.get("username")
        or not data.get("email")
        or not data.get("password")
    ):
        return jsonify({"error": "username, email, and password are required"}), 400
    
    db = get_db()
    password_hash = generate_password_hash(data["password"])

    try:
        cur = db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (data ["username"], data["email"], password_hash, "user"),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username or email already exists"}), 409

    return jsonify({"id": cur.lastrowid, "username":data["username"], "email": data["email"]}),201
    
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "username and password are required"}), 400

    db = get_db()
    cur = db.execute(
        "SELECT id, username, email, password_hash, role FROM users WHERE username = ?",
        (data["username"],),
    )
    user = cur.fetchone()

    # same generic response for any bad credentials
    invalid_response = (jsonify({"error": "invalid credentials"}), 401)

    if user is None:
        return invalid_response

    if not check_password_hash(user["password_hash"], data["password"]):
        return invalid_response

    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(hours=1)
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")


    return jsonify({"token": token}), 200

    # 4. if ok -> return id + username

if __name__ == "__main__":
    app.run(debug=True, port=5001)
