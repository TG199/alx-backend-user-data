#!/usr/bin/env python3
""" Simple Flask app"""
from flask import Flask, jsonify, request
from auth import Auth


app = Flask(__name__)


AUTH = Auth()


@app.route("/", methods=["GET"])
def welcome():
    """Returns a JSON response with a welcome message"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register_user():
    """Registers a new user if email is not already registered."""
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return jsonify({"message": "email and password are required"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
