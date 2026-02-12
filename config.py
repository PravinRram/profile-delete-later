import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")
    UPLOAD_FOLDER = os.environ.get(
        "UPLOAD_FOLDER",
        os.path.join(os.getcwd(), "instance", "uploads"),
    )
    _legacy_db = os.path.join(os.getcwd(), "instance", "kampongkoneck.db")
    _default_db = os.path.join(os.getcwd(), "instance", "kampongkonek.db")
    _db_path = _legacy_db if os.path.exists(_legacy_db) else _default_db
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + _db_path,
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024
