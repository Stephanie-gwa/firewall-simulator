import pytest

from firewall_sim.webapp import create_app


@pytest.fixture
def app():
    application = create_app(":memory:", seed=True)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def store(app):
    return app.config["STORE"]
