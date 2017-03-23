from unittest import TestCase
import pamphlet

class TestApp(pamphlet.PamApplication):
    def conversation(self, messages):
        for message in messages:
            if not message.wants_password:
                yield "testuser"
            else:
                yield "test password"

class AuthTest(TestCase):
    def test_authentication(self):
        app = TestApp('authtest')
        app.authenticate()
