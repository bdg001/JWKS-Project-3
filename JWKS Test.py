import unittest
import http.client
import json

class TestMyServer(unittest.TestCase):
    def setUp(self):
        # Set up an HTTP connection to the server
        self.connection = http.client.HTTPConnection("localhost", 8080)
        
    def tearDown(self):
        # Clean up after the test
        self.connection.close()
        
    def test_well_known_jwks(self):
        # Test if the public keys are retrievable
        self.connection.request("GET", "/.well-known/jwks.json")
        response = self.connection.getresponse()
        
        self.assertEqual(response.status, 200)
        content_type = response.getheader("Content-Type")
        self.assertEqual(content_type, "application/json")
        
        data = response.read()
        keys = json.loads(data)
        
        # Verify the structure of the JWKS
        self.assertTrue("keys" in keys)
        self.assertEqual(len(keys["keys"]), 1)  # Assumes one key
        
        key = keys["keys"][0]
        self.assertEqual(key["alg"], "HS256")
        self.assertEqual(key["kty"], "AES")
        self.assertEqual(key["use"], "sig")
        self.assertTrue("kid" in key)
        
    def test_auth_endpoint(self):
        # Test JWT generation at the /auth endpoint
        self.connection.request("POST", "/auth")
        response = self.connection.getresponse()
        
        self.assertEqual(response.status, 200)
        
        data = response.read()
        jwt_token = data.decode("utf-8")
        
        # You can add more assertions to validate the JWT token if needed

    def test_register_endpoint(self):
        # Test user registration at the /register endpoint
        headers = {"Content-Type": "application/json"}
        data = {"username": "testuser", "email": "test@example.com"}
        json_data = json.dumps(data)
        
        self.connection.request("POST", "/register", body=json_data, headers=headers)
        response = self.connection.getresponse()
        
        self.assertEqual(response.status, 201)
        
        data = response.read()
        result = json.loads(data)
        
        # Add assertions based on your registration endpoint response format
        self.assertTrue("password" in result)

if __name__ == '__main__':
    unittest.main()