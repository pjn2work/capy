import unittest
from datetime import datetime
from src.pyca import app
from src.lib_ca import get_subject_dict_from_cert_str, get_subject_dict_from_csr_str, \
    decode_cert, generate_ssh_keypair, convert_keypair_to_pem_format, convert_subject_to_dict


class Testing(unittest.TestCase):

    def setUp(self) -> None:
        self.ctx = app.app_context()
        self.ctx.push()
        self.client = app.test_client()

    def tearDown(self) -> None:
        self.ctx.pop()

    def get_json(self, url: str, params: dict = {}, headers={"accept": "application/json"}):
        return self.client.get(url, data=params, headers=headers)

    def post_json(self, url: str, data: dict = {}, headers={"accept": "application/json"}):
        return self.client.post(url, data=data, headers=headers)

    def _gen_csr(self):
        subject = {
            "C": "FR",
            "ST": "Paris",
            "L": "Notre Dame",
            "O": "CSR",
            "OU": "csr.qa",
            "CN": "csr.acme.com"
        }
        response = self.get_json(url="/ca/gen-csr", params=subject)

        assert response.status_code == 200, response
        return subject, response.get_json()

    def test_gen_csr(self):
        subject, resp_dict = self._gen_csr()

        # assert reply
        assert "csr" == resp_dict.get("type"), resp_dict
        assert "-----BEGIN CERTIFICATE REQUEST-----" in resp_dict.get("data"), resp_dict
        assert "-----BEGIN RSA PRIVATE KEY-----" in resp_dict.get("private_key"), resp_dict
        assert "-----BEGIN PUBLIC KEY-----" in resp_dict.get("public_key"), resp_dict

        # assert subject
        assert_dict(subject, get_subject_dict_from_csr_str(resp_dict["data"]))

    def _gen_cert_root(self):
        subject = {
            "C": "UK",
            "ST": "London",
            "L": "Pinner",
            "O": "RootCert",
            "OU": "root.qa",
            "CN": "root.acme.com"
        }
        response = self.get_json(url="/ca/gen-cert-root",
                                 params={**subject,
                                         "days": 10,
                                         "path_length": 3
                                         })

        assert response.status_code == 200, response
        return subject, response.get_json()

    def test_gen_cert_root(self):
        subject, resp_dict = self._gen_cert_root()

        # assert reply
        assert "root" == resp_dict.get("type"), resp_dict
        assert "-----BEGIN CERTIFICATE-----" in resp_dict.get("data"), resp_dict
        assert "-----BEGIN RSA PRIVATE KEY-----" in resp_dict.get("private_key"), resp_dict
        assert "-----BEGIN PUBLIC KEY-----" in resp_dict.get("public_key"), resp_dict

        cert = decode_cert(resp_dict["data"])

        # assert subject
        assert_dict(subject, get_subject_dict_from_cert_str(resp_dict["data"]))

        # assert dates
        start_delta, end_delta = datetime.utcnow() - cert.not_valid_before, datetime.utcnow() - cert.not_valid_after
        assert start_delta.total_seconds() < 2, f"not_valid_before is incorrect:\n{cert.not_valid_before}\n{start_delta}"
        assert end_delta.days == -10, f"not_valid_after is incorrect:\n{cert.not_valid_after}\n{end_delta}"

        # assert constraints
        constraints = cert.extensions[0].value
        assert constraints.path_length == 3
        assert constraints.ca is True

    def _gen_cert_intermediate(self):
        subject = {
            "C": "ES",
            "ST": "Barcelona",
            "L": "Sant Andreu",
            "O": "IntermCert",
            "OU": "interm.qa",
            "CN": "interm.acme.com"
        }
        private_key, _ = convert_keypair_to_pem_format(generate_ssh_keypair())
        _, root_cert = self._gen_cert_root()

        response = self.post_json(url="/ca/gen-cert-interm",
                                  data={**subject,
                                        "days": 8,
                                        "path_length": 2,
                                        "issuer_private_key": private_key,
                                        "issuer_cert": root_cert["data"]})

        assert response.status_code == 200, response
        return subject, response.get_json()

    def test_gen_cert_intermediate(self):
        subject, resp_dict = self._gen_cert_intermediate()

        # assert reply
        assert "interm" == resp_dict.get("type"), resp_dict
        assert "-----BEGIN CERTIFICATE-----" in resp_dict.get("data"), resp_dict
        assert "-----BEGIN RSA PRIVATE KEY-----" in resp_dict.get("private_key"), resp_dict
        assert "-----BEGIN PUBLIC KEY-----" in resp_dict.get("public_key"), resp_dict

        # create certificate object based on pem string
        cert = decode_cert(resp_dict["data"])

        # assert subject
        assert_dict(subject, get_subject_dict_from_cert_str(resp_dict["data"]))

        # assert dates
        start_delta, end_delta = datetime.utcnow() - cert.not_valid_before, datetime.utcnow() - cert.not_valid_after
        assert start_delta.total_seconds() < 2, f"not_valid_before is incorrect:\n{cert.not_valid_before}\n{start_delta}"
        assert end_delta.days == -8, f"not_valid_after is incorrect:\n{cert.not_valid_after}\n{end_delta}"

        # assert constraints
        constraints = cert.extensions[0].value
        assert constraints.path_length == 2
        assert constraints.ca is True

    def _gen_cert_end_entity(self):
        subject, csr = self._gen_csr()
        issuer_subject, interm_cert = self._gen_cert_intermediate()
        private_key, _ = convert_keypair_to_pem_format(generate_ssh_keypair())

        response = self.post_json(url="/ca/gen-cert-end",
                                  data={"days": 30,
                                        "issuer_private_key": private_key,
                                        "issuer_cert": interm_cert["data"],
                                        "csr_data": csr["data"]})

        assert response.status_code == 200, response
        return subject, issuer_subject, response.get_json()

    def test_gen_cert_end_entity(self):
        subject, issuer_subject, resp_dict = self._gen_cert_end_entity()

        # assert reply
        assert "endentity" == resp_dict.get("type"), resp_dict
        assert "-----BEGIN CERTIFICATE-----" in resp_dict.get("data"), resp_dict

        # create certificate object based on pem string
        cert = decode_cert(resp_dict["data"])

        # assert subject
        assert_dict(subject, get_subject_dict_from_cert_str(resp_dict["data"]))

        # assert issuer subject
        assert_dict(issuer_subject, convert_subject_to_dict(cert.issuer))

        # assert dates
        start_delta, end_delta = datetime.utcnow() - cert.not_valid_before, datetime.utcnow() - cert.not_valid_after
        assert start_delta.total_seconds() < 2, f"not_valid_before is incorrect:\n{cert.not_valid_before}\n{start_delta}"
        assert end_delta.days == -30, f"not_valid_after is incorrect:\n{cert.not_valid_after}\n{end_delta}"

        # assert constraints
        constraints = cert.extensions[0].value
        assert constraints.path_length is None, constraints
        assert constraints.ca is False, constraints


def assert_dict(expected: dict, received: dict):
    for k, v in expected.items():
        assert received.get(k) == v, f"Expected {k} = {v}. Received {received.get(k)}\n{received}"


if __name__ == "__main__":
    unittest.main()
