#!/usr/bin/env python3


import os
import lib_ca as CA
from flask import Flask, Response, jsonify, request


app = Flask(__name__)
app.config["DEBUG"] = True


# Aux methods = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = -
def get_fpn(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def get_file(filename):
    try:
        return open(get_fpn(filename)).read()
    except IOError as exc:
        return str(exc)


def get_form_fields() -> dict:
    form_fields = request.args.to_dict(flat=True)
    if not form_fields:
        form_fields = request.form.to_dict(flat=True)
    return form_fields

# Aux methods = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = -


@app.route('/ca/', methods=['GET'])
def main_page():
    return Response(get_file("index.html"))


@app.route('/ca/str2pem', methods=['POST'])
def str2pem():
    data_pem = CA.convert_str_to_pem(get_form_fields()["data_str"])
    return Response(data_pem, mimetype='text')


@app.route('/ca/gen-csr', methods=['GET'])
def generate_csr():
    """
    GET https://127.0.0.1:25050/ca/gen-csr?C=PT&ST=Lisboa&L=Santo Antonio&O=ACME&OU=qa&CN=acme.com
    """

    # generate private key
    key = CA.generate_ssh_keypair()
    key_priv, key_pub = CA.convert_keypair_to_pem_format(key)
    key_priv = CA.convert_pem_to_str(key_priv)
    key_pub = CA.convert_pem_to_str(key_pub)

    # create root subject
    subject = CA.create_subject_from_dict(get_form_fields())

    # generate root certificate
    csr_pem = CA.generate_csr(subject, key)
    csr_pem = CA.convert_pem_to_str(CA.convert_csr_to_pem_format(csr_pem))

    return jsonify({"type": "csr", "data": csr_pem, "private_key": key_priv, "public_key": key_pub})


@app.route('/ca/gen-cert-root', methods=['GET'])
def generate_cert_root():
    """
    GET https://127.0.0.1:25050/ca/gen-cert-root?C=PT&ST=Lisboa&L=Santo Antonio&O=ACME&OU=qa&CN=acme.com
    """
    # get fields
    _form_fields = get_form_fields()
    days = int(_form_fields["days"])
    path_length = int(_form_fields["path_length"])

    # generate private key
    key = CA.generate_ssh_keypair()
    key_priv, key_pub = CA.convert_keypair_to_pem_format(key)
    key_priv = CA.convert_pem_to_str(key_priv)
    key_pub = CA.convert_pem_to_str(key_pub)

    # create root subject
    issuer_subject = subject = CA.create_subject_from_dict(_form_fields)

    # generate root certificate
    cert_pem = CA.generate_cert(issuer_subject, subject, public_key=key.public_key(), sign_key=key, days=days, is_ca=True, path_length=path_length)
    cert_pem = CA.convert_pem_to_str(CA.convert_cert_to_pem_format(cert_pem))

    return jsonify({
        "type": "root",
        "data": cert_pem,
        "private_key": key_priv,
        "public_key": key_pub})


@app.route('/ca/gen-cert-interm', methods=['POST'])
def generate_cert_interm():
    """
    POST https://127.0.0.1:25050/ca/gen-cert-interm?C=PT&ST=Lisboa&L=Santo Antonio&O=ACME&OU=qa&CN=acme.com
    {
        "issuer_private_key": "...pem...",
        "issuer_cert": "...pem..."
    }
    """
    # get fields
    _form_fields = get_form_fields()
    days = int(_form_fields["days"])
    path_length = int(_form_fields["path_length"])

    # generate private key
    key = CA.generate_ssh_keypair()
    key_priv, key_pub = CA.convert_keypair_to_pem_format(key)
    key_priv = CA.convert_pem_to_str(key_priv)
    key_pub = CA.convert_pem_to_str(key_pub)

    # create subject
    subject = CA.create_subject_from_dict(_form_fields)

    # get parent private_key & subject
    issuer_private_key = _form_fields["issuer_private_key"].replace("\\n", "")
    issuer_private_key = CA.decode_key(issuer_private_key)
    issuer_cert_str = _form_fields["issuer_cert"].replace("\\n", "")
    issuer_subject = CA.decode_cert(issuer_cert_str).subject

    # generate intermediate certificate
    cert_pem = CA.generate_cert(issuer_subject, subject, public_key=key.public_key(), sign_key=issuer_private_key, days=days, is_ca=True, path_length=path_length)
    cert_pem = CA.convert_pem_to_str(CA.convert_cert_to_pem_format(cert_pem))

    return jsonify({
        "type": "interm",
        "data": cert_pem,
        "private_key": key_priv,
        "public_key": key_pub})


@app.route('/ca/gen-cert-end', methods=['POST'])
def generate_cert_end_entity():
    """
    POST https://127.0.0.1:25050/ca/gen-cert-end
    {
        "issuer_private_key": "...pem...",
        "issuer_cert": "...pem..."
        "csr_data": "...pem..."
    }
    """
    # get fields
    _form_fields = get_form_fields()
    days = int(_form_fields["days"])
    csr_data_str = _form_fields["csr_data"].replace("\\n", "")

    # get parent private_key & subject
    issuer_private_key = _form_fields["issuer_private_key"].replace("\\n", "")
    issuer_private_key = CA.decode_key(issuer_private_key)
    issuer_cert_str = _form_fields["issuer_cert"].replace("\\n", "")
    issuer_subject = CA.decode_cert(issuer_cert_str).subject

    # generate intermediate certificate
    cert_pem = CA.generate_cert_from_csr(issuer_subject, csr_data_str, sign_key=issuer_private_key, days=days, return_in_pem_format=True)
    cert_pem = CA.convert_pem_to_str(cert_pem)

    return jsonify({
        "type": "endentity",
        "data": cert_pem})


if __name__ == '__main__':
    app.run(port=25050, host='0.0.0.0')
