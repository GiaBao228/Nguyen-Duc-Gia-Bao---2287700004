# demo.py
import os
from cryptography import x509

from ca_utils import (
    create_root_ca,
    create_intermediate_ca,
    issue_certificate,
    verify_certificate_chain,
    load_cert,
)

from revoke_utils import revoke_certificate, check_revocation_status

root_key = root_cert = inter_key = inter_cert = None

def setup_ca():
    global root_key, root_cert, inter_key, inter_cert
    print("==> Tạo Root CA ...")
    root_key, root_cert = create_root_ca()
    print("   ✔ Root CA:", root_key, root_cert)

    print("==> Tạo Intermediate CA ...")
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    print("   ✔ Intermediate CA:", inter_key, inter_cert)

    return root_key, root_cert, inter_key, inter_cert

def issue_cert_demo():
    subject_info = {
        "common_name": "giabao",
        "org": "giabao Company",
        "country": "VN",
    }
    print("==> Phát hành chứng chỉ cho end-user ...")
    user_key, user_cert = issue_certificate(inter_key, inter_cert, subject_info)
    cert_path = os.path.join("certs", f"{subject_info['common_name']}_cert.pem")
    key_path = os.path.join("certs", f"{subject_info['common_name']}_key.pem")
    print(f"   ✔ Đã phát hành: {cert_path}, {key_path}")
    return cert_path

def verify_chain_demo(user_cert_path):
    print("==> Kiểm tra chuỗi chứng chỉ ...")
    chain_paths = [
        os.path.join("certs", "intermediate_cert.pem"),
        os.path.join("certs", "root_ca_cert.pem"),
    ]
    chain = [load_cert(p) for p in chain_paths]
    user_cert = load_cert(user_cert_path)
    valid = verify_certificate_chain(user_cert, chain)
    print(f"   ✔ Chuỗi hợp lệ: {valid}")
    return valid

def revoke_demo(user_cert_path):
    print("==> Thu hồi chứng chỉ người dùng ...")
    revoke_certificate(
        user_cert_path,
        os.path.join("certs", "intermediate_cert.pem"),
        os.path.join("certs", "intermediate_key.pem"),
        reason=x509.ReasonFlags.key_compromise,
    )
    print("   ✔ Đã thu hồi")

def crl_check_demo(user_cert_path):
    print("==> Kiểm tra trạng thái (CRL) của chứng chỉ ...")
    status = check_revocation_status(user_cert_path)
    print(f"   ✔ Trạng thái: {status}")
    return status

def run_all():
    setup_ca()
    user_cert = issue_cert_demo()
    verify_chain_demo(user_cert)
    revoke_demo(user_cert)
    crl_check_demo(user_cert)

if __name__ == "__main__":
    run_all()