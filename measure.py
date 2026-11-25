"""Reproduce local byte measurements and software signature benchmarks."""
import argparse
import csv
import ctypes
import json
import os
import platform
import subprocess
import tempfile
import time
from pathlib import Path

SIGNATURES = {
    "ECDSA P-256": ("EC", ["-pkeyopt", "ec_paramgen_curve:P-256"], "1.2.840.10045.4.3.2", 65, "ecdsap256"),
    "ML-DSA-65": ("ML-DSA-65", [], "2.16.840.1.101.3.4.3.18", 1952, "ML-DSA-65"),
    "SLH-DSA-SHA2-128s": ("SLH-DSA-SHA2-128s", [], "2.16.840.1.101.3.4.3.20", 32, "SLH-DSA-SHA2-128s"),
}
GROUPS = ("X25519", "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")

def write_csv(path, rows):
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

def openssl_run(exe, *args, **kwargs):
    return subprocess.run([exe, *args], check=True, capture_output=True, timeout=45, **kwargs).stdout

def der_parts(data):
    """Yield tag and contents of each adjacent DER element."""
    off = 0
    while off < len(data):
        tag, size = data[off:off+2]
        off += 2
        if size & 128:
            count = size & 127
            size = int.from_bytes(data[off:off+count], "big")
            off += count
        end = off + size
        assert end <= len(data)
        yield tag, data[off:end]
        off = end

def inspect_der(data):
    (_, outer), = der_parts(data)
    (_, tbs), (_, algorithm), (tag, sig) = der_parts(outer)
    assert tag == 3 and sig[0] == 0
    (_, oid), *_ = der_parts(algorithm)
    components = list(der_parts(tbs))
    start = int(components[0][0] == 160)
    (_, spki) = components[start + 5]
    (_, _), (tag, pub) = der_parts(spki)
    assert tag == 3 and pub[0] == 0
    return len(pub)-1, len(sig)-1, oid.hex()

def get_memory():
    if os.name == "nt":
        memory = ctypes.c_ulonglong()
        if ctypes.windll.kernel32.GetPhysicallyInstalledSystemMemory(ctypes.byref(memory)):
            return round(memory.value / 1048576, 2)
        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong),
                        ("values", ctypes.c_ulonglong * 7)]
        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return round(status.values[0] / 2**30, 2)
    try:
        return round(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 2**30, 2)
    except (AttributeError, ValueError):
        return None

def make_chain(exe, directory, params):
    alg, flags, _, pk_expected, _ = params
    directory.mkdir()
    config = directory / "profile.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\n"
                      "[root]\nbasicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\n"
                      "[intermediate]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
                      "[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                      "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n", encoding="ascii")
    pwd = str(directory)
    names = ("root", "intermediate", "leaf")
    subjects = ("Root CA", "Issuing CA", "localhost")
    for index, role in enumerate(names):
        key, cert = role + ".key", role + ".pem"
        openssl_run(exe, "genpkey", "-algorithm", alg, *flags, "-out", key, cwd=pwd)
        if index == 0:
            openssl_run(exe, "req", "-new", "-x509", "-key", key, "-out", cert,
                        "-subj", "/CN="+subjects[index], "-days", "30", "-set_serial", "1",
                        "-config", config.name, "-extensions", role, cwd=pwd)
        else:
            openssl_run(exe, "req", "-new", "-key", key, "-out", role+".csr",
                        "-subj", "/CN="+subjects[index], "-config", config.name, cwd=pwd)
            parent = names[index-1]
            openssl_run(exe, "x509", "-req", "-in", role+".csr", "-out", cert,
                        "-CA", parent+".pem", "-CAkey", parent+".key", "-set_serial", str(index+1),
                        "-days", "30", "-extfile", config.name, "-extensions", role, cwd=pwd)
    openssl_run(exe, "verify", "-CAfile", "root.pem", "-untrusted", "intermediate.pem",
                "-verify_hostname", "localhost", "leaf.pem", cwd=pwd)
    rows = {}
    for role in ("leaf", "intermediate"):
        der = openssl_run(exe, "x509", "-in", role+".pem", "-outform", "DER", cwd=pwd)
        key_bytes, sig_bytes, oid = inspect_der(der)
        expected_oid = {
            "EC": "2a8648ce3d040302", "ML-DSA-65": "608648016503040312",
            "SLH-DSA-SHA2-128s": "608648016503040314",
        }[alg]
        assert key_bytes == pk_expected and oid == expected_oid, (alg, key_bytes, oid)
        rows[role] = (len(der), key_bytes, sig_bytes)
    return rows

def memory_tls(exe, group, directory, count, explicit_crypto=None, explicit_ssl=None):
    """Exchange real TLS records through paired memory BIOs, without sockets."""
    from ctypes import c_void_p as ptr, c_int as integer, c_char_p as string, c_long as long, c_size_t as size
    from ctypes.util import find_library
    from shutil import which

    binary = Path(which(exe) or exe).resolve()
    crypto_path = explicit_crypto or (str(binary.parent/"libcrypto-3-x64.dll") if os.name == "nt" else find_library("crypto"))
    ssl_path = explicit_ssl or (str(binary.parent/"libssl-3-x64.dll") if os.name == "nt" else find_library("ssl"))
    crypto = ctypes.CDLL(crypto_path)
    tls = ctypes.CDLL(ssl_path)

    def bind(lib, name, result_type, *arg_types):
        fn = getattr(lib, name)
        fn.restype = result_type
        fn.argtypes = list(arg_types)
        return fn

    method = bind(tls, "TLS_method", ptr)
    ctx_new = bind(tls, "SSL_CTX_new", ptr, ptr)
    ctx_free = bind(tls, "SSL_CTX_free", None, ptr)
    ctrl = bind(tls, "SSL_CTX_ctrl", long, ptr, integer, long, ptr)
    load_chain = bind(tls, "SSL_CTX_use_certificate_chain_file", integer, ptr, string)
    load_key = bind(tls, "SSL_CTX_use_PrivateKey_file", integer, ptr, string, integer)
    load_root = bind(tls, "SSL_CTX_load_verify_locations", integer, ptr, string, string)
    verify_mode = bind(tls, "SSL_CTX_set_verify", None, ptr, integer, ptr)
    no_tickets = bind(tls, "SSL_CTX_set_num_tickets", integer, ptr, size)
    new = bind(tls, "SSL_new", ptr, ptr)
    free = bind(tls, "SSL_free", None, ptr)
    set_bio = bind(tls, "SSL_set_bio", None, ptr, ptr, ptr)
    client_mode = bind(tls, "SSL_set_connect_state", None, ptr)
    server_mode = bind(tls, "SSL_set_accept_state", None, ptr)
    check_host = bind(tls, "SSL_set1_host", integer, ptr, string)
    verify = bind(tls, "SSL_get_verify_result", long, ptr)
    handshake = bind(tls, "SSL_do_handshake", integer, ptr)
    error = bind(tls, "SSL_get_error", integer, ptr, integer)
    bio_new = bind(crypto, "BIO_new", ptr, ptr)
    bio_mem = bind(crypto, "BIO_s_mem", ptr)
    bio_pending = bind(crypto, "BIO_ctrl_pending", size, ptr)
    bio_read = bind(crypto, "BIO_read", integer, ptr, ptr, integer)
    bio_write = bind(crypto, "BIO_write", integer, ptr, ptr, integer)
    version = bind(crypto, "OpenSSL_version", string, integer)(0).decode()
    assert openssl_run(exe, "version").decode().startswith(version), version
    callback_type = ctypes.CFUNCTYPE(None, integer, integer, integer, ptr, size, ptr, ptr)
    set_callback = bind(tls, "SSL_set_msg_callback", None, ptr, callback_type)

    names = {(1,1): "ClientHello", (0,2): "ServerHello", (0,8):"EncryptedExtensions",
             (0,11): "Certificate", (0,15): "CertificateVerify", (0,20): "FinishedServer",
             (1,20): "FinishedClient"}
    chain = directory/"wire-chain.pem"
    chain.write_bytes((directory/"leaf.pem").read_bytes() + (directory/"intermediate.pem").read_bytes())
    client_ctx, server_ctx = ctx_new(method()), ctx_new(method())
    assert client_ctx and server_ctx
    try:
        for ctx in (client_ctx, server_ctx):
            for selector in (123, 124):  # SSL_CTRL_SET_MIN/MAX_PROTO_VERSION
                assert ctrl(ctx, selector, 0x0304, None) == 1
            group_name = ctypes.create_string_buffer(group.encode("ascii"))
            assert ctrl(ctx, 92, 0, group_name) == 1, group  # SSL_CTRL_SET_GROUPS_LIST
        assert no_tickets(server_ctx, 0) == 1
        assert load_chain(server_ctx, os.fsencode(chain)) == 1
        assert load_key(server_ctx, os.fsencode(directory/"leaf.key"), 1) == 1
        assert load_root(client_ctx, os.fsencode(directory/"root.pem"), None) == 1
        verify_mode(client_ctx, 1, None)  # SSL_VERIFY_PEER
        result = []
        for sample in range(1, count+1):
            client, server = new(client_ctx), new(server_ctx)
            assert client and server
            observed = {}

            @callback_type
            def record(writing, _version, content_type, buffer, n, _ssl, _arg):
                if content_type == 22 and n > 0:
                    tag = names.get((writing, ctypes.string_at(buffer, 1)[0]))
                    if tag:
                        observed.setdefault(tag, []).append(n)

            try:
                client_mode(client)
                server_mode(server)
                assert check_host(client, b"localhost") == 1
                set_callback(client, record)
                ci, co, si, so = (bio_new(bio_mem()) for _ in range(4))
                assert ci and co and si and so
                set_bio(client, ci, co)
                set_bio(server, si, so)
                done = {}
                for _ in range(20):
                    for dev, outgoing, incoming in ((client, co, si), (server, so, ci)):
                        if not done.get(dev):
                            code = handshake(dev)
                            assert code == 1 or error(dev, code) in (2,3), (group, code, error(dev,code))
                            done[dev] = code == 1
                        n = bio_pending(outgoing)
                        if n:
                            block = ctypes.create_string_buffer(n)
                            assert bio_read(outgoing, block, n) == n
                            assert bio_write(incoming, block, n) == n
                    if all(done.values()):
                        break
                assert all(done.values()) and verify(client) == 0
                assert set(observed) == set(names.values()) and all(len(v) == 1 for v in observed.values())
                result.append(dict(group=group, sample=sample,
                                   **{name: observed[name][0] for name in names.values()}))
            finally:
                free(client)
                free(server)
        return result
    finally:
        ctx_free(client_ctx)
        ctx_free(server_ctx)

def measure_signature(exe, directory, algorithms, repeats):
    result = []
    for sample in range(1, repeats+1):
        for label, params in algorithms.items():
            name = params[-1]
            args = [exe, "speed", "-elapsed", "-seconds", "1", "-mr"]
            if name != "ecdsap256":
                args.append("-signature-algorithms")
            process = subprocess.run([*args, name], check=True, capture_output=True,
                                     text=True, cwd=directory, timeout=30)
            trace = process.stdout + process.stderr
            prefix = "+F4:" if name == "ecdsap256" else "+F10:"
            line = next((line for line in trace.splitlines() if line.startswith(prefix)), "")
            fields = line.split(":")
            if not line:
                raise RuntimeError(trace)
            sign, verify = (1000/float(x) for x in fields[-2:])
            result.append(dict(algorithm=label, sample=sample, sign_ms=sign, verify_ms=verify))
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--crypto-lib")
    parser.add_argument("--ssl-lib")
    parser.add_argument("--cpu-label", default=platform.processor())
    parser.add_argument("--handshakes", type=int, default=20)
    parser.add_argument("--chains", type=int, default=12)
    parser.add_argument("--timing-repeats", type=int, default=5)
    parser.add_argument("--only", choices=["bytes","timing","all"], default="all")
    args = parser.parse_args()
    assert min(args.handshakes,args.chains,args.timing_repeats) >= 2
    args.out.mkdir(parents=True, exist_ok=True)
    metadata = dict(openssl=openssl_run(args.openssl,"version").decode().strip(),
                    cpu=args.cpu_label, physical_memory_GiB=get_memory(),
                    logical_cpus=os.cpu_count(), os=platform.platform(),
                    python=platform.python_version())
    (args.out/"environment.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(metadata, flush=True)
    with tempfile.TemporaryDirectory(prefix="pqc-r1-") as temp:
        root = Path(temp)
        if args.only != "timing":
            chains, handshakes = [], []
            for sample in range(1, args.chains+1):
                for label, params in SIGNATURES.items():
                    path = root / f"chain-{sample}-{params[0]}"
                    roles = make_chain(args.openssl, path, params)
                    for role, (der, key, sig) in roles.items():
                        chains.append(dict(algorithm=label, sample=sample, role=role, DER=der,
                                           public_key=key, signature=sig, residual=der-key-sig,
                                           signature_oid=params[2]))
            write_csv(args.out/"certificate_runs.csv", chains)
            print("Certificate runs written", flush=True)
            for group in GROUPS:
                handshakes.extend(memory_tls(args.openssl, group, root/"chain-1-EC", args.handshakes, args.crypto_lib, args.ssl_lib))
                write_csv(args.out/"tls_runs.csv", handshakes)
                print(group, "complete", flush=True)
            auth = memory_tls(args.openssl, 'X25519MLKEM768', root/'chain-1-ML-DSA-65',
                              args.handshakes, args.crypto_lib, args.ssl_lib)
            write_csv(args.out/'tls_auth_runs.csv', auth)
        if args.only != "bytes":
            timings = measure_signature(args.openssl, root, SIGNATURES, args.timing_repeats)
            write_csv(args.out/"signature_runs.csv", timings)
            print("Signature runs written", flush=True)

if __name__ == "__main__":
    main()
