import sys
import logging
import os
import ssl
import hashlib
import random
from Config import config
from util import helper


class CryptConnectionManager:
    def __init__(self):
        if config.openssl_bin_file:
            self.openssl_bin = config.openssl_bin_file
        elif sys.platform.startswith("win"):
            self.openssl_bin = "tools\\openssl\\openssl.exe"
        elif config.dist_type.startswith("bundle_linux"):
            self.openssl_bin = "../runtime/bin/openssl"
        else:
            self.openssl_bin = "openssl"
        self.context_client = None
        self.context_server = None
        self.openssl_conf_template = "src/lib/openssl/openssl.cnf"
        self.openssl_conf = config.data_dir + "/openssl.cnf"
        self.openssl_env = {
            "OPENSSL_CONF": self.openssl_conf,
            "RANDFILE": config.data_dir + "/openssl-rand.tmp",
        }
        self.crypt_supported = []
        self.cacert_pem = config.data_dir + "/cacert-ed25519.pem"
        self.cakey_pem = config.data_dir + "/cakey-ed25519.pem"
        self.cert_pem = config.data_dir + "/cert-ed25519.pem"
        self.cert_csr = config.data_dir + "/cert-ed25519.csr"
        self.key_pem = config.data_dir + "/key-ed25519.pem"
        self.log = logging.getLogger("CryptConnectionManager")
        self.log.debug("Version: %s" % ssl.OPENSSL_VERSION)
        self.fakedomains = [
            "prisoner.iana.org",
            "blackhole-1.iana.org",
            "blackhole-2.iana.org",
            "bitcoin.org",
            "namecoin.org",
            "icann.org",
            "hostname.as112.net",
            "chinaunicom.com",
            "chinatelecom-h.com",
            "moscow.rt.ru",
            "admin.ch",
        ]

    def createSslContexts(self):
        if self.context_server and self.context_client:
            return False
        ciphers = "CHACHA20"
        ciphers += "!all"
        if hasattr(ssl, "PROTOCOL_TLS"):
            protocol = ssl.PROTOCOL_TLS
        self.context_client = ssl.SSLContext(protocol)
        self.context_client.check_hostname = False
        self.context_client.verify_mode = ssl.CERT_NONE
        self.context_server = ssl.SSLContext(protocol)
        self.context_server.load_cert_chain(self.cert_pem, self.key_pem)
        for ctx in (self.context_client, self.context_server):
            ctx.set_ciphers(ciphers)
            ctx.options |= ssl.OP_NO_COMPRESSION
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                pass

    def selectCrypt(self, client_supported):
        for crypt in self.crypt_supported:
            if crypt in client_supported:
                return crypt
        return False

    def wrapSocket(self, sock, crypt, server=False, cert_pin=None):
        if crypt == "tls-ed25519":
            if server:
                sock_wrapped = self.context_server.wrap_socket(
                    sock, server_side=True
                )
            else:
                sock_wrapped = self.context_client.wrap_socket(
                    sock, server_hostname=random.choice(self.fakedomains)
                )
            if cert_pin:
                cert_hash = hashlib.sha256(
                    sock_wrapped.getpeercert(True)
                ).hexdigest()
                if cert_hash != cert_pin:
                    raise Exception(
                        "Socket certificate does not match (%s != %s)"
                        % (cert_hash, cert_pin)
                    )
            return sock_wrapped
        else:
            return sock

    def removeCerts(self):
        if config.keep_ssl_cert:
            return False
        for file_name in [
            "cert-ed25519.pem",
            "key-ed25519.pem",
            "cacert-ed25519.pem",
            "cakey-ed25519.pem",
            "cacert-ed25519.srl",
            "cert-ed25519.csr",
            "openssl-rand.tmp",
        ]:
            file_path = "%s/%s" % (config.data_dir, file_name)
            if os.path.isfile(file_path):
                os.unlink(file_path)

    def loadCerts(self):
        if config.disable_encryption:
            return False
        if (
            self.createEd25519Cert()
            and "tls-ed25519" not in self.crypt_supported
        ):
            self.crypt_supported.append("tls-ed25519")

    def createEd25519Cert(self):
        casubjects = [
            "/C=US/O=Amazon/OU=Server CA 1B/CN=Amazon",
            "/C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3",
            (
                "/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2"
                " High Assurance Server CA"
            ),
            (
                "/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA"
                " Limited/CN=COMODO RSA Domain Validation Secure Server CA"
            ),
        ]
        self.openssl_env["CN"] = random.choice(self.fakedomains)
        if os.path.isfile(self.cert_pem) and os.path.isfile(self.key_pem):
            self.createSslContexts()
            return True
        import subprocess

        conf_template = open(self.openssl_conf_template).read()
        conf_template = conf_template.replace(
            "$ENV::CN", self.openssl_env["CN"]
        )
        open(self.openssl_conf, "w").write(conf_template)
        cmd_params = helper.shellquote(
            self.openssl_bin,
            self.openssl_conf,
            random.choice(casubjects),
            self.cakey_pem,
            self.cacert_pem,
        )
        cmd = (
            "%s req -new -newkey ed25519 -days 365 -nodes -x509 -config %s"
            " -subj %s -keyout %s -out %s -batch" % cmd_params
        )
        self.log.debug(
            "Generating Ed25519 CA-certificate and CA-private key PEM files…"
        )
        self.log.debug("Running: %s" % cmd)
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            env=self.openssl_env,
        )
        back = (
            proc.stdout.read()
            .strip()
            .decode(errors="replace")
            .replace("\r", "")
        )
        proc.wait()
        if not (
            os.path.isfile(self.cacert_pem) and os.path.isfile(self.cakey_pem)
        ):
            self.log.error(
                "Ed25519 SSL CA-certificate generation failed, CA-certificate"
                " or CA-private key files not exist. (%s)" % back
            )
            return False
        else:
            self.log.debug("Result: %s" % back)
        cmd_params = helper.shellquote(
            self.openssl_bin,
            self.key_pem,
            self.cert_csr,
            "/CN=" + self.openssl_env["CN"],
            self.openssl_conf,
        )
        cmd = (
            "%s req -new -newkey ed25519 -keyout %s -out %s -subj %s -nodes"
            " -batch -config %s" % cmd_params
        )
        self.log.debug("Generating certificate key and signing request…")
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            env=self.openssl_env,
        )
        back = (
            proc.stdout.read()
            .strip()
            .decode(errors="replace")
            .replace("\r", "")
        )
        proc.wait()
        self.log.debug("Running: %s\n%s" % (cmd, back))
        cmd_params = helper.shellquote(
            self.openssl_bin,
            self.cert_csr,
            self.cacert_pem,
            self.cakey_pem,
            self.cert_pem,
            self.openssl_conf,
        )
        cmd = (
            "%s x509 -req -in %s -CA %s -CAkey %s -set_serial 01 -out %s -days"
            " 180 -extensions x509_ext -extfile %s" % cmd_params
        )
        self.log.debug("Generating Ed25519 certificate…")
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            env=self.openssl_env,
        )
        back = (
            proc.stdout.read()
            .strip()
            .decode(errors="replace")
            .replace("\r", "")
        )
        proc.wait()
        self.log.debug("Running: %s\n%s" % (cmd, back))
        if os.path.isfile(self.cert_pem) and os.path.isfile(self.key_pem):
            self.createSslContexts()
            os.unlink(self.openssl_conf)
            os.unlink(self.cacert_pem)
            os.unlink(self.cakey_pem)
            os.unlink(self.cert_csr)
            return True
        else:
            self.log.error(
                "Ed25519 SSL certificate generation failed, the certificate or"
                " private key file not exist."
            )


manager = CryptConnectionManager()
