"""Unit tests for sign-in and authorization: tokens (tools/common/tokens.py), the tool Lambdas' caller checks
(tools/common/caller.py) and SAML assertion validation (web/auth.py; skipped unless signxml and lxml are installed).
No AWS calls: secrets, QuickSight and DynamoDB are replaced by stubs."""

import base64
import datetime as dt
import os
import sys
import time
import unittest
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for sub in ("tools/common", "web"):
    sys.path.insert(0, os.path.join(ROOT, sub))
for key, value in (("ACCOUNT_ID", "1"), ("QS_REGION", "cn-north-1"), ("AWS_REGION", "cn-north-1"),
                   ("SESSION_SECRET_ID", "x"), ("SAML_SP_ENTITY_ID", "urn:example:chat"),
                   ("IDP_METADATA_PARAMETER", "/example/idp-metadata")):
    os.environ.setdefault(key, value)

import jwt  # noqa: E402

import caller  # noqa: E402
import tokens  # noqa: E402

SECRET = "s" * 64
KEY = tokens.signing_key(SECRET)


class TokensTest(unittest.TestCase):
    def test_session_round_trip(self):
        token, claims = tokens.mint(KEY, tokens.SESSION_AUDIENCE, "a@example.com", 3600, name="Alex")
        got = tokens.verify(KEY, token, tokens.SESSION_AUDIENCE)
        self.assertEqual((got["sub"], got["name"], got["jti"]), ("a@example.com", "Alex", claims["jti"]))
        self.assertEqual(got["exp"] - got["iat"], 3600)

    def test_audiences_are_not_interchangeable(self):
        session = tokens.mint(KEY, tokens.SESSION_AUDIENCE, "a@example.com", 60)[0]
        tool = tokens.mint(KEY, tokens.TOOLS_AUDIENCE, "a@example.com", 60, analysis="a1")[0]
        with self.assertRaises(tokens.InvalidToken):
            tokens.verify(KEY, session, tokens.TOOLS_AUDIENCE)
        with self.assertRaises(tokens.InvalidToken):
            tokens.verify(KEY, tool, tokens.SESSION_AUDIENCE)

    def test_expired(self):
        token = tokens.mint(KEY, tokens.SESSION_AUDIENCE, "a@example.com", -tokens.LEEWAY_SECONDS - 5)[0]
        with self.assertRaises(tokens.InvalidToken) as raised:
            tokens.verify(KEY, token, tokens.SESSION_AUDIENCE)
        self.assertTrue(raised.exception.expired)

    def test_forged_tampered_and_unsigned(self):
        token = tokens.mint(KEY, tokens.SESSION_AUDIENCE, "a@example.com", 60)[0]
        other = tokens.signing_key("o" * 64)
        header, body, signature = token.split(".")
        claims = jwt.decode(token, KEY, algorithms=["HS256"], audience=tokens.SESSION_AUDIENCE)
        claims["sub"] = "admin@example.com"
        swapped = jwt.encode(claims, other, algorithm="HS256").split(".")[1]
        unsigned = jwt.encode(claims, None, algorithm="none")
        for bad in (tokens.mint(other, tokens.SESSION_AUDIENCE, "a@example.com", 60)[0],  # another key
                    f"{header}.{swapped}.{signature}",  # body changed, signature kept
                    unsigned, f"{header}.{body}.", "x.y", "", "a" * 5000):
            with self.assertRaises(tokens.InvalidToken, msg=bad[:40]):
                tokens.verify(KEY, bad, tokens.SESSION_AUDIENCE)

    def test_required_claims_and_issuer(self):
        now = int(time.time())
        base = {"iss": tokens.ISSUER, "aud": tokens.SESSION_AUDIENCE, "sub": "a@example.com", "iat": now,
                "exp": now + 60, "jti": "j"}
        for missing in tokens.REQUIRED_CLAIMS:
            token = jwt.encode({k: v for k, v in base.items() if k != missing}, KEY, algorithm="HS256")
            with self.assertRaises(tokens.InvalidToken, msg=missing):
                tokens.verify(KEY, token, tokens.SESSION_AUDIENCE)
        for claim, value in (("iss", "someone-else"), ("sub", "")):
            token = jwt.encode({**base, claim: value}, KEY, algorithm="HS256")
            with self.assertRaises(tokens.InvalidToken, msg=claim):
                tokens.verify(KEY, token, tokens.SESSION_AUDIENCE)
        tool = jwt.encode({**base, "aud": tokens.TOOLS_AUDIENCE}, KEY, algorithm="HS256")
        with self.assertRaises(tokens.InvalidToken):  # a tool token must name its analysis
            tokens.verify(KEY, tool, tokens.TOOLS_AUDIENCE, required=("analysis",))

    def test_short_secret_refused(self):
        with self.assertRaises(RuntimeError):
            tokens.signing_key("too-short")


class CallerTest(unittest.TestCase):
    def setUp(self):
        caller._cache.clear()
        caller._cache["session-key"] = (time.time(), KEY)

    def tool(self, analysis, sub="a@example.com", seconds=60):
        return tokens.mint(KEY, tokens.TOOLS_AUDIENCE, sub, seconds, analysis=analysis)[0]

    def test_tool_token_is_bound_to_its_analysis(self):
        self.assertEqual(caller.verify_token(self.tool("a1"), "a1"), "a@example.com")
        self.assertEqual(caller.verify_token(self.tool(""), ""), "a@example.com")  # the analysis picker
        for token, analysis, message in ((self.tool("a1"), "a2", "不是为这个分析签发的"),
                                         (self.tool(""), "a1", "不是为这个分析签发的"),
                                         (self.tool("a1", seconds=-100), "a1", "登录已过期"),
                                         (tokens.mint(KEY, tokens.SESSION_AUDIENCE, "a@example.com", 60)[0], "a1", "用户身份校验失败"),
                                         ("", "a1", "缺少已登录用户的身份")):
            with self.assertRaisesRegex(caller.ToolError, message):
                caller.verify_token(token, analysis)

    def test_duplicate_email_is_refused_not_merged(self):
        users = [{"Arn": "arn:u1", "UserName": "role/A/a", "Email": "A@example.com", "Active": True},
                 {"Arn": "arn:u2", "UserName": "role/B/a", "Email": "a@example.com", "Active": True},
                 {"Arn": "arn:u3", "UserName": "old", "Email": "a@example.com", "Active": False}]
        groups = {"role/A/a": [{"Arn": "arn:g1"}], "role/B/a": [{"Arn": "arn:g2"}]}
        paged = caller._paged
        try:
            caller._paged = lambda call, key, **kw: groups[kw["UserName"]] if key == "GroupList" else users
            with self.assertRaisesRegex(caller.ToolError, "2 个活跃用户"):
                caller.principals("a@example.com")
            users.pop(1)
            caller._cache.pop("principals:a@example.com", None)
            self.assertEqual(caller.principals("a@example.com"), {"arn:u1", "arn:g1"})
        finally:
            caller._paged = paged

    def test_viewer_skips_a_deleted_dashboard(self):
        not_found = caller.qs.exceptions.ResourceNotFoundException(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "gone"}}, "DescribeDashboardPermissions")

        def permissions(AwsAccountId, DashboardId):  # noqa: N803 - boto3 argument names
            if DashboardId == "d-deleted":
                raise not_found
            return {"Permissions": [{"Principal": "arn:u1", "Actions": ["quicksight:DescribeDashboard"]}]}
        originals = caller.principals, caller.analysis_permissions, caller.dashboards_of
        try:
            caller.principals = lambda email: {"arn:u1"}
            caller.analysis_permissions = lambda aid: []
            caller.dashboards_of = lambda aid: ["d-deleted", "d-live"]
            caller.qs.describe_dashboard_permissions = permissions
            self.assertEqual(caller.require_viewer({"_caller": self.tool("a1"), "_analysis": "a1"}), ("a@example.com", "a1"))
        finally:
            caller.principals, caller.analysis_permissions, caller.dashboards_of = originals
            del caller.qs.describe_dashboard_permissions


try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from lxml import etree
    from signxml import XMLSigner
    import auth
except ImportError as missing:  # signxml / lxml are only in the web Lambda package
    auth = None
    SKIP = f"needs the web Lambda's packages: {missing}"


def _keypair(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            cert.public_bytes(serialization.Encoding.PEM))


class FakeTable:
    """Enough of a DynamoDB Table for login_redirect / complete_login and session revocation."""

    class _Exceptions:
        class ConditionalCheckFailedException(Exception):
            pass

    def __init__(self):
        self.items = {}
        self.meta = type("Meta", (), {"client": type("Client", (), {"exceptions": self._Exceptions})()})()

    def put_item(self, Item, ConditionExpression=None):  # noqa: N803
        if ConditionExpression and Item["jobId"] in self.items:
            raise self._Exceptions.ConditionalCheckFailedException()
        self.items[Item["jobId"]] = Item

    def get_item(self, Key, ConsistentRead=False):  # noqa: N803
        item = self.items.get(Key["jobId"])
        return {"Item": item} if item else {}

    def delete_item(self, Key, ReturnValues=None, ConditionExpression=None):  # noqa: N803
        if Key["jobId"] not in self.items:
            raise self._Exceptions.ConditionalCheckFailedException()
        return {"Attributes": self.items.pop(Key["jobId"])}


@unittest.skipIf(auth is None, "" if auth else SKIP)
class SamlTest(unittest.TestCase):
    IDP = "https://idp.example.com/saml"
    ACS = "https://chat.example.com/saml/acs"

    @classmethod
    def setUpClass(cls):
        cls.old, cls.new, cls.stranger = _keypair("old"), _keypair("new"), _keypair("stranger")
        auth._session_key = KEY
        auth.directory_name = lambda email: ""
        auth._idp.update(at=time.time() + 10**6, value=(cls.IDP, "https://idp.example.com/sso",
                                                        [cls.old[1].decode(), cls.new[1].decode()]))

    def response(self, request_id, signer, assertion_id="_a"):
        now = dt.datetime.now(dt.timezone.utc)
        fmt = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        ns = auth.NS
        id_attribute = f' ID="{assertion_id}"' if assertion_id else ""
        assertion = etree.fromstring(
            f'<saml:Assertion xmlns:saml="{ns["saml"]}"{id_attribute} Version="2.0" IssueInstant="{fmt(now)}">'
            f"<saml:Issuer>{self.IDP}</saml:Issuer><saml:Subject><saml:NameID>Alex@Example.com</saml:NameID>"
            f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData '
            f'InResponseTo="{request_id}" Recipient="{self.ACS}" NotOnOrAfter="{fmt(now + dt.timedelta(minutes=5))}"/>'
            f"</saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{fmt(now)}\" "
            f'NotOnOrAfter="{fmt(now + dt.timedelta(minutes=5))}"><saml:AudienceRestriction>'
            f"<saml:Audience>{auth.SP_ENTITY_ID}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
            f"</saml:Assertion>")
        signed = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(
            assertion, key=signer[0], cert=signer[1])
        root = etree.fromstring(f'<samlp:Response xmlns:samlp="{ns["samlp"]}" ID="_r" Version="2.0">'
                                f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
                                f"</samlp:Status></samlp:Response>")
        root.append(signed)
        return base64.b64encode(etree.tostring(root)).decode()

    def start(self, table):
        auth.login_redirect(table, "n" * 32, self.ACS)
        return next(k for k in table.items if k.startswith("saml#")).split("#", 1)[1]

    def test_accepts_either_metadata_certificate_and_rejects_replay(self):
        for signer in (self.old, self.new):  # during a rotation the metadata lists both
            table = FakeTable()
            request_id = self.start(table)
            assertion_id = "_" + uuid.uuid4().hex
            token, payload, nonce, _attrs = auth.complete_login(table, self.response(request_id, signer, assertion_id),
                                                                request_id, self.ACS)
            self.assertEqual((payload["sub"], nonce), ("alex@example.com", "n" * 32))
            self.assertEqual(auth.verify_session(token, table)["sub"], "alex@example.com")
            with self.assertRaisesRegex(auth.AuthError, "expired or already used"):  # same RelayState again
                auth.complete_login(table, self.response(request_id, signer, assertion_id), request_id, self.ACS)
            table.items[f"saml#{request_id}"] = {"nonce": "n" * 32, "createdAt": int(time.time())}
            with self.assertRaisesRegex(auth.AuthError, "replayed"):  # same assertion, new pending request
                auth.complete_login(table, self.response(request_id, signer, assertion_id), request_id, self.ACS)

    def test_rejects_unknown_certificate_and_missing_id(self):
        table = FakeTable()
        request_id = self.start(table)
        with self.assertRaisesRegex(auth.AuthError, "signature invalid"):
            auth.complete_login(table, self.response(request_id, self.stranger), request_id, self.ACS)
        table = FakeTable()
        request_id = self.start(table)
        with self.assertRaisesRegex(auth.AuthError, "no valid ID"):
            auth.complete_login(table, self.response(request_id, self.old, assertion_id=""), request_id, self.ACS)

    def test_sign_out_revokes_the_session(self):
        table = FakeTable()
        token, claims = auth.mint_session("alex@example.com", "Alex")
        self.assertIsNotNone(auth.verify_session(token, table))
        auth.revoke_session(table, claims)
        self.assertIsNone(auth.verify_session(token, table))
        tool = auth.mint_tool_token("alex@example.com", "a1", 60)
        self.assertIsNone(auth.verify_session(tool, table))  # a tool token is not a sign-in


if __name__ == "__main__":
    unittest.main()
