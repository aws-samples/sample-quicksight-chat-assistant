"""Unit tests for sign-in and authorization: tokens (tools/common/tokens.py), the tool Lambdas' caller checks
(tools/common/caller.py), SAML assertion validation (web/auth.py) and sign-out (web/handler.py); the last two are
skipped unless signxml and lxml are installed. No AWS calls: secrets, QuickSight, DynamoDB and the Runtime are stubs."""

import base64
import datetime as dt
from decimal import Decimal
import importlib.util
import io
import json
import os
import sys
import time
import unittest
import urllib.parse
import uuid
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for sub in ("tools/common", "web"):
    sys.path.insert(0, os.path.join(ROOT, sub))
for key, value in (("ACCOUNT_ID", "1"), ("QS_REGION", "cn-north-1"), ("AWS_REGION", "cn-north-1"),
                   ("SESSION_SECRET_ID", "x"), ("TOOL_SECRET_ID", "y"), ("SAML_SP_ENTITY_ID", "urn:example:chat"),
                   ("IDP_METADATA_PARAMETER", "/example/idp-metadata"), ("RUNTIME_ARN", "arn:example:runtime/r"),
                   ("JOBS_TABLE", "jobs"), ("ANALYSIS_TOOLS_FN", "analysis-tools")):
    os.environ.setdefault(key, value)

import jwt  # noqa: E402

import caller  # noqa: E402
import tokens  # noqa: E402

SECRET = "s" * 64
KEY = tokens.signing_key(SECRET)  # session-key
TOOL_KEY = tokens.signing_key("t" * 64)  # tool-key


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
        def b64(part):
            return base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b"=").decode()
        unsigned = f'{b64({"alg": "none", "typ": "JWT"})}.{b64(claims)}.'  # an "alg": "none" token must be refused
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
        caller._cache["tool-key"] = (time.time(), TOOL_KEY)
        caller.revocation_check = None

    def tool(self, analysis, sub="a@example.com", seconds=60, key=TOOL_KEY, **claims):
        return tokens.mint(key, tokens.TOOLS_AUDIENCE, sub, seconds, analysis=analysis, **{"sid": "s1", **claims})[0]

    def test_tool_token_needs_the_tool_key_and_a_session(self):
        for token in (self.tool("a1", key=KEY),  # a tool token signed with the session key
                      tokens.mint(TOOL_KEY, tokens.TOOLS_AUDIENCE, "a@example.com", 60, analysis="a1")[0],  # no sid
                      self.tool("a1", sid="")):
            with self.assertRaisesRegex(caller.ToolError, "用户身份校验失败"):
                caller.verify_token(token, "a1")

    def test_signed_out_session_is_refused(self):
        try:
            caller.revocation_check = lambda sid: sid == "s1"
            with self.assertRaisesRegex(caller.ToolError, "已退出登录"):
                caller.verify_token(self.tool("a1"), "a1")
            self.assertEqual(caller.verify_token(self.tool("a1", sid="s2"), "a1"), "a@example.com")
        finally:
            caller.revocation_check = None

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
        originals = caller.principals, caller.analysis_permissions, caller.dashboards_of, caller._dashboard_is_from
        try:
            caller.principals = lambda email: {"arn:u1"}
            caller.analysis_permissions = lambda aid: []
            caller.dashboards_of = lambda aid: ["d-deleted", "d-live"]
            caller._dashboard_is_from = lambda dashboard, aid: True
            caller.qs.describe_dashboard_permissions = permissions
            self.assertEqual(caller.require_viewer({"_caller": self.tool("a1"), "_analysis": "a1"}),
                             ("a@example.com", "a1", "d-live"))
        finally:
            caller.principals, caller.analysis_permissions, caller.dashboards_of, caller._dashboard_is_from = originals
            del caller.qs.describe_dashboard_permissions


try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    # Test fixture: builds and signs its own XML (SignXML requires lxml).
    from lxml import etree  # nosec B410
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

    def update_item(self, Key, UpdateExpression, ConditionExpression=None, ExpressionAttributeNames=None,  # noqa: N803
                    ExpressionAttributeValues=None, **_):
        """SET a = :v, ... honouring the "#s = :running" condition of the web Lambda's cancel()."""
        names, values = ExpressionAttributeNames or {}, ExpressionAttributeValues or {}
        item = self.items.setdefault(Key["jobId"], dict(Key))
        if ConditionExpression == "#s = :running" and item.get("status") != values[":running"]:
            raise self._Exceptions.ConditionalCheckFailedException()
        for part in UpdateExpression.removeprefix("SET ").split(","):
            name, value = (x.strip() for x in part.split("="))
            item[names.get(name, name)] = values[value]
        return {}

    def delete_item(self, Key, ReturnValues=None, ConditionExpression=None, ExpressionAttributeValues=None):  # noqa: N803
        item = self.items.get(Key["jobId"])
        values = ExpressionAttributeValues or {}
        if item is None or (ConditionExpression == "expiresAt > :now" and item.get("expiresAt", 0) <= values[":now"]):
            raise self._Exceptions.ConditionalCheckFailedException()
        return {"Attributes": self.items.pop(Key["jobId"])}


@unittest.skipIf(auth is None, "" if auth else SKIP)
class SamlTest(unittest.TestCase):
    IDP = "https://idp.example.com/saml"
    ACS = "https://chat.example.com/saml/acs"

    @classmethod
    def setUpClass(cls):
        cls.old, cls.new, cls.stranger = _keypair("old"), _keypair("new"), _keypair("stranger")
        auth._session_key, auth._tool_signing_key = KEY, TOOL_KEY
        auth.directory_name = lambda email: ""
        auth._idp.update(at=time.time() + 10**6, value=(cls.IDP, "https://idp.example.com/sso",
                                                        [cls.old[1].decode(), cls.new[1].decode()]))

    def assertion(self, request_id, assertion_id="_a", audience=None, recipient=None, in_response_to=None,
                  subject="Alex@Example.com"):
        now = dt.datetime.now(dt.timezone.utc)
        fmt = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        ns = auth.NS
        id_attribute = f' ID="{assertion_id}"' if assertion_id else ""
        # Test fixture: parses the XML it just built.
        return etree.fromstring(  # nosec B320
            f'<saml:Assertion xmlns:saml="{ns["saml"]}"{id_attribute} Version="2.0" IssueInstant="{fmt(now)}">'
            f"<saml:Issuer>{self.IDP}</saml:Issuer><saml:Subject><saml:NameID>{subject}</saml:NameID>"
            f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData '
            f'InResponseTo="{in_response_to or request_id}" Recipient="{recipient or self.ACS}" '
            f'NotOnOrAfter="{fmt(now + dt.timedelta(minutes=5))}"/>'
            f"</saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{fmt(now)}\" "
            f'NotOnOrAfter="{fmt(now + dt.timedelta(minutes=5))}"><saml:AudienceRestriction>'
            f"<saml:Audience>{audience or auth.SP_ENTITY_ID}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
            f"</saml:Assertion>")

    def response(self, request_id, signer, assertion_id="_a", audience=None, recipient=None, in_response_to=None,
                 sign=True, prefix=b"", wrap=False, count=1):
        """A base64 SAMLResponse. prefix: bytes put before the XML (a DOCTYPE); wrap: the signed assertion moved into
        samlp:Extensions with a forged unsigned assertion in its place; count: number of signed assertions."""
        ns = auth.NS
        # Test fixture: parses the XML it just built.
        root = etree.fromstring(f'<samlp:Response xmlns:samlp="{ns["samlp"]}" ID="_r" Version="2.0">'  # nosec B320
                                f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
                                f"</samlp:Status></samlp:Response>")
        for i in range(count):
            assertion = self.assertion(request_id, assertion_id + (str(i) if i else ""), audience, recipient,
                                       in_response_to)
            if sign:
                assertion = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(
                    assertion, key=signer[0], cert=signer[1])
            if wrap:
                etree.SubElement(root, etree.QName(ns["samlp"], "Extensions")).append(assertion)
                root.append(self.assertion(request_id, "_forged", subject="mallory@example.com"))
            else:
                root.append(assertion)
        return base64.b64encode(prefix + etree.tostring(root)).decode()

    def refused(self, message, **kwargs):
        table = FakeTable()
        request_id = self.start(table)
        with self.assertRaisesRegex(auth.AuthError, message):
            auth.complete_login(table, self.response(request_id, self.old, "_" + uuid.uuid4().hex, **kwargs),
                                request_id, self.ACS)

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
        tool = auth.mint_tool_token("alex@example.com", "a1", 60, sid=claims["jti"])
        self.assertIsNone(auth.verify_session(tool, table))  # a tool token is not a sign-in
        self.assertEqual(tokens.verify(TOOL_KEY, tool, tokens.TOOLS_AUDIENCE)["sid"], claims["jti"])
        with self.assertRaises(tokens.InvalidToken):  # signed with the tool key, not the session key
            tokens.verify(KEY, tool, tokens.TOOLS_AUDIENCE)

    def test_browser_session_exchange_is_short_lived_and_one_time(self):
        table = FakeTable()
        session_id = "s" * 43
        session_expiry = int(time.time()) + 300
        exchange = auth.create_browser_exchange(table, session_id, session_expiry)
        self.assertEqual(auth.consume_browser_exchange(table, exchange), (session_id, session_expiry))
        with self.assertRaisesRegex(auth.AuthError, "expired or already used"):
            auth.consume_browser_exchange(table, exchange)
        expired = auth.create_browser_exchange(table, session_id, session_expiry)
        table.items[auth._browser_exchange_key(expired)["jobId"]]["expiresAt"] = int(time.time()) - 1
        with self.assertRaisesRegex(auth.AuthError, "expired or already used"):
            auth.consume_browser_exchange(table, expired)

    def test_rejects_doctype_external_entities_and_entity_expansion(self):
        xxe = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        laughs = b'<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
        for prefix in (xxe, laughs, b'<!doctype r SYSTEM "http://attacker.example/x.dtd">'):
            self.refused("DOCTYPE", prefix=prefix)
        utf16 = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>'.encode("utf-16")
        with self.assertRaises(auth.UnsafeXml):  # the byte check cannot see it; the parsed docinfo does
            auth._parse_xml(utf16)
        metadata = (b'<!DOCTYPE m [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                    b'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&x;"/>')
        with self.assertRaisesRegex(RuntimeError, "DOCTYPE"):
            auth.parse_idp_metadata(metadata)

    def test_rejects_two_assertions_wrapping_and_unsigned(self):
        self.refused("exactly one", count=2)
        self.refused("not signed", wrap=True)  # signature wrapping: the signed assertion is not the one read
        self.refused("not signed", sign=False)

    def test_rejects_wrong_audience_recipient_and_request(self):
        self.refused("audience mismatch", audience="urn:example:other-app")
        self.refused("bearer confirmation", recipient="https://evil.example.com/saml/acs")
        self.refused("bearer confirmation", in_response_to="_" + uuid.uuid4().hex)

    def test_authn_request_is_built_as_xml(self):
        table = FakeTable()
        acs = 'https://chat.example.com/saml/acs?x=1&y="<z>'
        location = auth.login_redirect(table, "n" * 32, acs)
        self.assertTrue(location.startswith("https://idp.example.com/sso?SAMLRequest="))
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
        xml = zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), -15)
        # Test fixture: parses the request the code under test just built.
        request = etree.fromstring(xml)  # nosec B320
        self.assertEqual(request.tag, f"{{{auth.NS['samlp']}}}AuthnRequest")
        self.assertEqual(request.get("ID"), query["RelayState"][0])
        self.assertEqual(request.get("AssertionConsumerServiceURL"), acs)
        self.assertEqual(request.findtext("saml:Issuer", namespaces=auth.NS), auth.SP_ENTITY_ID)
        self.assertIn(f"saml#{request.get('ID')}", table.items)


class _Runtime:
    """The AgentCore Runtime client of the web Lambda: acknowledges jobs and cancel signals."""

    def __init__(self):
        self.payloads = []

    def invoke_agent_runtime(self, **kwargs):
        self.payloads.append(json.loads(kwargs["payload"]))
        return {"response": io.BytesIO(json.dumps({"accepted": True, "cancelled": True}).encode())}


@unittest.skipIf(auth is None, "" if auth else SKIP)
class WebLogoutTest(unittest.TestCase):
    """Sign-out revokes the session, cancels its running answers, and its tool tokens stop working."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("web_handler", os.path.join(ROOT, "web", "handler.py"))
        cls.web = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.web)

    def setUp(self):
        auth._session_key, auth._tool_signing_key = KEY, TOOL_KEY
        self.table, self.runtime = FakeTable(), _Runtime()
        self.web.jobs, self.web.agentcore = self.table, self.runtime
        self.token, self.claims = auth.mint_session("alex@example.com", "Alex")

    def call(self, method, path, body=None):
        return self.web.handler({"requestContext": {"http": {"method": method}, "domainName": "chat.example.com"},
                                 "rawPath": path, "headers": {"authorization": f"Bearer {self.token}"},
                                 "body": json.dumps(body) if body is not None else ""}, None)

    def test_browser_session_dynamodb_numbers_serialize_in_me_response(self):
        session_id, csrf = auth.create_browser_session(self.table, self.claims)
        item = self.table.items[auth._browser_session_key(session_id)["jobId"]]
        item["iat"], item["exp"] = Decimal(item["iat"]), Decimal(item["exp"])
        response = self.web.handler({
            "requestContext": {"http": {"method": "GET"}, "domainName": "chat.example.com"},
            "rawPath": "/me", "headers": {"cookie": f"{self.web.BROWSER_COOKIE}={session_id}"}, "body": "",
        }, None)
        body = json.loads(response["body"])
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual((body["sub"], body["csrf"]), (self.claims["sub"], csrf))
        self.assertIsInstance(body["exp"], int)

    def test_browser_exchange_sets_a_partitioned_httponly_cookie_once(self):
        session_id, _csrf = auth.create_browser_session(self.table, self.claims)
        exchange = auth.create_browser_exchange(self.table, session_id, self.claims["exp"])
        event = {
            "requestContext": {"http": {"method": "POST"}, "domainName": "chat.example.com"},
            "rawPath": "/auth/exchange", "headers": {"content-type": "application/json"},
            "body": json.dumps({"exchange": exchange}),
        }
        response = self.web.handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(len(response["cookies"]), 1)
        cookie = response["cookies"][0]
        self.assertIn(f"{self.web.BROWSER_COOKIE}={session_id};", cookie)
        self.assertIn("; Secure; HttpOnly; SameSite=None; Partitioned", cookie)
        self.assertNotIn(session_id, response["body"])
        self.assertEqual(self.web.handler(event, None)["statusCode"], 401)

    def test_logout_cancels_running_jobs_and_revokes_tool_tokens(self):
        ids = [json.loads(self.call("POST", "/chat", {"prompt": "趋势", "analysis": "a1"})["body"])["jobId"]
               for _ in range(2)]
        jti = self.claims["jti"]
        self.assertEqual([self.table.items[i]["sid"] for i in ids], [jti, jti])
        tool_tokens = [p["auth"] for p in self.runtime.payloads]
        self.assertEqual([tokens.verify(TOOL_KEY, t, tokens.TOOLS_AUDIENCE)["sid"] for t in tool_tokens], [jti, jti])
        self.assertEqual(self.table.items[f"sessjobs#{jti}"]["jobIds"], ids)

        out = self.call("POST", "/auth/logout", {})
        self.assertEqual((out["statusCode"], json.loads(out["body"])["cancelled"]), (200, 2))
        self.assertEqual([self.table.items[i]["status"] for i in ids], ["CANCELLED", "CANCELLED"])
        # the record outlives the job tool tokens (8 h), not just the 1-hour session token
        self.assertGreaterEqual(self.table.items[f"revoked#{jti}"]["expiresAt"],
                                int(time.time()) + self.web.JOB_TOKEN_SECONDS)
        self.assertEqual(self.call("GET", "/me")["statusCode"], 401)
        try:  # the analysis tools' hook (tools/analysis/handler.py) reads the same revoked# record
            caller._cache["tool-key"] = (time.time(), TOOL_KEY)
            caller.revocation_check = lambda sid: bool(self.table.get_item(Key={"jobId": f"revoked#{sid}"}).get("Item"))
            with self.assertRaisesRegex(caller.ToolError, "已退出登录"):
                caller.verify_token(tool_tokens[0], "a1")
        finally:
            caller.revocation_check = None

    def test_remembers_the_newest_jobs_only(self):
        for i in range(self.web.SESSION_JOBS_MAX + 5):
            self.web._remember_job(self.claims, f"{i:032x}")
        ids = self.table.items[f"sessjobs#{self.claims['jti']}"]["jobIds"]
        self.assertEqual(ids, [f"{i:032x}" for i in range(5, self.web.SESSION_JOBS_MAX + 5)])


if __name__ == "__main__":
    unittest.main()
