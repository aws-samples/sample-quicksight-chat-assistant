"""IAM Identity Center SAML 2.0 (SP-initiated) login, session tokens and tool tokens for the chat page.

The Identity Center application metadata (XML) is read from the SSM parameter IDP_METADATA_PARAMETER on first use,
so it can be set after deployment (`./qsca idp-metadata <file>`) without redeploying. Tokens are JWTs signed with
HS256 by PyJWT (tools/common/tokens.py, shared with the tool Lambdas). Two keys: session tokens are signed with the
Secrets Manager secret SESSION_SECRET_ID, which only this Lambda can read; tool tokens with TOOL_SECRET_ID, which the
tool Lambdas read to verify them (so a tool Lambda cannot mint a browser session).

All XML parsing goes through _parse_xml: a parser that resolves no entities, loads no DTD and fetches nothing, and
any document with a DOCTYPE is refused. The AuthnRequest is built with lxml element APIs, never by string formatting.

Flow: the chat iframe opens a popup at /auth/login?nonce=..., which redirects to Identity Center with an
AuthnRequest. Identity Center posts a signed assertion to /saml/acs. After validation the popup hands a
session token (1 hour by default) back to the iframe with postMessage, restricted to this origin and matched by
nonce. Sign-out revokes the session token (its jti is stored until it would have expired). Tool calls never use the
session token: the web Lambda issues a separate tool token per job or button click (see tokens.py).
"""

import base64
import datetime as dt
import json
import os
import re
import time
import urllib.parse
import uuid
import zlib

import boto3
from botocore.config import Config
# SignXML requires lxml; every parse in this module goes through _parse_xml (hardened parser, DOCTYPE refused).
from lxml import etree  # nosec B410
from signxml import XMLVerifier
from signxml.exceptions import SignXMLException

import tokens

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}
SP_ENTITY_ID = os.environ["SAML_SP_ENTITY_ID"]
SESSION_SECRET_ID = os.environ["SESSION_SECRET_ID"]
TOOL_SECRET_ID = os.environ["TOOL_SECRET_ID"]
IDP_METADATA_PARAMETER = os.environ["IDP_METADATA_PARAMETER"]
SESSION_SECONDS = int(os.environ.get("SESSION_SECONDS", "3600"))
LOGIN_SECONDS = 600
CLOCK_SKEW = dt.timedelta(minutes=3)
SAFE_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False,
                              huge_tree=False, remove_comments=True, remove_pis=True)
DOCTYPE = re.compile(rb"<!DOCTYPE", re.I)


class AuthError(Exception):
    pass


class NotConfigured(Exception):
    """Identity Center metadata has not been stored yet."""


class UnsafeXml(Exception):
    """The document declares a DOCTYPE (DTDs, entities); SAML and metadata never need one."""


def _parse_xml(data):
    """Parse untrusted XML bytes with SAFE_PARSER; any DOCTYPE is refused before and after parsing."""
    if DOCTYPE.search(data):
        raise UnsafeXml("DOCTYPE not allowed")
    # Hardened parser: no entity resolution, no DTD loading, no network, no huge trees; DOCTYPE refused above.
    root = etree.fromstring(data, SAFE_PARSER)  # nosec B320
    info = root.getroottree().docinfo
    if info.doctype or info.internalDTD is not None:  # e.g. a DOCTYPE in UTF-16, which the byte check cannot see
        raise UnsafeXml("DOCTYPE not allowed")
    return root


def parse_idp_metadata(xml_bytes):
    try:
        root = _parse_xml(xml_bytes)
    except UnsafeXml as error:
        raise RuntimeError("Identity Center metadata must not contain a DOCTYPE") from error
    entity_id = root.get("entityID")
    redirect = root.xpath(
        "//md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location",
        namespaces=NS,
    )
    certs = root.xpath("//md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use='signing']//ds:X509Certificate/text()", namespaces=NS)
    if not (entity_id and redirect and certs):
        raise RuntimeError("Identity Center metadata is missing entityID, redirect binding or signing certificate")
    pems = []
    for cert in certs:  # every signing certificate: during a certificate rotation the metadata lists old and new
        body = "".join(cert.split())
        pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END CERTIFICATE-----\n"
        if pem not in pems:
            pems.append(pem)
    return entity_id, redirect[0], pems


_idp = {}


def idp():
    """(entity id, SSO redirect URL, [signing certificate PEM]), loaded from SSM and cached for 5 minutes."""
    if not _idp or time.time() - _idp["at"] > 300:
        ssm = boto3.client("ssm")
        try:
            raw = ssm.get_parameter(Name=IDP_METADATA_PARAMETER)["Parameter"]["Value"]
        except ssm.exceptions.ParameterNotFound as error:
            raise NotConfigured("管理员尚未上传 Identity Center 元数据") from error
        _idp.update(at=time.time(), value=parse_idp_metadata(raw.encode("utf-8")))
    return _idp["value"]


_session_key = None
_tool_signing_key = None


def _key():
    """The session-token key (SESSION_SECRET_ID): browser sessions only, readable by this Lambda alone."""
    global _session_key
    if _session_key is None:
        raw = boto3.client("secretsmanager").get_secret_value(SecretId=SESSION_SECRET_ID)["SecretString"]
        _session_key = tokens.signing_key(raw)
    return _session_key


def _tool_key():
    """The tool-token key (TOOL_SECRET_ID), shared with the tool Lambdas that verify tool tokens."""
    global _tool_signing_key
    if _tool_signing_key is None:
        raw = boto3.client("secretsmanager").get_secret_value(SecretId=TOOL_SECRET_ID)["SecretString"]
        _tool_signing_key = tokens.signing_key(raw)
    return _tool_signing_key


def _revoked_key(jti):
    return {"jobId": f"revoked#{jti}"}


def mint_session(subject, name):
    """The browser's session token after a validated SAML login: (token, claims)."""
    return tokens.mint(_key(), tokens.SESSION_AUDIENCE, subject, SESSION_SECONDS, name=name)


def verify_session(token, table):
    """Return the session claims, or None when the token is missing, forged, expired, meant for the tools, or
    revoked by sign-out."""
    try:
        claims = tokens.verify(_key(), token, tokens.SESSION_AUDIENCE)
    except tokens.InvalidToken:
        return None
    if table.get_item(Key=_revoked_key(claims["jti"]), ConsistentRead=True).get("Item"):
        return None
    return claims


def revoke_session(table, claims):
    """Sign-out: the session token stops working at once; the record expires (TTL) when the token would have."""
    table.put_item(Item={**_revoked_key(claims["jti"]), "createdAt": int(time.time()),
                         "expiresAt": int(claims["exp"]) + tokens.LEEWAY_SECONDS + 60})


def mint_tool_token(subject, analysis, seconds, sid, jti=None):
    """A token for the analysis/data tool Lambdas, bound to this user and analysis ("" for the analysis picker) and
    to the browser session `sid` (its jti) it was issued under, so sign-out can stop it (tools/common/caller.py)."""
    return tokens.mint(_tool_key(), tokens.TOOLS_AUDIENCE, subject, seconds, jti=jti, analysis=analysis or "",
                       sid=sid)[0]


def _authn_request(request_id, instant, sso_url, acs_url):
    """The SAML AuthnRequest XML, built with element APIs (attribute values are escaped by lxml)."""
    request = etree.Element(etree.QName(NS["samlp"], "AuthnRequest"), nsmap={"samlp": NS["samlp"], "saml": NS["saml"]})
    for name, value in (("ID", request_id), ("Version", "2.0"), ("IssueInstant", instant), ("Destination", sso_url),
                        ("AssertionConsumerServiceURL", acs_url),
                        ("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")):
        request.set(name, value)
    etree.SubElement(request, etree.QName(NS["saml"], "Issuer")).text = SP_ENTITY_ID
    return etree.tostring(request)


def login_redirect(table, nonce, acs_url):
    """Store the pending request and return the Identity Center redirect URL."""
    _entity, sso_url, _cert = idp()
    request_id = "_" + uuid.uuid4().hex
    now = int(time.time())
    table.put_item(Item={"jobId": f"saml#{request_id}", "nonce": nonce, "createdAt": now, "expiresAt": now + LOGIN_SECONDS})
    instant = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    deflater = zlib.compressobj(9, zlib.DEFLATED, -15)
    request = _authn_request(request_id, instant, sso_url, acs_url)
    encoded = base64.b64encode(deflater.compress(request) + deflater.flush()).decode("ascii")
    separator = "&" if "?" in sso_url else "?"
    return sso_url + separator + urllib.parse.urlencode({"SAMLRequest": encoded, "RelayState": request_id})


def _time(value, name):
    if not value:
        raise AuthError(f"missing {name}")
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _verified_assertion(response_xml):
    try:
        return _verify_signature(response_xml)
    except SignXMLException as error:
        raise AuthError(f"signature invalid: {type(error).__name__}") from error
    except etree.XMLSyntaxError as error:
        raise AuthError("SAMLResponse is not well-formed XML") from error


def _verify_with_idp_certs(xml):
    """Verify the XML signature against each Identity Center signing certificate in turn (old and new during a
    rotation); signxml ignores any key in the document itself. Returns the element the signature covers."""
    error = None
    for pem in idp()[2]:
        try:
            return XMLVerifier().verify(xml, x509_cert=pem, ignore_ambiguous_key_info=True).signed_xml
        except SignXMLException as failure:
            error = failure
    raise error


def _verify_signature(response_xml):
    try:
        root = _parse_xml(response_xml)
    except UnsafeXml as error:
        raise AuthError("SAMLResponse must not contain a DOCTYPE") from error
    if root.tag != f"{{{NS['samlp']}}}Response":
        raise AuthError("not a SAML Response")
    assertions = root.findall("saml:Assertion", NS)
    if len(assertions) != 1 or root.findall(".//saml:EncryptedAssertion", NS):
        raise AuthError("expected exactly one plain assertion")
    if assertions[0].find("ds:Signature", NS) is not None:
        signed = _verify_with_idp_certs(etree.tostring(assertions[0]))
    elif root.find("ds:Signature", NS) is not None:
        signed_root = _verify_with_idp_certs(response_xml)
        inner = signed_root.findall("saml:Assertion", NS)
        if len(inner) != 1:
            raise AuthError("signed response does not contain exactly one assertion")
        signed = inner[0]
    else:
        raise AuthError("SAML response is not signed")
    if signed.tag != f"{{{NS['saml']}}}Assertion":
        raise AuthError("signature does not cover the assertion")
    status = root.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != "urn:oasis:names:tc:SAML:2.0:status:Success":
        raise AuthError(f"SAML status {status.get('Value') if status is not None else 'missing'}")
    return signed


def complete_login(table, saml_response_b64, relay_state, acs_url):
    """Validate the posted assertion and return (session token, payload, nonce)."""
    if not relay_state or not relay_state.startswith("_") or len(relay_state) > 64:
        raise AuthError("unsolicited login: start from the chat panel")
    try:
        pending = table.delete_item(Key={"jobId": f"saml#{relay_state}"}, ReturnValues="ALL_OLD",
                                    ConditionExpression="attribute_exists(jobId)").get("Attributes")
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        pending = None
    if not pending or int(pending["createdAt"]) + LOGIN_SECONDS < time.time():
        raise AuthError("login request expired or already used")

    try:
        response_xml = base64.b64decode(saml_response_b64, validate=False)
    except ValueError as error:
        raise AuthError("SAMLResponse is not base64") from error
    if len(response_xml) > 200_000:
        raise AuthError("SAMLResponse too large")
    assertion = _verified_assertion(response_xml)

    now = dt.datetime.now(dt.timezone.utc)
    issuer = assertion.findtext("saml:Issuer", namespaces=NS)
    if issuer != idp()[0]:
        raise AuthError(f"unexpected issuer {issuer}")
    conditions = assertion.find("saml:Conditions", NS)
    if conditions is None:
        raise AuthError("missing Conditions")
    if conditions.get("NotBefore") and _time(conditions.get("NotBefore"), "NotBefore") > now + CLOCK_SKEW:
        raise AuthError("assertion not yet valid")
    if _time(conditions.get("NotOnOrAfter"), "NotOnOrAfter") <= now - CLOCK_SKEW:
        raise AuthError("assertion expired")
    audiences = conditions.xpath("saml:AudienceRestriction/saml:Audience/text()", namespaces=NS)
    if SP_ENTITY_ID not in [audience.strip() for audience in audiences]:
        raise AuthError(f"audience mismatch {audiences}")

    confirmations = assertion.xpath(
        "saml:Subject/saml:SubjectConfirmation[@Method='urn:oasis:names:tc:SAML:2.0:cm:bearer']/saml:SubjectConfirmationData",
        namespaces=NS,
    )
    if not any(
        data.get("Recipient") == acs_url
        and data.get("InResponseTo") == relay_state
        and _time(data.get("NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter") > now - CLOCK_SKEW
        for data in confirmations
    ):
        raise AuthError("bearer confirmation does not match this request")

    subject = (assertion.findtext("saml:Subject/saml:NameID", namespaces=NS) or "").strip()
    if not subject or len(subject) > 256:
        raise AuthError("missing NameID")
    assertion_id = assertion.get("ID") or ""
    if not assertion_id or len(assertion_id) > 256:
        raise AuthError("assertion has no valid ID")
    try:
        table.put_item(Item={"jobId": f"samlassert#{assertion_id}", "createdAt": int(time.time()),
                             "expiresAt": int(time.time()) + 24 * 3600},
                       ConditionExpression="attribute_not_exists(jobId)")
    except table.meta.client.exceptions.ConditionalCheckFailedException as error:
        raise AuthError("assertion replayed") from error

    attributes = {
        attr.get("Name"): attr.findtext("saml:AttributeValue", namespaces=NS)
        for attr in assertion.findall("saml:AttributeStatement/saml:Attribute", NS)
    }
    name = display_name(attributes)
    source = "assertion" if name else ""
    if not name:
        name = directory_name(subject)
        source = "directory" if name else "email"
    token, payload = mint_session(subject.lower(), name or subject)
    payload["name_source"] = source
    return token, payload, pending["nonce"], sorted(attributes)


_identity_store = {}


def directory_name(email):
    """The user's name from the Identity Center identity store, looked up by email. Best effort: any failure (no
    permission, user not found, timeout) just means the chat page shows the email."""
    try:
        if "client" not in _identity_store:
            region = os.environ.get("IDENTITY_CENTER_REGION") or None
            config = Config(connect_timeout=2, read_timeout=3, retries={"max_attempts": 2})
            store_id = os.environ.get("IDENTITY_STORE_ID") or \
                boto3.client("sso-admin", region_name=region, config=config).list_instances()["Instances"][0]["IdentityStoreId"]
            _identity_store.update(client=boto3.client("identitystore", region_name=region, config=config), id=store_id)
        client, store_id = _identity_store["client"], _identity_store["id"]
        user_id = client.get_user_id(IdentityStoreId=store_id, AlternateIdentifier={
            "UniqueAttribute": {"AttributePath": "emails.value", "AttributeValue": email}})["UserId"]
        user = client.describe_user(IdentityStoreId=store_id, UserId=user_id)
        name = user.get("Name") or {}
        return display_name({"familyName": name.get("FamilyName"), "givenName": name.get("GivenName"),
                             "displayName": user.get("DisplayName")})
    except Exception as error:  # noqa: BLE001 - the name is cosmetic; never fail a login over it
        print(json.dumps({"auth": "name_lookup_failed", "error": repr(error)[:200]}))
        return ""


CJK = re.compile(r"[\u3400-\u9fff\uf900-\ufaff]")


def display_name(attributes):
    """Readable user name from optional SAML attributes (Identity Center attribute mappings, see README):
    familyName/givenName -> "张伟" for CJK names (family name first, no space) or "Alex Lee"; else displayName/name.
    The value is only shown in the chat page; the email Subject stays the identity."""
    clean = {k: " ".join(str(v or "").split())[:100] for k, v in attributes.items()}
    family, given = clean.get("familyName", ""), clean.get("givenName", "")
    if family and given:
        return f"{family}{given}" if CJK.search(family + given) else f"{given} {family}"
    return clean.get("displayName") or clean.get("name") or clean.get("username") or given or ""
