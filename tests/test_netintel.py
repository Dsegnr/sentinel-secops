from sentinel.core import netintel


def test_registrable_domain():
    assert netintel.registrable_domain("a.b.example.com") == "example.com"
    assert netintel.registrable_domain("example.com.cn") == "example.com.cn"
    assert netintel.registrable_domain("www.example.co.uk") == "example.co.uk"
    assert netintel.registrable_domain("example.com") == "example.com"
    assert netintel.registrable_domain("cn") == "cn"


def test_fmt_age():
    assert netintel.fmt_age("") == ""
    assert "年" in netintel.fmt_age("2020-01-01")
    assert netintel.fmt_age("not-a-date") == ""


def test_parse_whois_fields():
    raw = (
        "Domain Name: EXAMPLE.COM\n"
        "Registrar: RESERVED-Internet Assigned Numbers Authority\n"
        "Creation Date: 1995-08-14T04:00:00Z\n"
        "Registry Expiry Date: 2027-08-13T04:00:00Z\n"
        "Domain Status: clientDeleteProhibited\n"
        "Name Server: ELLIOTT.NS.CLOUDFLARE.COM\n"
        "Registrar Abuse Contact Email: abuse@iana.org\n"
    )
    info = netintel.parse_whois(raw)
    assert info["registrar"].startswith("RESERVED")
    assert info["created"].startswith("1995")
    assert info["expires"].startswith("2027")
    assert "clientDeleteProhibited" in info["statuses"]
    assert "elliott.ns.cloudflare.com" in info["nameservers"]
    assert info["abuse_email"] == "abuse@iana.org"


def test_parse_rdap():
    data = {
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
        ],
        "status": ["client delete prohibited"],
        "nameservers": [{"ldhName": "ELLIOTT.NS.CLOUDFLARE.COM"}],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "RESERVED Registry"]]],
            },
            {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@iana.org"]]]},
        ],
    }
    info = netintel.parse_rdap(data)
    assert info["registrar"] == "RESERVED Registry"
    assert info["created"].startswith("1995")
    assert info["abuse_email"] == "abuse@iana.org"
    assert info["nameservers"] == ["elliott.ns.cloudflare.com"]


def test_txt_of():
    rec = {"TXT": ["v=spf1 -all", "google-site-verification=x", "V=DMARC1; p=reject"]}
    assert netintel.txt_of(rec, "v=spf1") == ["v=spf1 -all"]
    assert len(netintel.txt_of(rec, "v=dmarc1")) == 1
    assert netintel.txt_of(rec, "v=dkim1") == []
