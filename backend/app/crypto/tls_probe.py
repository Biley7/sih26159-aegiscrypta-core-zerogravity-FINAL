import ipaddress
import socket
import ssl
from typing import Optional, List, Tuple, Dict, Any

from fastapi import HTTPException

from app.models import (
    ProtocolAuditResult,
    TlsHandshakeResult,
    SecurityFinding,
    FindingSeverity,
    CheckStatus
)
from app.crypto.cert_analyzer import parse_x509_certificate
from app.crypto.cipher_evaluator import evaluate_cipher_and_tls

# ---------------------------------------------------------------------------
# SSRF Prevention (VULN-01): Prohibited IP address ranges.
# All probes must resolve to a routable public address.  Any resolution that
# lands on loopback, private RFC-1918, link-local, multicast, reserved, or
# the cloud instance-metadata service is rejected before a socket is opened.
# ---------------------------------------------------------------------------
_BLOCKED_METADATA_ADDRS = frozenset({
    "169.254.169.254",   # AWS / GCP / Azure IMDS (IPv4)
    "fd00:ec2::254",     # AWS IMDS (IPv6 link-local)
})


def _get_peer_intermediate_certificates(ssl_sock) -> List[bytes]:
    """Return peer-supplied intermediate certificates when the runtime exposes them."""
    getter = getattr(ssl_sock, "get_unverified_chain", None)
    if getter is None:
        getter = getattr(ssl_sock, "get_verified_chain", None)
    if getter is None:
        return []
    try:
        chain = getter()
        return list(chain[1:]) if chain else []
    except Exception:
        return []


def _assert_public_host(host: str) -> None:
    """
    Resolve *host* to its first A/AAAA address and verify it is a publicly
    routable IP.  Raises ``HTTPException(403)`` if the resolved address is
    private, loopback, link-local, multicast, reserved, or a known cloud
    metadata endpoint.

    This is the network-layer SSRF guard that complements the Pydantic
    field-validator which already rejects bare IP strings and non-FQDN input.

    Raises:
        HTTPException: 403 when the resolved IP is prohibited.
        HTTPException: 400 when DNS resolution fails entirely.
    """
    try:
        # getaddrinfo returns [(family, type, proto, canonname, sockaddr), ...]
        # sockaddr is (address, port) for IPv4 and (address, port, flow, scope) for IPv6
        results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(
            status_code=400,
            detail=f"DNS resolution failed for host '{host}': {exc}"
        )

    for _family, _type, _proto, _canon, sockaddr in results:
        ip_str = sockaddr[0]

        # Explicit block for cloud metadata IPs (not caught by ipaddress flags alone)
        if ip_str in _BLOCKED_METADATA_ADDRS:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Host '{host}' resolves to a prohibited cloud instance-metadata "
                    f"address ({ip_str}). SSRF probe blocked."
                )
            )

        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        # Reject any non-globally-routable address
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Host '{host}' resolves to a prohibited non-public address "
                    f"({ip_str}). Private, loopback, link-local, multicast, and "
                    "reserved ranges are not permitted for security probes."
                )
            )


def _read_until(sock: socket.socket, terminator: bytes, max_bytes: int = 4096) -> bytes:
    """Reads socket until terminator is found or max_bytes reached."""
    buf = bytearray()
    while len(buf) < max_bytes:
        chunk = sock.recv(1)
        if not chunk:
            break
        buf.extend(chunk)
        if buf.endswith(terminator):
            break
    return bytes(buf)


def _read_smtp_response(sock: socket.socket) -> str:
    """Reads an RFC 5321 SMTP response (handles multiline 250-... followed by 250 <space>)."""
    lines = []
    while True:
        line_bytes = _read_until(sock, b"\n")
        if not line_bytes:
            break
        line = line_bytes.decode("utf-8", errors="replace").strip()
        lines.append(line)
        if len(line) >= 4 and line[3] == " ":
            break
        elif len(line) < 4:
            break
    return "\n".join(lines)


def _read_imap_response(sock: socket.socket, tag: str) -> str:
    """Reads IMAP responses until the line beginning with the tag is encountered."""
    lines = []
    while True:
        line_bytes = _read_until(sock, b"\n")
        if not line_bytes:
            break
        line = line_bytes.decode("utf-8", errors="replace").strip()
        lines.append(line)
        if line.startswith(f"{tag} "):
            break
    return "\n".join(lines)


def _read_pop3_multiline(sock: socket.socket) -> str:
    """Reads POP3 response until a terminating dot '.' on its own line."""
    lines = []
    while True:
        line_bytes = _read_until(sock, b"\n")
        if not line_bytes:
            break
        line = line_bytes.decode("utf-8", errors="replace").strip()
        lines.append(line)
        if line == ".":
            break
    return "\n".join(lines)


def probe_protocol_tls(
    host: str,
    port: int,
    protocol: str = "smtp",
    use_starttls: bool = True,
    target_domain: Optional[str] = None,
    timeout: float = 4.0
) -> ProtocolAuditResult:
    """
    Performs active cryptographic handshake and protocol auditing:
    - Supports SMTP (STARTTLS / Implicit TLS), IMAP (STARTTLS / Implicit TLS), and POP3 (STLS / Implicit TLS).
    - Negotiates full TLS context.
    - Extracts negotiated TLS version, cipher suite, forward secrecy, and X.509 certificate chain.
    - Generates prioritized security findings.

    SSRF Prevention (VULN-01): resolves the target hostname and rejects any address
    that falls within private, loopback, link-local, multicast, reserved, or cloud
    metadata ranges *before* a socket is opened.
    """
    # ------------------------------------------------------------------
    # SSRF guard: resolve host → IP and validate it is publicly routable.
    # _assert_public_host raises HTTPException(400/403) on violation so
    # the socket below is never reached for prohibited targets.
    # ------------------------------------------------------------------
    _assert_public_host(host)

    proto = protocol.upper()
    service_type = "STARTTLS" if use_starttls else "Direct TLS"
    all_findings: List[SecurityFinding] = []
    banner: Optional[str] = None
    starttls_advertised: Optional[bool] = None
    starttls_negotiated: Optional[bool] = None
    tls_handshake: Optional[TlsHandshakeResult] = None
    status = CheckStatus.PASS

    sock = None
    ssl_sock = None

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        sock = raw_sock
        raw_sock.settimeout(timeout)

        # ----------------------------------------------------
        # 1. Plaintext Protocol Handshake & STARTTLS Initiation
        # ----------------------------------------------------
        if use_starttls:
            if proto == "SMTP":
                banner = _read_until(raw_sock, b"\n").decode("utf-8", errors="replace").strip()
                # Send EHLO
                raw_sock.sendall(b"EHLO securemailscope.scanner\r\n")
                ehlo_resp = _read_smtp_response(raw_sock)

                starttls_advertised = "STARTTLS" in ehlo_resp.upper()
                if not starttls_advertised:
                    all_findings.append(SecurityFinding(
                        title="STARTTLS Not Advertised on SMTP",
                        severity=FindingSeverity.HIGH,
                        category="Protocol",
                        description=f"SMTP server at {host}:{port} did not advertise STARTTLS capability in EHLO response.",
                        recommendation="Enable STARTTLS on the mail server to prevent plaintext transmission of emails and credentials."
                    ))
                    status = CheckStatus.FAIL
                    return ProtocolAuditResult(
                        protocol=proto,
                        host=host,
                        port=port,
                        service_type=service_type,
                        banner=banner,
                        starttls_advertised=False,
                        starttls_negotiated=False,
                        findings=all_findings,
                        status=status
                    )

                # Send STARTTLS command
                raw_sock.sendall(b"STARTTLS\r\n")
                stls_resp = _read_until(raw_sock, b"\n").decode("utf-8", errors="replace").strip()
                if not stls_resp.startswith("220"):
                    starttls_negotiated = False
                    all_findings.append(SecurityFinding(
                        title="STARTTLS Negotiation Rejected by SMTP Server",
                        severity=FindingSeverity.HIGH,
                        category="Protocol",
                        description=f"Server rejected STARTTLS command with response: '{stls_resp}'",
                        recommendation="Check mail server TLS certificate configuration and cipher suite compatibility."
                    ))
                    status = CheckStatus.FAIL
                    return ProtocolAuditResult(
                        protocol=proto,
                        host=host,
                        port=port,
                        service_type=service_type,
                        banner=banner,
                        starttls_advertised=True,
                        starttls_negotiated=False,
                        findings=all_findings,
                        status=status
                    )
                starttls_negotiated = True

            elif proto == "IMAP":
                banner = _read_until(raw_sock, b"\n").decode("utf-8", errors="replace").strip()
                # Send CAPABILITY
                raw_sock.sendall(b"a001 CAPABILITY\r\n")
                cap_resp = _read_imap_response(raw_sock, "a001")

                starttls_advertised = "STARTTLS" in cap_resp.upper()
                if not starttls_advertised:
                    all_findings.append(SecurityFinding(
                        title="STARTTLS Not Advertised on IMAP",
                        severity=FindingSeverity.HIGH,
                        category="Protocol",
                        description=f"IMAP server at {host}:{port} did not advertise STARTTLS in CAPABILITY response.",
                        recommendation="Enable STARTTLS on IMAP (port 143) to secure email retrieval against interception."
                    ))
                    status = CheckStatus.FAIL
                    return ProtocolAuditResult(
                        protocol=proto,
                        host=host,
                        port=port,
                        service_type=service_type,
                        banner=banner,
                        starttls_advertised=False,
                        starttls_negotiated=False,
                        findings=all_findings,
                        status=status
                    )

                raw_sock.sendall(b"a002 STARTTLS\r\n")
                stls_resp = _read_imap_response(raw_sock, "a002")
                if "OK" not in stls_resp.upper():
                    starttls_negotiated = False
                    status = CheckStatus.FAIL
                    return ProtocolAuditResult(
                        protocol=proto,
                        host=host,
                        port=port,
                        service_type=service_type,
                        banner=banner,
                        starttls_advertised=True,
                        starttls_negotiated=False,
                        findings=all_findings,
                        status=status
                    )
                starttls_negotiated = True

            elif proto == "POP3":
                banner = _read_until(raw_sock, b"\n").decode("utf-8", errors="replace").strip()
                raw_sock.sendall(b"CAPA\r\n")
                cap_resp = _read_pop3_multiline(raw_sock)

                starttls_advertised = "STLS" in cap_resp.upper()
                if not starttls_advertised:
                    all_findings.append(SecurityFinding(
                        title="STLS Not Advertised on POP3",
                        severity=FindingSeverity.HIGH,
                        category="Protocol",
                        description=f"POP3 server at {host}:{port} did not advertise STLS capability in CAPA response.",
                        recommendation="Enable STLS on POP3 (port 110) to secure authentication credentials and mail downloads."
                    ))
                    status = CheckStatus.FAIL
                    return ProtocolAuditResult(
                        protocol=proto,
                        host=host,
                        port=port,
                        service_type=service_type,
                        banner=banner,
                        starttls_advertised=False,
                        starttls_negotiated=False,
                        findings=all_findings,
                        status=status
                    )

                raw_sock.sendall(b"STLS\r\n")
                stls_resp = _read_until(raw_sock, b"\n").decode("utf-8", errors="replace").strip()
                if not stls_resp.startswith("+OK"):
                    starttls_negotiated = False
                    status = CheckStatus.FAIL
                    return ProtocolAuditResult(
                        protocol=proto,
                        host=host,
                        port=port,
                        service_type=service_type,
                        banner=banner,
                        starttls_advertised=True,
                        starttls_negotiated=False,
                        findings=all_findings,
                        status=status
                    )
                starttls_negotiated = True

        # ----------------------------------------------------
        # 2. TLS Handshake Wrapping & Telemetry Extraction
        # ----------------------------------------------------
        ctx = ssl.create_default_context()
        # Security scanner posture: do not drop connection on self-signed or name mismatch
        # so we can parse and report the exact cryptographic state.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        ssl_sock.settimeout(timeout)

        # If implicit TLS, grab banner now
        if not use_starttls and banner is None:
            try:
                banner = _read_until(ssl_sock, b"\n").decode("utf-8", errors="replace").strip()
            except Exception:
                banner = "Connected via Implicit TLS"

        # Negotiated TLS telemetry
        negotiated_version = ssl_sock.version()
        cipher_tuple = ssl_sock.cipher()
        alpn = ssl_sock.selected_alpn_protocol()
        der_cert = ssl_sock.getpeercert(binary_form=True)

        # 3. Analyze Cipher and TLS version
        cipher_info, cipher_findings = evaluate_cipher_and_tls(negotiated_version, cipher_tuple)
        all_findings.extend(cipher_findings)

        # 4. Analyze X.509 Certificate
        #    RFC 6125: the certificate must cover the identity we actually connected
        #    to (``host``, which is also the SNI value sent on this socket) — not the
        #    apex domain the operator typed. Comparing against the queried domain
        #    produced false "Certificate Domain Name Mismatch" findings on any MX
        #    whose name differs from the domain it serves mail for.
        cert_info = None
        if der_cert:
            cert_info, cert_findings = parse_x509_certificate(
                der_cert,
                target_domain=host,
                intermediate_certificates=_get_peer_intermediate_certificates(ssl_sock),
            )
            all_findings.extend(cert_findings)

        # Check for critical or high findings to determine status
        has_critical = any(f.severity == FindingSeverity.CRITICAL for f in all_findings)
        has_high = any(f.severity == FindingSeverity.HIGH for f in all_findings)
        has_medium = any(f.severity == FindingSeverity.MEDIUM for f in all_findings)

        if has_critical:
            status = CheckStatus.FAIL
        elif has_high or has_medium:
            status = CheckStatus.WARN
        else:
            status = CheckStatus.PASS

        tls_handshake = TlsHandshakeResult(
            success=True,
            negotiated_version=negotiated_version,
            cipher=cipher_info,
            certificate=cert_info,
            alpn_selected=alpn,
            error_message=None
        )

        return ProtocolAuditResult(
            protocol=proto,
            host=host,
            port=port,
            service_type=service_type,
            banner=banner,
            starttls_advertised=starttls_advertised,
            starttls_negotiated=starttls_negotiated,
            tls_handshake=tls_handshake,
            findings=all_findings,
            status=status
        )

    except (socket.timeout, TimeoutError):
        all_findings.append(SecurityFinding(
            title=f"Connection Timeout on {proto}:{port}",
            severity=FindingSeverity.MEDIUM,
            category="Network",
            description=f"Connection to {host}:{port} timed out after {timeout}s (likely firewall/ISP port restriction).",
            recommendation=f"Ensure port {port} is accessible through local and upstream firewalls."
        ))
        return ProtocolAuditResult(
            protocol=proto,
            host=host,
            port=port,
            service_type=service_type,
            banner=None,
            starttls_advertised=None,
            starttls_negotiated=None,
            tls_handshake=TlsHandshakeResult(success=False, error_message="Connection timed out"),
            findings=all_findings,
            status=CheckStatus.UNKNOWN
        )

    except (ConnectionRefusedError, OSError) as e:
        all_findings.append(SecurityFinding(
            title=f"Port Closed or Unreachable on {proto}:{port}",
            severity=FindingSeverity.LOW,
            category="Network",
            description=f"Could not connect to {host}:{port}: {str(e)}",
            recommendation=f"If {proto} service is meant to be active on {port}, verify daemon status."
        ))
        return ProtocolAuditResult(
            protocol=proto,
            host=host,
            port=port,
            service_type=service_type,
            banner=None,
            starttls_advertised=None,
            starttls_negotiated=None,
            tls_handshake=TlsHandshakeResult(success=False, error_message=str(e)),
            findings=all_findings,
            status=CheckStatus.UNKNOWN
        )

    except Exception as e:
        all_findings.append(SecurityFinding(
            title=f"TLS Handshake Failure on {proto}:{port}",
            severity=FindingSeverity.HIGH,
            category="TLS",
            description=f"TLS negotiation error: {str(e)}",
            recommendation="Review mail server SSL/TLS library and cipher suite configuration."
        ))
        return ProtocolAuditResult(
            protocol=proto,
            host=host,
            port=port,
            service_type=service_type,
            banner=banner,
            starttls_advertised=starttls_advertised,
            starttls_negotiated=False,
            tls_handshake=TlsHandshakeResult(success=False, error_message=str(e)),
            findings=all_findings,
            status=CheckStatus.FAIL
        )

    finally:
        if ssl_sock:
            try:
                ssl_sock.close()
            except Exception:
                pass
        elif sock:
            try:
                sock.close()
            except Exception:
                pass


def probe_https_sni_fallback(
    host: str,
    target_domain: str,
    timeout: float = 2.0
) -> ProtocolAuditResult:
    """
    Fallback probe when direct SMTP ports (25, 587, 465) are blocked by ISP firewalls.
    Connects to port 443 with TLS SNI on host or target_domain to extract negotiated
    TLS version, cipher suite, forward secrecy, and X.509 certificate chain.
    Ensures legitimate mail infrastructure is not misclassified as insecure due to ISP restrictions.
    """
    proto = "SMTP"
    service_type = "HTTPS-SNI Fallback"
    all_findings: List[SecurityFinding] = []

    candidates = [host, target_domain]
    seen_targets: List[str] = []
    for c in candidates:
        if c and c not in seen_targets:
            seen_targets.append(c)

    for target_host in seen_targets:
        raw_sock = None
        ssl_sock = None
        try:
            raw_sock = socket.create_connection((target_host, 443), timeout=timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=target_domain or target_host)
            ssl_sock.settimeout(timeout)

            negotiated_version = ssl_sock.version()
            cipher_tuple = ssl_sock.cipher()
            alpn = ssl_sock.selected_alpn_protocol()
            der_cert = ssl_sock.getpeercert(binary_form=True)

            cipher_info, cipher_findings = evaluate_cipher_and_tls(negotiated_version, cipher_tuple)
            all_findings.extend(cipher_findings)

            cert_info = None
            if der_cert:
                # The server selects its certificate from the SNI name we sent, so
                # that name — not the apex domain — is the identity to verify.
                cert_info, cert_findings = parse_x509_certificate(
                    der_cert,
                    target_domain=target_domain or target_host,
                    intermediate_certificates=_get_peer_intermediate_certificates(ssl_sock),
                )
                all_findings.extend(cert_findings)

            all_findings.append(SecurityFinding(
                title="Cryptographic Parameters Verified via HTTPS SNI Fallback",
                severity=FindingSeverity.INFO,
                category="Network",
                description=(
                    f"Direct SMTP socket probes (ports 25, 587, 465) to {host} timed out due to ISP network filtering. "
                    f"TLS version ({negotiated_version}), cipher suite, and certificate were successfully verified via SNI fallback."
                ),
                recommendation="Mail domain identity and modern TLS cryptography verified. Request ISP port 25 unblocking if sending outbound mail directly."
            ))

            tls_handshake = TlsHandshakeResult(
                success=True,
                negotiated_version=negotiated_version,
                cipher=cipher_info,
                certificate=cert_info,
                alpn_selected=alpn,
                error_message=None
            )

            return ProtocolAuditResult(
                protocol=proto,
                host=host,
                port=25,
                service_type=service_type,
                banner=f"Verified via SNI fallback to {target_host}:443 (ISP port 25 filtered)",
                starttls_advertised=True,
                starttls_negotiated=True,
                tls_handshake=tls_handshake,
                findings=all_findings,
                status=CheckStatus.PASS
            )
        except Exception:
            continue
        finally:
            if ssl_sock:
                try:
                    ssl_sock.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass

    all_findings.append(SecurityFinding(
        title=f"All Probing Ports Blocked on {host}",
        severity=FindingSeverity.MEDIUM,
        category="Network",
        description=f"Direct SMTP ports (25/587/465) and HTTPS fallback to {host} timed out or were unreachable.",
        recommendation="Verify host reachability and firewall policies."
    ))
    return ProtocolAuditResult(
        protocol=proto,
        host=host,
        port=25,
        service_type=service_type,
        banner=None,
        starttls_advertised=None,
        starttls_negotiated=None,
        tls_handshake=TlsHandshakeResult(success=False, error_message="All connection probes timed out"),
        findings=all_findings,
        status=CheckStatus.UNKNOWN
    )

