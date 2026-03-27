"""
pin0ccsAI — Web3 Module
Smart contract interaction analysis, signature replay detection,
improper access control in contracts, and wallet auth flaws.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Optional

import httpx

from core.config import Config
from core.logger import get_logger
from core.models import Finding, Severity, VulnType

log = get_logger(__name__)

# Common ERC-20/ERC-721 function signatures
_COMMON_SIGS = {
    "0x06fdde03": "name()",
    "0x095ea7b3": "approve(address,uint256)",
    "0x18160ddd": "totalSupply()",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x313ce567": "decimals()",
    "0x70a08231": "balanceOf(address)",
    "0x8da5cb5b": "owner()",
    "0xa9059cbb": "transfer(address,uint256)",
    "0xdd62ed3e": "allowance(address,address)",
    "0xf2fde38b": "transferOwnership(address)",
    "0x715018a6": "renounceOwnership()",
}

# ABI patterns indicating dangerous functions
_DANGEROUS_PATTERNS = [
    r'\bselfdestruct\b',
    r'\bsuicide\b',
    r'\bdelegatecall\b',
    r'\bcall\.value\b',
    r'tx\.origin',
    r'\bassembly\b',
    r'ecrecover',
    r'block\.timestamp',
    r'block\.number.*==',
    r'block\.difficulty',
]


class Web3Module:
    def __init__(self, config: Config):
        self.cfg = config.web3
        self._rpc_timeout = config.web3.rpc_timeout

    async def analyze_contract(
        self, contract_address: str, rpc_url: str, abi: Optional[list] = None
    ) -> list[Finding]:
        """Full contract security analysis."""
        findings: list[Finding] = []

        log.info("web3.analyze_start", contract=contract_address)

        # 1. Fetch contract bytecode
        bytecode = await self._get_bytecode(contract_address, rpc_url)
        if not bytecode or bytecode == "0x":
            log.warning("web3.no_bytecode", contract=contract_address)
            return findings

        # 2. Function selector mapping
        selectors = self._extract_selectors(bytecode)

        # 3. Dangerous pattern detection
        dangerous_findings = self._detect_dangerous_patterns(
            bytecode, contract_address
        )
        findings.extend(dangerous_findings)

        # 4. Signature replay check
        if self.cfg.check_signature_replay:
            replay_findings = await self._check_signature_replay(
                contract_address, rpc_url, selectors
            )
            findings.extend(replay_findings)

        # 5. Access control check
        if self.cfg.check_access_control:
            ac_findings = await self._check_access_control(
                contract_address, rpc_url, selectors
            )
            findings.extend(ac_findings)

        # 6. Reentrancy indicators
        if self.cfg.check_reentrancy:
            reentrancy_findings = self._check_reentrancy_patterns(
                bytecode, contract_address
            )
            findings.extend(reentrancy_findings)

        # 7. ABI analysis if provided
        if abi:
            abi_findings = self._analyze_abi(abi, contract_address)
            findings.extend(abi_findings)

        log.info("web3.analyze_complete",
                 contract=contract_address, findings=len(findings))
        return findings

    async def check_wallet_auth(self, target_url: str) -> list[Finding]:
        """Check web3 wallet authentication flows for flaws."""
        findings: list[Finding] = []

        async with httpx.AsyncClient(timeout=15, verify=False,
                                      follow_redirects=True) as client:
            # Check for auth endpoints that use wallet signatures
            auth_paths = ["/api/auth/wallet", "/auth/nonce", "/api/nonce",
                          "/login/web3", "/api/login", "/connect/wallet"]
            for path in auth_paths:
                url = target_url.rstrip("/") + path
                try:
                    resp = await client.get(url)
                    if resp.status_code not in (404, 410):
                        body = resp.text.lower()

                        # Check for predictable nonces
                        if "nonce" in body:
                            nonce_finding = await self._test_nonce_predictability(
                                url, client
                            )
                            if nonce_finding:
                                findings.append(nonce_finding)

                        # Check for missing nonce (signature replay)
                        if resp.status_code == 200 and "nonce" not in body:
                            findings.append(Finding(
                                title="Missing nonce in wallet auth — signature replay possible",
                                vuln_type=VulnType.SIGNATURE_REPLAY,
                                severity=Severity.HIGH,
                                url=url,
                                endpoint=url,
                                evidence=resp.text[:300],
                                steps_to_reproduce=[
                                    f"1. GET {url}",
                                    "2. No nonce returned — auth may accept replayed signatures",
                                    "3. Capture a valid auth signature and replay it",
                                ],
                                impact="Attacker can impersonate users by replaying captured auth signatures",
                                tool="web3_module",
                                confidence=0.5,
                            ))
                except Exception:
                    pass

        return findings

    # ─── RPC Helpers ──────────────────────────────────────────────────────────

    async def _rpc_call(self, rpc_url: str, method: str, params: list) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }
        async with httpx.AsyncClient(timeout=self._rpc_timeout) as client:
            resp = await client.post(rpc_url, json=payload)
            data = resp.json()
            if "error" in data:
                raise ValueError(f"RPC error: {data['error']}")
            return data.get("result")

    async def _get_bytecode(self, address: str, rpc_url: str) -> Optional[str]:
        try:
            return await self._rpc_call(rpc_url, "eth_getCode", [address, "latest"])
        except Exception as e:
            log.debug("web3.bytecode_failed", error=str(e))
            return None

    # ─── Analysis Methods ─────────────────────────────────────────────────────

    def _extract_selectors(self, bytecode: str) -> list[str]:
        """Extract 4-byte function selectors from bytecode."""
        # Look for PUSH4 opcode (0x63) followed by 4 bytes
        selectors = set()
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]
        for i in range(0, len(bytecode) - 10, 2):
            opcode = bytecode[i:i+2]
            if opcode == "63":  # PUSH4
                selector = "0x" + bytecode[i+2:i+10]
                selectors.add(selector)
        return list(selectors)

    def _detect_dangerous_patterns(
        self, bytecode: str, contract_address: str
    ) -> list[Finding]:
        findings = []

        # Check for selfdestruct (opcode 0xff)
        if "ff" in bytecode.lower():
            # More precise: check for the actual selfdestruct opcode in context
            findings.append(Finding(
                title="Contract contains selfdestruct opcode",
                vuln_type=VulnType.CONTRACT_ACCESS,
                severity=Severity.HIGH,
                url=contract_address,
                endpoint=contract_address,
                evidence="Bytecode contains 0xff (selfdestruct)",
                steps_to_reproduce=[
                    f"1. Inspect contract at {contract_address}",
                    "2. Find the selfdestruct call path",
                    "3. Check if access control protects it",
                ],
                impact="Privileged attacker or owner can destroy contract and drain funds",
                tool="web3_module",
                confidence=0.6,
            ))

        # Check for delegatecall (opcode 0xf4)
        if "f4" in bytecode.lower():
            findings.append(Finding(
                title="Contract uses delegatecall — storage collision risk",
                vuln_type=VulnType.CONTRACT_ACCESS,
                severity=Severity.MEDIUM,
                url=contract_address,
                endpoint=contract_address,
                evidence="Bytecode contains 0xf4 (delegatecall)",
                steps_to_reproduce=[
                    "1. Identify delegatecall target",
                    "2. Check if target address is user-controlled",
                    "3. Test for storage collision in proxy pattern",
                ],
                impact="Delegatecall to attacker-controlled address enables arbitrary code execution",
                tool="web3_module",
                confidence=0.5,
            ))

        return findings

    async def _check_signature_replay(
        self, contract_address: str, rpc_url: str, selectors: list[str]
    ) -> list[Finding]:
        findings = []

        # Functions that commonly accept signatures: execute, permit, transferWithSig, etc.
        sig_func_sigs = {
            "0xd505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            "0x8fcbaf0c": "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
        }

        matched = [s for s in selectors if s in sig_func_sigs]
        if matched:
            for selector in matched:
                func_name = sig_func_sigs[selector]
                # Check if nonce is part of the signature (EIP-712 standard)
                # This is a heuristic — real check requires ABI + call
                findings.append(Finding(
                    title=f"Signature function detected: {func_name} — verify replay protection",
                    vuln_type=VulnType.SIGNATURE_REPLAY,
                    severity=Severity.HIGH,
                    url=contract_address,
                    endpoint=contract_address,
                    evidence=f"Function selector {selector} found in bytecode",
                    steps_to_reproduce=[
                        f"1. Contract at {contract_address} implements {func_name}",
                        "2. Verify nonce tracking in signature validation",
                        "3. Test: submit same signed permit twice",
                        "4. If second call succeeds, signature replay is confirmed",
                    ],
                    impact="Attacker can replay valid signatures to perform unauthorized actions",
                    tool="web3_module",
                    confidence=0.55,
                ))

        return findings

    async def _check_access_control(
        self, contract_address: str, rpc_url: str, selectors: list[str]
    ) -> list[Finding]:
        findings = []

        # Check if owner() returns zero address or is unset
        owner_sig = "0x8da5cb5b"
        if owner_sig in selectors:
            try:
                result = await self._rpc_call(rpc_url, "eth_call", [
                    {
                        "to": contract_address,
                        "data": owner_sig,
                    },
                    "latest",
                ])
                if result and result != "0x" + "0" * 64:
                    owner = "0x" + result[-40:]
                    zero_address = "0x" + "0" * 40
                    if owner.lower() == zero_address:
                        findings.append(Finding(
                            title="Contract owner is zero address — ownable functions may be unprotected",
                            vuln_type=VulnType.CONTRACT_ACCESS,
                            severity=Severity.CRITICAL,
                            url=contract_address,
                            endpoint=contract_address,
                            evidence=f"owner() returned: {owner}",
                            steps_to_reproduce=[
                                f"1. Call owner() on {contract_address}",
                                "2. Returns zero address (0x0000...)",
                                "3. Attempt to call privileged functions",
                            ],
                            impact="Anyone can call owner-protected functions — full contract takeover possible",
                            tool="web3_module",
                            confidence=0.9,
                        ))
            except Exception as e:
                log.debug("web3.owner_check_failed", error=str(e))

        return findings

    def _check_reentrancy_patterns(
        self, bytecode: str, contract_address: str
    ) -> list[Finding]:
        findings = []
        # Check for CALL opcode (0xf1) before SSTORE (0x55) — classic reentrancy
        # This is a simplified bytecode-level heuristic
        hex_bc = bytecode.lower().replace("0x", "")
        call_pos = [i for i in range(0, len(hex_bc)-1, 2) if hex_bc[i:i+2] == "f1"]
        sstore_pos = [i for i in range(0, len(hex_bc)-1, 2) if hex_bc[i:i+2] == "55"]

        # If there's a CALL before any SSTORE, reentrancy may be possible
        if call_pos and sstore_pos:
            if min(call_pos) < max(sstore_pos):
                findings.append(Finding(
                    title="Potential reentrancy — CALL before SSTORE pattern detected",
                    vuln_type=VulnType.REENTRANCY,
                    severity=Severity.CRITICAL,
                    url=contract_address,
                    endpoint=contract_address,
                    evidence="Bytecode pattern: external CALL opcode appears before SSTORE in execution path",
                    steps_to_reproduce=[
                        f"1. Decompile contract at {contract_address}",
                        "2. Find functions that make external calls before updating state",
                        "3. Deploy attacker contract with fallback that re-enters target",
                        "4. Call vulnerable function",
                    ],
                    impact="Attacker can drain contract funds via reentrant calls before balance is updated",
                    tool="web3_module",
                    confidence=0.55,
                ))

        return findings

    def _analyze_abi(self, abi: list, contract_address: str) -> list[Finding]:
        findings = []

        for item in abi:
            if item.get("type") != "function":
                continue

            name = item.get("name", "")
            state_mutability = item.get("stateMutability", "")
            inputs = item.get("inputs", [])

            # Unprotected state-changing functions (no 'onlyOwner' modifier visible in ABI)
            if state_mutability in ("payable", "nonpayable"):
                # Functions that sound privileged but aren't view/pure
                privileged_keywords = [
                    "withdraw", "drain", "migrate", "upgrade", "set",
                    "update", "admin", "owner", "pause", "unpause", "mint"
                ]
                if any(kw in name.lower() for kw in privileged_keywords):
                    # ABI doesn't show modifiers — flag for manual review
                    findings.append(Finding(
                        title=f"Privileged function {name}() — verify access control",
                        vuln_type=VulnType.CONTRACT_ACCESS,
                        severity=Severity.MEDIUM,
                        url=contract_address,
                        endpoint=contract_address,
                        evidence=f"ABI: {json.dumps(item)}",
                        steps_to_reproduce=[
                            f"1. Call {name}() on {contract_address} without authorization",
                            "2. If call succeeds, access control is missing",
                        ],
                        impact="Unprotected privileged function may allow unauthorized state changes",
                        tool="web3_module",
                        confidence=0.45,
                    ))

        return findings

    async def _test_nonce_predictability(
        self, url: str, client: httpx.AsyncClient
    ) -> Optional[Finding]:
        """Test if nonces are sequential/predictable."""
        try:
            nonces = []
            for _ in range(3):
                resp = await client.get(url)
                body = resp.json() if "json" in resp.headers.get("content-type", "") else {}
                nonce = body.get("nonce", body.get("challenge", ""))
                if nonce:
                    nonces.append(str(nonce))
                await asyncio.sleep(0.5)

            if len(nonces) == 3:
                # Check if all numeric and sequential
                try:
                    nums = [int(n) for n in nonces]
                    if nums[1] - nums[0] == 1 and nums[2] - nums[1] == 1:
                        return Finding(
                            title="Predictable nonce in wallet auth",
                            vuln_type=VulnType.WALLET_AUTH,
                            severity=Severity.HIGH,
                            url=url,
                            endpoint=url,
                            evidence=f"Sequential nonces observed: {nonces}",
                            steps_to_reproduce=[
                                f"1. Request nonce 3 times from {url}",
                                "2. Nonces are sequential integers",
                                "3. Predict future nonce and pre-sign authentication",
                            ],
                            impact="Attacker can predict future nonces and forge authentication",
                            tool="web3_module",
                            confidence=0.85,
                        )
                except ValueError:
                    pass
        except Exception:
            pass
        return None
