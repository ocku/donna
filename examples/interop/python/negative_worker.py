"""Independent negative-cache discovery and untimed capture verification."""

import argparse
import json
from pathlib import Path
import time
import socket

import dns.dnssec
import dns.flags
import dns.message
import dns.rdatatype

from negative_fixture import cases, guards, inputs, SEEDS, frame, request
from negative_evidence import NegativeVerifier
from negative_refresh import NegativeRefreshes
from recursive_capture import compact, read_compact
from recursive_evidence import authenticated_keys
from negative_security import verify as verify_security
from negative_proof_bank import freeze, clock_domain


def fetch(address, case, cd=False):
    query = request(case, cd)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(12)
        peer.connect(address)
        assert peer.send(query) == len(query)
        wire = peer.recv(65535)
        mono, wall = time.monotonic_ns(), time.time()
    capture = dict(
        case=case,
        cd=cd,
        query=query.hex(),
        response=wire.hex(),
        received_monotonic_ns=mono,
        checked_at=wall,
    )
    try:
        message = dns.message.from_wire(wire)
    except Exception as error:
        capture["decode_error"] = repr(error)
        message = None
    return capture, message


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("stream", "inputs", "preload", "freeze", "verify", "makebad")
    )
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument(
        "--scenario",
        choices=("descendant", "sibling", "guards", "expiry", "security"),
        default="descendant",
    )
    parser.add_argument("--security", choices=("bad-ds", "bad-signature"))
    parser.add_argument("--cd-first", action="store_true")
    parser.add_argument(
        "--kind", choices=("exact", "descendant", "sibling"), default="exact"
    )
    parser.add_argument("--path", default="/suite/state.json")
    args = parser.parse_args()
    public = json.loads(Path("/work/public.json").read_text())
    address = args.host, args.port
    if args.action == "inputs":
        for kind in ("exact", "descendant", "sibling"):
            Path("/suite/" + kind + ".queries").write_bytes(frame(inputs(kind)))
        print(
            json.dumps(
                dict(
                    populations={
                        kind: len(inputs(kind))
                        for kind in ("exact", "descendant", "sibling")
                    }
                )
            )
        )
    elif args.action == "stream":
        if args.scenario == "security":
            assert args.security is not None
            plan = [dict(SEEDS["sibling"]), dict(SEEDS["sibling"])]
        elif args.scenario == "guards":
            plan = guards()
            plan.insert(1, dict(plan[0]))
        else:
            seed = SEEDS["descendant" if args.scenario == "expiry" else args.scenario]
            plan = [
                dict(seed),
                dict(seed),
                cases("descendant" if args.scenario == "expiry" else args.scenario)[0],
            ]
        verifier, witnesses = NegativeVerifier(public, time.time()), []
        deadline = None
        seed_reply = None
        for index, case in enumerate(plan):
            if index == 2 and args.scenario == "expiry":
                time.sleep(max(0, (deadline - time.monotonic_ns()) / 1e9) + 1.25)
                verifier = NegativeVerifier(public, time.time())
            if (
                index == 2
                and args.scenario == "sibling"
                and public["denial"] == "nsec3"
                and seed_reply is not None
            ):
                for candidate in cases("sibling"):
                    try:
                        verifier.oracle.verify(candidate, seed_reply)
                    except AssertionError:
                        continue
                    case = candidate
                    plan[index] = case
                    break
                else:
                    raise AssertionError(
                        "no bounded candidate covered by seed NSEC3 proof"
                    )
            cd = args.scenario == "security" and index == (0 if args.cd_first else 1)
            capture, reply = fetch(address, case, cd)
            if index == 0:
                seed_reply = reply
            print(
                json.dumps(
                    dict(
                        step=index,
                        case=case,
                        capture=capture,
                        deadline_ns=deadline,
                        expiry_wait_grace_seconds=1.25
                        if args.scenario == "expiry"
                        else None,
                        security=args.security,
                        cd_first=args.cd_first,
                    )
                ),
                flush=True,
            )
            acknowledgement = json.loads(input())
            witnesses.extend(acknowledgement["events"])
            verifier.refreshes = NegativeRefreshes(verifier.oracle, witnesses, plan)
            try:
                if args.scenario == "security":
                    info = verify_security(public, case, capture, args.security)
                else:
                    info = verifier.verify(
                        case, capture, ad=case["kind"] != "insecure-positive"
                    )
                passed, error = True, None
            except Exception as failure:
                passed, error, info = False, repr(failure), None
            if index == 0 and args.scenario == "expiry":
                ttl = min(rr.ttl for rr in reply.authority) if reply is not None else 5
                deadline = capture["received_monotonic_ns"] + ttl * 1_000_000_000
            print(
                json.dumps(
                    dict(
                        checked=True,
                        passed=passed,
                        error=error,
                        verification=info,
                        deadline_ns=deadline,
                    )
                ),
                flush=True,
            )
    elif args.action == "preload":
        plan = cases(args.kind) if args.kind == "exact" else [SEEDS[args.kind]]
        verifier, captures = NegativeVerifier(public, time.time()), []
        for case in plan:
            capture, reply = fetch(address, case)
            # These are first observations of distinct requested questions,
            # not a single cache entry whose lifetime can be merged by min().
            verifier.deadlines.clear()
            verifier.verify(case, capture)
            captures.append(capture)
        if args.kind != "exact":
            for case in cases(args.kind):
                verifier.oracle.verify(case, reply)
        state = dict(
            captures=captures,
            kind=args.kind,
            observation_checks={
                key: value
                for key, value in verifier.summary().items()
                if key != "deadlines"
            },
        )
        Path(args.path).write_text(json.dumps(state))
        print(
            json.dumps(
                dict(flags=reply.flags, state=args.path, preloaded=len(captures))
            ),
            flush=True,
        )
    elif args.action == "freeze":
        path = Path(args.path)
        state = json.loads(path.read_text())
        witnesses = json.loads(Path(str(path) + ".events.json").read_text())
        state["acquisition_events"] = witnesses
        state["verification"] = freeze(public, state["captures"], witnesses)
        state["clock_domain"] = clock_domain(state["captures"])
        state["deadline_model"] = (
            "signature/data-bound proof availability; frozen before native traffic; acquisition-only renewal"
        )
        path.write_text(json.dumps(state))
        print(
            json.dumps(
                dict(
                    proof_bounds=len(state["verification"]["deadlines"]),
                    responses=len(state["captures"]),
                )
            ),
            flush=True,
        )
    elif args.action == "verify":
        path = Path(args.path)
        native = json.loads(Path(str(path) + ".json").read_text())
        packing = compact(path, str(path) + ".rcc", inputs(args.kind), native)
        state = Path(str(path) + ".preload.json")
        deadlines = (
            json.loads(state.read_text())["verification"]["deadlines"]
            if state.exists()
            else None
        )
        domain = (
            clock_domain(json.loads(state.read_text())["captures"], native)
            if state.exists()
            else None
        )
        verifier = NegativeVerifier(
            public,
            native["started_unix_seconds"],
            deadlines=deadlines,
            frozen=True,
            require_seed=state.exists(),
        )
        witnesses = json.loads(Path(str(path) + ".refresh.json").read_text())
        plan = cases(args.kind)
        verifier.refreshes = NegativeRefreshes(verifier.oracle, witnesses, plan)
        for capture in read_compact(str(path) + ".rcc", inputs(args.kind), native):
            verifier.verify(plan[capture["index"]], capture)
        authenticated_keys(public, native["ended_unix_seconds"])
        record = dict(
            compaction=packing,
            verification={
                key: value
                for key, value in verifier.summary().items()
                if key != "deadlines"
            },
            clock_domain=domain,
        )
        Path(str(path) + ".verified.json").write_text(json.dumps(record))
        path.unlink()
        print(json.dumps(record), flush=True)
    elif args.action == "makebad":
        verifier = NegativeVerifier(public, time.time())
        proof_type = (
            dns.rdatatype.NSEC if public["denial"] == "nsec" else dns.rdatatype.NSEC3
        )
        for owner, dataset in verifier.leaf.iterate_rdatasets(proof_type):
            candidate = dns.rrset.from_rdata_list(owner, dataset.ttl, list(dataset))
            if verifier.oracle.relevant(SEEDS["sibling"], candidate):
                break
        signatures = verifier.leaf.get_rdataset(
            owner, dns.rdatatype.RRSIG, covers=proof_type
        )
        original = signatures[0]
        changed = bytes([original.signature[0] ^ 1]) + original.signature[1:]
        signatures.clear()
        signatures.add(original.replace(signature=changed))
        candidate = dns.rrset.from_rdata_list(
            owner,
            verifier.leaf.get_rdataset(owner, proof_type).ttl,
            list(verifier.leaf.get_rdataset(owner, proof_type)),
        )
        try:
            dns.dnssec.validate_rrsig(
                candidate, signatures[0], verifier.keys, now=time.time()
            )
        except dns.dnssec.ValidationFailure:
            pass
        else:
            raise AssertionError("signature corruption did not fail mathematics")
        Path(args.path).write_text(verifier.leaf.to_text(relativize=False))
        print(
            json.dumps(dict(owner=owner.to_text(), covers=int(proof_type))), flush=True
        )


if __name__ == "__main__":
    main()
