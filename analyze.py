"""Reproduce the Round 1 packet sensitivity model and ranking checks."""
import argparse
import csv
import math
import random
import statistics
from itertools import product
from pathlib import Path

SEED = 22573
ASSETS = {
    "Backup replication": (5, 2, 3, 2, 4),
    "Public API": (2, 5, 3, 5, 4),
    "Service mesh": (4, 2, 3, 2, 5),
    "Managed bastion": (2, 3, 5, 2, 5),
    "Release signing": (1, 2, 5, 5, 2),
}
WEIGHTS = {"Confidentiality-led": (40, 25, 25, 10),
           "Privilege-led": (20, 25, 45, 10),
           "Equal weight": (25, 25, 25, 25)}
WEIGHTS.update({f"Drop {key}": tuple(0 if i==j else point for j,point in enumerate(WEIGHTS["Confidentiality-led"]))
                for i,key in enumerate("CEPI")})

def write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

def ranking(out):
    rows = []
    for label, weights in WEIGHTS.items():
        scores = {asset: sum(r*w for r,w in zip(ratings,weights)) for asset,ratings in ASSETS.items()}
        for asset in sorted(scores, key=lambda a: (-scores[a], a)):
            rows.append(dict(policy=label, asset=asset, score=round(scores[asset]/sum(weights),6),
                             rank=1+sum(v>scores[asset] for v in scores.values()),
                             readiness=ASSETS[asset][-1]))
    write_csv(out/"rankings.csv", rows)

def chunks(total, capacity):
    whole, last = divmod(total, capacity)
    return [capacity]*whole + ([last] if last else [])

def packetize(protocol, mtu, hello, server, finish):
    if protocol == "TCP-TLS":
        capacity = mtu-72  # IPv6 (40 B) and TCP including modeled options (32 B)
        add = lambda n: [v+72 for v in chunks(n, capacity)]
        return [add(hello+5),add(server+32),add(finish+22)], None, None
    # 48 B IPv6/UDP + 64 B fixed QUIC framing/protection budget per datagram.
    capacity = mtu-112
    c = [max(1200, v+64) for v in chunks(hello, capacity)]
    s = [max(1200, v+64) if i==0 else v+64 for i,v in enumerate(chunks(server, capacity))]
    f = [v+64 for v in chunks(finish, capacity)]
    return [[v+48 for v in flight] for flight in (c,s,f)], 3*sum(c), sum(s)

def trial(rng, flights, rtt, loss, mbps, protocol, mtu):
    # Flight-based selective repeat with a one-RTT repair interval for either
    # transport. Simulation time ends when the client Finished reaches server.
    elapsed = rtt if protocol=="TCP-TLS" else 0.0
    retried = 0
    for flight in flights:
        elapsed += rtt/2
        pending = flight
        while pending:
            elapsed += sum(pending)*0.008/mbps
            pending = [length for length in pending if rng.random()<loss]
            if pending:
                elapsed += rtt
                retried += len(pending)
    # Fixed useful transfer to compare effective rates. Payload is sent only
    # after the model receives the client Finished. Use the same loss model.
    handshake = elapsed
    capacity, overhead = (mtu-72,72) if protocol=="TCP-TLS" else (mtu-112,112)
    payload = [v+overhead for v in chunks(16384,capacity)]
    elapsed += rtt/2
    while payload:
        elapsed += sum(payload)*0.008/mbps
        payload = [length for length in payload if rng.random()<loss]
        if payload:
            elapsed += rtt
    return handshake, retried, 16384*0.008/elapsed

def load_flights(path):
    data = {}
    for row in csv.DictReader(path.open(encoding="utf-8")):
        data.setdefault(row["group"], []).append(row)
    def med(rows,key):
        return round(statistics.median(int(row[key]) for row in rows))
    return {group:(med(rows,"ClientHello"), sum(med(rows,key) for key in (
                    "ServerHello","EncryptedExtensions","Certificate","CertificateVerify","FinishedServer")),
                   med(rows,"FinishedClient"))
            for group,rows in data.items()}

def network(tls_runs, out, trials):
    samples, summary = [], []
    rng = random.Random(SEED)
    for (protocol, (group, (hello, server, finish)), mtu, rtt, loss, mbps) in product(
            ("TCP-TLS","QUIC-like"), load_flights(tls_runs).items(), (1280,1420,1500),
            (10,40,100), (0,.01,.03), (10,100)):
        flights, budget, server_udp = packetize(protocol,mtu,hello,server,finish)
        dimensions = dict(protocol=protocol, group=group, mtu=mtu, rtt_ms=rtt, loss=loss, mbps=mbps)
        assert budget is None or server_udp <= budget, (dimensions,budget,server_udp)
        results = [trial(rng,flights,rtt,loss,mbps,protocol,mtu) for _ in range(trials)]
        for i,(latency,retries,goodput) in enumerate(results,1):
            samples.append(dict(**dimensions, trial=i, handshake_ms=round(latency,6),
                                retries=retries, transfer_Mbps=round(goodput,6)))
        latency,retries,rates = zip(*results)
        summary.append(dict(**dimensions, n=trials, client_packets=len(flights[0]),
                            server_packets=len(flights[1]), server_udp_bytes=server_udp,
                            amp_budget=budget, mean_ms=round(statistics.mean(latency),6),
                            variance_ms2=round(statistics.variance(latency),6),
                            p95_ms=round(sorted(latency)[math.ceil(.95*trials)-1],6),
                            retry_pct=round(100*sum(bool(v) for v in retries)/trials,3),
                            mean_transfer_Mbps=round(statistics.mean(rates),6)))
    write_csv(out/"network_grid.csv",summary)
    write_csv(out/"network_trials.csv",samples)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--tls-runs", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=500)
    args = parser.parse_args()
    assert args.trials>=2
    args.out.mkdir(parents=True,exist_ok=True)
    ranking(args.out)
    network(args.tls_runs,args.out,args.trials)

if __name__ == "__main__":
    main()

