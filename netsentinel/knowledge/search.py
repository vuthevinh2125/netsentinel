"""Offline BM25 search over the knowledge base, with citations.

BM25 rather than embeddings: it runs anywhere without downloading a model, it is fast on 1,600
documents, and every hit can be explained by the words it matched, which matters when an
analyst has to trust (or doubt) what the AI read.
"""
from __future__ import annotations

import gzip
import json
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

KB_PATH = Path(__file__).with_name("kb.jsonl.gz")
TOKEN = re.compile(r"[a-z0-9]+(?:\.[0-9]+)?")
STOP = set("""a an and are as at be by can for from has have in into is it its may of on or that the their this to
use used using was were which will with within also such other these those than then they them via""".split())


# Words a network alert uses -> the words ATT&CK uses for the same idea. Standard SOC vocabulary,
# applied to every query alike; it only adds terms, it never removes the analyst's own words.
THESAURUS = {
    "beacon": "command control c2 application layer protocol web protocols",
    "beaconing": "command control c2 application layer protocol web protocols",
    "call": "command control", "home": "command control",
    "heartbeat": "command control", "jitter": "command control periodic",
    "upload": "exfiltration transfer data", "uploaded": "exfiltration transfer data",
    "exfil": "exfiltration", "scan": "network service discovery", "probes": "network service discovery",
    "unanswered": "discovery scanning", "tunnelling": "tunneling dns application layer protocol",
    "tunneling": "dns application layer protocol", "lateral": "remote services", "smb": "smb windows admin shares",
    "brute": "brute force password guessing", "logins": "valid accounts authentication",
    "p2p": "peer", "bittorrent": "peer file sharing",
}


def expand(text: str) -> str:
    words = TOKEN.findall(text.lower())
    extra = [THESAURUS[w] for w in dict.fromkeys(words) if w in THESAURUS]
    return text + (" " + " ".join(extra) if extra else "")


def tokens(text: str) -> list[str]:
    return [t for t in TOKEN.findall(text.lower()) if t not in STOP and len(t) > 1]


class KnowledgeBase:
    def __init__(self, docs: list[dict], k1: float = 1.4, b: float = 0.75):
        self.docs = docs
        self.k1, self.b = k1, b
        # title words count three times: a match in the name is stronger evidence
        self.tf = [Counter(tokens(d["title"]) * 3 + tokens(d["text"])) for d in docs]
        self.len = [sum(c.values()) for c in self.tf]
        self.avg = sum(self.len) / max(1, len(self.len))
        df = Counter()
        for c in self.tf:
            df.update(c.keys())
        n = len(docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}
        self.by_id = {d["id"]: d for d in docs}

    @classmethod
    def load(cls, path: str | Path = KB_PATH) -> "KnowledgeBase":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return cls([json.loads(l) for l in fh if l.strip()])

    def search(self, query: str, k: int = 5, kinds: tuple[str, ...] | None = None,
               use_thesaurus: bool = True) -> list[tuple[float, dict]]:
        q = Counter(tokens(expand(query) if use_thesaurus else query))
        scores = []
        for i, tf in enumerate(self.tf):
            if kinds and self.docs[i]["kind"] not in kinds:
                continue
            s = 0.0
            norm = self.k1 * (1 - self.b + self.b * self.len[i] / self.avg)
            for t, qn in q.items():
                f = tf.get(t)
                if f:
                    s += self.idf[t] * f * (self.k1 + 1) / (f + norm)
            if s > 0:
                scores.append((s, i))
        scores.sort(reverse=True)
        return [(round(s, 2), self.docs[i]) for s, i in scores[:k]]


def snippet(doc: dict, query: str, width: int = 700) -> str:
    """The most relevant stretch of a document: the sentences that share the most query words."""
    q = set(tokens(query))
    sents = re.split(r"(?<=[.!?])\s+|\n", doc["text"])
    head = sents[0]
    ranked = sorted(sents[1:], key=lambda s: -len(q & set(tokens(s))))
    out = head
    for s in ranked:
        if len(out) + len(s) + 1 > width:
            break
        if q & set(tokens(s)):
            out += " … " + s
    return out[:width]


@lru_cache(maxsize=1)
def default_kb() -> KnowledgeBase:
    return KnowledgeBase.load()
