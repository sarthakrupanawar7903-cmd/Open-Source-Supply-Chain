# Open-Source-Supply-Chain
> Manipal Hackathon 2026  
> Problem Statement: **Open Source Supply Chains: The Ripple Effect**  
> Domain: Cybersecurity 

Contributors :- 
Sarthak, Zain,Pari,Avani,Mahi

---

##  Problem Statement

Modern software depends on deeply nested open-source packages. A compromise in a low-level dependency can propagate through many downstream applications. Traditional security tools often evaluate packages individually, making it difficult to understand structural importance or how compromise could spread.

Security teams need visibility into:

- Which components sit at critical points in the dependency chain
- Which applications are affected downstream
- How risk propagates through the ecosystem
- Where mitigation will reduce the most downstream exposure



## Our Solution

We are building an intelligent risk-analysis system that maps relationships within a software dependency ecosystem and explores the downstream consequences of compromise.

The system identifies critical dependencies, affected applications, propagation paths, and mitigation priorities while making its reasoning visible. It distinguishes broadly exposed components from isolated ones and helps security teams focus mitigation where one intervention can reduce downstream risk.



##  Key Features

- Dependency graph builder from package manifests, lockfiles, and SBOMs
- Critical dependency detection using graph centrality a         blast-radius analysis
- Compromise propagation simulation
- Affected application and dependency path explorer
- Explainable risk alerts — not just a vulnerability score
- Mitigation priority dashboard
- Visual dependency graph
- Exportable reports: JSON / CSV / SARIF / PDF
- Support for common ecosystems: npm, PyPI, Maven, Go modules, etc.

---

##  Architecture

```text
Package manifests / SBOM / lockfiles
              ↓
      Ingestion & parsers
              ↓
     Dependency graph builder
              ↓
  Risk scoring + propagation engine
              ↓
     API / alerts / dashboard
