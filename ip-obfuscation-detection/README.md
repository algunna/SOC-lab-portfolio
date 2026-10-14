# IP Obfuscation Detection Lab

## Purpose

This lab is a first step towards spotting attempts to hide where activity comes from (VPNs, proxies, anonymization services). Today it does one thing: it flags events in a CloudTrail timeline whose source is an **external (public) IP address**, so an analyst can review them in context. It is an educational lab, not a production detection system.

## Detection

Every timeline line whose `SourceIP` is a public IPv4 or IPv6 address produces a `[MEDIUM] Suspicious public IP source` alert. Private, loopback, link-local and other reserved addresses, and non-IP sources such as `AWS Internal` or AWS service hostnames, are ignored.

A public source IP on its own is not evidence of obfuscation or of anything malicious: most legitimate console and API use comes from public addresses.

## Not implemented

The detections this lab is meant to grow into are not built yet: rapid IP changes for one user or session, inconsistent geolocation, and known VPN, proxy or Tor ranges. Each needs either more events per identity or external enrichment data.

## Run

From the repository root:

```bash
python ip-obfuscation-detection/scripts/detect_ip_obfuscation.py
python -m unittest discover -s ip-obfuscation-detection/tests -v
```

The input is `sample-logs/cloudtrail_timeline.txt` (the timeline format produced by the [CloudTrail SOC Pipeline](../cloudtrail-soc-pipeline)) and alerts are written to [output/ip_obfuscation_alerts.txt](output/ip_obfuscation_alerts.txt). Use `--input` and `--output` for other files. CI runs the tests in [legacy-lab-tests.yml](../.github/workflows/legacy-lab-tests.yml).

## Analyst workflow

1. Review what each flagged event did and which identity performed it; root activity from an external address deserves the closest look.
2. Compare the source with the addresses that identity normally uses.
3. Correlate with authentication success or failure, and escalate when the behavior departs from normal use.
