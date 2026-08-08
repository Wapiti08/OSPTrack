# Artifact recovery audit

This directory is an isolated, read-only discovery workflow for malicious
package coordinates whose original registry artifacts may no longer exist. It
does not import OSPTrack's simulation code, modify existing datasets, execute
packages, or download package archives.

The audit combines:

1. exact archives already preserved in the Backstabbers Knife Collection;
2. archives found below explicitly supplied cache/mirror directories;
3. repository and evidence URLs from local OpenSSF OSV reports;
4. optional, free metadata probes against the original registry and
   ecosyste.ms.

Results are written only below `artifact_recovery/outputs/`, which is ignored
by Git except for its placeholder.

## Local audit

From the repository root:

```bash
python3 artifact_recovery/audit.py \
  --coordinates data/pkg_mal.csv \
  --known-archives data/Backstabbers-Knife-Collection/samples \
  --osv-root data/malicious-packages-info
```

Search additional read-only cache or mirror directories by repeating
`--cache-root`:

```bash
python3 artifact_recovery/audit.py \
  --cache-root /path/to/old/npm-cache \
  --cache-root /path/to/pip-download-cache
```

Only ordinary archive files are inspected. npm/PyPI metadata inside tar/zip
archives is read without extraction or execution. Unrecognized archives remain
unattributed rather than being matched by filename alone.

## Optional free metadata probes

```bash
python3 artifact_recovery/audit.py --online --limit 100
```

Online mode performs metadata-only HTTP GET requests. It does not follow an
artifact URL or save an artifact. Start with a small limit to respect public
service rate limits. Set `--contact-email` to identify research traffic to
ecosyste.ms' polite pool:

```bash
python3 artifact_recovery/audit.py \
  --online \
  --limit 100 \
  --contact-email researcher@example.edu
```

Use `--start-index` with `--limit` to probe bounded batches without exceeding
free-service rate limits. Give each batch a distinct `--output-dir` if its
results must be retained.

## Recover exact archives

After producing the baseline audit, recover a bounded batch into the separate
quarantine directory:

```bash
python3 artifact_recovery/collect.py --limit 100 --workers 6
```

The collector only downloads HTTPS artifacts from official npm, PyPI,
RubyGems, or crates.io hosts. It rejects oversized files, archive/coordinate
mismatches, and published-integrity mismatches. Accepted specimens are stored
under `data/recovered-malicious-packages/<ecosystem>/<name>/<version>/`; they
are never extracted or executed by the collector.

## Outputs

- `outputs/recovery_audit.csv`: one row per requested coordinate
- `outputs/summary.json`: counts by recovery status and evidence source

Important statuses:

- `exact_local_archive`: an exact coordinate was read from a local archive
- `registry_metadata_available`: the registry still exposes the exact version
- `ecosystems_metadata_available`: ecosyste.ms remembers the exact version
- `osv_references_only`: reports/references exist but no artifact was found
- `unresolved`: no current recovery lead was found

Metadata availability is not artifact recovery. Any subsequently obtained
archive must be hashed and provenance-checked before it is admitted to the
primary dynamic replay dataset. `repository_url`, `candidate_artifact_url`, and
`published_integrity` are untrusted leads copied from metadata; the audit never
follows the candidate artifact URL.
