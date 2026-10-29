# Dependency provenance

The user authorizes Tokio, RustCrypto and AWS as trusted organizations. The existing
workspace does **not** satisfy that restriction on available evidence. Packages
already present are not automatically authorized, and necessity does not grant
an exception. The earlier focused dependency review incorrectly invented a
review-based exception; that policy statement has been corrected.

Run the standard-library-only inventory from the repository root:

```sh
python3 examples/interop/run.py audit-dependencies
PYTHONPATH=examples/interop python3 -m unittest discover -s examples/interop/tests -p test_audit_dependencies.py
```

The inventory reads the current lockfile, workspace manifests and cached package
manifests without downloading packages. It records package identities/checksums,
declared repositories, direct dependencies and the root lockfile hash. Its
report goes to ignored `.artifacts/` by default or an explicit output path.
Historical report dumps and fixed package counts have been removed.

Repository declarations are evidence of claimed provenance, not verified
ownership or a security assessment. Authorization does not propagate through
dependency edges. Missing cached metadata remains unverified. The checker
matches the exact `tokio-rs`, `RustCrypto`, `aws` and `awslabs` organizations;
lookalike names, package names and use by an authorized project do not qualify.

The application examples introduce no new third-party package identities. Their
workspace selects dependencies per application; encrypted transport features
are opt-in. Database SDKs remain in the remote adapter’s separate workspace.
Resolving the existing trust restriction remains separate work; reorganizing
examples does not establish that all transitive packages are authorized.
