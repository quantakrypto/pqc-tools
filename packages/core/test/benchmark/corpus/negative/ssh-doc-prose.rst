Changelog
=========

- Removed support for the ``ssh-rsa`` and ``ssh-dss`` host key algorithms.
- Deprecated the ``diffie-hellman-group14-sha1`` key exchange method.
- The ``ECDHE-RSA`` cipher suites are no longer offered by default.
- See the ``ecdsa-sha2-nistp256`` migration note for details.

These are prose mentions in documentation, not crypto configuration, so the
scanner must not flag them.
