//! Static transport configuration for the edge agent.
//!
//! Pins the classical TLS 1.2 cipher suites the upstream load balancer still
//! requires, and carries the SSH host-key policy used when the agent shells
//! into legacy jump hosts.

use rustls::cipher_suite::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};
use rustls::SupportedCipherSuite;

/// Ordered preference list negotiated with the load balancer.
pub const NEGOTIATED_SUITES: &[SupportedCipherSuite] = &[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
];

/// Host-key policy applied to outbound SSH sessions to the jump hosts.
///
/// Kept as an inline OpenSSH config fragment so ops can diff it against the
/// deployed `~/.ssh/config` verbatim.
pub const JUMP_HOST_SSH_POLICY: &str = "\
Host jump-*
    HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ssh-rsa
    PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512
    IdentityFile ~/.ssh/edge_agent_ed25519
";

/// Pinned host key for the primary jump host (checked into config on purpose).
pub const JUMP_HOST_KEY: &str =
    "jump-01 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0ExAMPLEkeyBytesForBenchmarkFixtureOnly00";

pub fn suites() -> Vec<SupportedCipherSuite> {
    NEGOTIATED_SUITES.to_vec()
}
