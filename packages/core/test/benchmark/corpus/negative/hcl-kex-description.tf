variable "ssh_kex" {
  description = "Acceptable values include curve25519-sha256, ecdh-sha2-nistp256, ecdh-sha2-nistp384, diffie-hellman-group14-sha1, diffie-hellman-group1-sha1"
  type        = list(string)
  default     = null
}

variable "tls_ciphers" {
  description = "e.g. ECDHE-RSA-AES128-GCM-SHA256 or TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
  type        = list(string)
}
