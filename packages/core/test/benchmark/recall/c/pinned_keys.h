/* pinned_keys.h
 *
 * Compile-time trust material for the update client: a pinned RSA public key
 * (PEM) used to verify release manifests, plus the SSH host-key policy used
 * when pulling deltas over the management channel. This header carries the
 * crypto as configuration/data rather than as API calls.
 */
#ifndef PINNED_KEYS_H
#define PINNED_KEYS_H

/* Pinned RSA-2048 manifest-signing key. */
static const char RELEASE_PUBKEY_PEM[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Zx7Yc2mQx5oQvJ7pKq3\n"
    "aVdN0mL8sT4rWq2eH9bYn6cKpR3uF1gXe0jZ5tB7wOa9cD2mH4kL6nP8rS1tU3vW\n"
    "x5Y7zA9bC1dE3fG5hI7jK9lM1nO3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hI3jK5lM7\n"
    "nO9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9d\n"
    "E1fG3hI5jK7lM9nO1pQ3rS5tU7vW9xY1zA3bC5dE7fG9hI1jK3lM5nO7pQ9rS1tU\n"
    "3vW5xY7zA9bC1dE3fG5hQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

/* known_hosts entry for the delta mirror (Ed25519 host key). */
static const char MIRROR_HOST_KEY[] =
    "mirror.internal ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIH3kJ9Qm2wYb7cR1fP5tL8nX0aVd2sT4rWq6eH1bYn6c";

/* Host-key algorithms we are willing to accept, in preference order. */
#define SSH_HOSTKEY_ALGS "ssh-ed25519,rsa-sha2-512,ecdsa-sha2-nistp256"

#endif /* PINNED_KEYS_H */
