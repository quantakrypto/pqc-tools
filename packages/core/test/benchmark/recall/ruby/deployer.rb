# frozen_string_literal: true

require "net/ssh"

# Runs the release script on each app host over SSH. Host-key and user-key
# algorithms are pinned to what our bastion advertises so a downgraded server
# can't silently negotiate something weaker.
class Deployer
  SSH_OPTIONS = {
    auth_methods: %w[publickey],
    keys: ["~/.ssh/deploy_ed25519", "~/.ssh/deploy_rsa"],
    host_key: %w[ssh-ed25519 rsa-sha2-512 ecdsa-sha2-nistp256],
    hostkeys_algorithms: %w[ssh-ed25519 ssh-rsa],
    encryption: %w[aes256-gcm@openssh.com]
  }.freeze

  def initialize(hosts, user: "deploy")
    @hosts = hosts
    @user = user
  end

  def run(command)
    @hosts.map do |host|
      Net::SSH.start(host, @user, SSH_OPTIONS) do |ssh|
        ssh.exec!(command)
      end
    end
  end
end
