-- Grant remote access to the application user.
-- This allows connections over VPN (Zerotier / Tailscale) from any host.
--
-- The MySQL Docker image creates MYSQL_USER with '%' by default, but
-- this script makes the grant explicit and ensures FLUSH PRIVILEGES is run.
--
-- SECURITY RECOMMENDATION:
--   For better defence-in-depth, restrict the host pattern to your VPN subnet
--   instead of using the wildcard '%'. Uncomment ONE of the examples below
--   that matches your VPN setup, and remove the wildcard grant above it.
--
--   Zerotier  (typical subnet 10.147.x.x/16):
--     GRANT ALL PRIVILEGES ON rijanauth.* TO 'rijanauth_user'@'10.147.%';
--
--   Tailscale (CGNAT range 100.64.x.x/10):
--     GRANT ALL PRIVILEGES ON rijanauth.* TO 'rijanauth_user'@'100.64.%';
--
--   Always combine with server-level firewall rules that allow TCP 3306
--   only from the VPN subnet.

GRANT ALL PRIVILEGES ON rijanauth.* TO 'rijanauth_user'@'%';
FLUSH PRIVILEGES;
