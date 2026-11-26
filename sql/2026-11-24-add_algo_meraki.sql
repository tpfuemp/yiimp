-- Meraki (Telestai / TLS) algo registration.
-- After applying, flush/expire the web memcache keys yaamp_algo_list,
-- yaamp_visible_algos, yaamp_unvisible_algos, yaamp_algo_ports and
-- yaamp_algo_colors so the new algo and port become visible immediately.
--
-- Add the TLS coin row through the admin UI with algo='meraki' and RPC
-- credentials pointing at a Telestai Core 3.x node with getblocktemplate.
INSERT INTO `algos` (`name`, `color`, `speedfactor`, `port`, `visible`, `powlimit_bits`) VALUES
('meraki', '#ffd166', 1, 3646, 1, NULL);
