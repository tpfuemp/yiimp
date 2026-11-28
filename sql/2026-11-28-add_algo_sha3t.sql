-- sha3t (triple SHA3-256: Fjarcode, Bitcoin III up to block 64360) algo registration.
-- After applying, flush/expire the web memcache keys yaamp_algo_list,
-- yaamp_visible_algos, yaamp_unvisible_algos, yaamp_algo_ports and
-- yaamp_algo_colors so the new algo and port become visible immediately.
INSERT INTO `algos` (`name`, `color`, `speedfactor`, `port`, `visible`, `powlimit_bits`) VALUES
('sha3t', '#9ad0c2', 1, 3648, 1, NULL);
