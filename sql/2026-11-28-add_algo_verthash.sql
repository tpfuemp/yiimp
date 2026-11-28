-- verthash (Vertcoin) algo registration. The stratum needs verthash.dat,
-- see [VERTHASH] in config.sample/verthash.conf.
-- After applying, flush/expire the web memcache keys yaamp_algo_list,
-- yaamp_visible_algos, yaamp_unvisible_algos, yaamp_algo_ports and
-- yaamp_algo_colors so the new algo and port become visible immediately.
INSERT INTO `algos` (`name`, `color`, `speedfactor`, `port`, `visible`, `powlimit_bits`) VALUES
('verthash', '#80c0f0', 1, 6144, 1, NULL);
