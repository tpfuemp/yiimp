-- NEB nebhash algo registration (neb-pool/1 stratum protocol).
-- After applying, flush/expire the web memcache keys yaamp_algo_list,
-- yaamp_visible_algos, yaamp_unvisible_algos, yaamp_algo_ports and
-- yaamp_algo_colors so the new algo and port become visible immediately.
--
-- The NEB node has no getblocktemplate/validateaddress RPC: stratum talks to
-- its work service (127.0.0.1:3441 by default) and uses JSON-RPC getinfo for
-- chain id/height. Add the NEB coin row through the admin UI with
-- algo='nebhash', RPC pointing at the node's JSON-RPC port (8432), and the
-- effective pool reward of 19 (20 NEB coinbase, 1 NEB dev output).
INSERT INTO `algos` (`name`, `color`, `speedfactor`, `port`, `visible`, `powlimit_bits`) VALUES
('nebhash', '#7fd6ff', 1, 3645, 1, NULL);
