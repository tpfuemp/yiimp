-- Parallax (LAX) XHash algo registration.
-- After applying, flush/expire the web memcache keys yaamp_algo_list,
-- yaamp_visible_algos, yaamp_unvisible_algos, yaamp_algo_ports and
-- yaamp_algo_colors so the new algo and port become visible immediately.
--
-- XHash is an Ethereum-style chain: the stratum uses the ethash work module
-- with the xhash engine (xhash_getWork / xhash_submitWork, eth_* block
-- queries). Shares use the ethash scale, target = 2^224 / difficulty, and
-- powlimit_bits = 0 makes the web hashrate difficulty / block_time.
--
-- Add the LAX coin row through the admin UI with algo='xhash',
-- rpcencoding='GETH', rpccurl=1, block_time 600 and mature_blocks 100.
-- The official Parallax node has no HTTP basic auth: leave rpcuser/rpcpasswd
-- empty and bind its RPC to loopback only.
INSERT INTO `algos` (`name`, `color`, `speedfactor`, `port`, `visible`, `powlimit_bits`) VALUES
('xhash', '#b39ddb', 1, 3647, 1, 0);
