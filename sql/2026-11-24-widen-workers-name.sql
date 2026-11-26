-- NEB neb1 addresses are 62-character bech32m strings, stored in workers.name
-- (varchar(52) so far): without this NEB authorize fails with MySQL error 1406.
ALTER TABLE `workers` MODIFY COLUMN `name` varchar(128) DEFAULT NULL;
