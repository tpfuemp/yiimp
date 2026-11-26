-- Stratum stores whether a worker is connected over TLS (stratum TLS listeners).
-- Required by stratum builds with TLS: their worker INSERT/UPDATE use this column.
ALTER TABLE `workers` ADD COLUMN `tls` TINYINT(1) NOT NULL DEFAULT 0;
