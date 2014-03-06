DROP DATABASE IF EXISTS results;
CREATE DATABASE results;
USE results;

#tables

DROP TABLE IF EXISTS targets;
CREATE TABLE results.targets(
    ip_subnet inet NOT NULL,
    as_number INT(10) unsigned NOT NULL,
    PRIMARY KEY(ip_subnet)
);

DROP TABLE IF EXISTS destinations;
CREATE TABLE results.destinations(
    ip_dest inet NOT NULL,
    ip_subnet INT(10) unsigned NOT NULL,
    PRIMARY KEY(ip_dest),
    FOREIGN KEY(ip_subnet) REFERENCES targets(ip_subnet) ON UPDATE CASCADE
);

DROP TABLE IF EXISTS traces;
CREATE TABLE results.traces(
    ip_hop inet NOT NULL,
    ip_dest inet NOT NULL,
    classification VARCHAR(15) NOT NULL,
    PRIMARY KEY(ip_hop,ip_dest)
    FOREIGN KEY(ip_dest) REFERENCES destinations(ip_dest) ON UPDATE CASCADE
);

