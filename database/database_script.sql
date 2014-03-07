CREATE TABLE targets(
    ip_subnet ip4r NOT NULL,
    as_number int NOT NULL,
    PRIMARY KEY(ip_subnet)
);

CREATE TABLE destinations(
    ip_dest ip4 NOT NULL,
    ip_subnet ip4r NOT NULL REFERENCES targets(ip_subnet) ON UPDATE CASCADE,
    PRIMARY KEY(ip_dest)
);

CREATE TABLE traces(
    n_hop ip4 NOT NULL,
    ip_hop ip4 NOT NULL,
    ip_dest ip4 NOT NULL REFERENCES destinations(ip_dest) ON UPDATE CASCADE,
    classification text NOT NULL,
    PRIMARY KEY(n_hop,ip_hop,ip_dest)
);

