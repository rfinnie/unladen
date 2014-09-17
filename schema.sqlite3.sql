CREATE TABLE objects (
    uuid text,
    account text,
    container text,
    name text,
    bytes int,
    store text,
    last_modified int,
    hash text,
    meta text,
    user_meta text
);

CREATE TABLE tokens_cache (
    id text,
    account text,
    expires int,
    source text
);

CREATE TABLE tempauth_users (
    account text,
    username text,
    password text
);
