CREATE TABLE files (
    uuid text,
    bytes_disk int,
    store text,
    uploader text,
    created int,
    meta text
);

CREATE TABLE objects (
    uuid text,
    account text,
    container text,
    name text,
    bytes int,
    last_modified int,
    expires int,
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
