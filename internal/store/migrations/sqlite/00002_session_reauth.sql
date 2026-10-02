-- +goose Up
-- Re-authentication window (Design Spec section 13.3). The timestamp of the
-- last fresh password confirmation for this session; sensitive operations
-- require it to be recent. NULL means the session has never re-authenticated.
ALTER TABLE sessions ADD COLUMN reauth_at TEXT;

-- +goose Down
ALTER TABLE sessions DROP COLUMN reauth_at;
