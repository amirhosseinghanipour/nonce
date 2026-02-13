-- +goose Up
-- Row-Level Security: tenant isolation so user queries only see rows for current project.
-- Set app.current_project_id in application before DB calls when RLS_ENABLED=true.
-- refresh_tokens is not RLS-protected here so token lookup by hash works without project context.

ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- users: only rows where project_id matches the session variable
CREATE POLICY users_project_isolation ON users
  FOR ALL
  USING (project_id = COALESCE(current_setting('app.current_project_id', true)::uuid, '00000000-0000-0000-0000-000000000000'))
  WITH CHECK (project_id = COALESCE(current_setting('app.current_project_id', true)::uuid, '00000000-0000-0000-0000-000000000000'));

-- +goose Down
DROP POLICY IF EXISTS users_project_isolation ON users;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
