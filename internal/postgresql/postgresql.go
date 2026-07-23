package postgresql

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

func Configure(ctx context.Context, r runner.Runner) error {
	if err := configureAccess(); err != nil {
		return err
	}
	if err := os.MkdirAll("/etc/centralcloud-agent/secrets", 0o750); err != nil {
		return err
	}
	passwordPath := "/etc/centralcloud-agent/secrets/postgres_password"
	password, err := ensurePassword(passwordPath)
	if err != nil {
		return err
	}
	sql := fmt.Sprintf(`DO $centralcloud$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'centralcloud_provisioner') THEN
    CREATE ROLE centralcloud_provisioner LOGIN CREATEDB CREATEROLE PASSWORD '%s';
  ELSE
    ALTER ROLE centralcloud_provisioner LOGIN CREATEDB CREATEROLE PASSWORD '%s';
  END IF;
END
$centralcloud$;
`, quoteLiteral(password), quoteLiteral(password))
	for index := range password {
		password[index] = 0
	}
	sqlFile, err := os.CreateTemp("/run", ".centralcloud-postgres-*.sql")
	if err != nil {
		return err
	}
	sqlPath := sqlFile.Name()
	defer func() { _ = os.Remove(sqlPath) }()
	if err := sqlFile.Chmod(0o600); err != nil {
		_ = sqlFile.Close()
		return err
	}
	if _, err := sqlFile.WriteString(sql); err != nil {
		_ = sqlFile.Close()
		return err
	}
	if err := sqlFile.Close(); err != nil {
		return err
	}
	postgresUser, err := user.Lookup("postgres")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(postgresUser.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(postgresUser.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(sqlPath, uid, gid); err != nil {
		return err
	}
	commands := [][]string{
		{"systemctl", "enable", "--now", "postgresql"},
		{"systemctl", "restart", "postgresql"},
		{"runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--file", sqlPath},
		{"pg_isready", "-h", "127.0.0.1", "-p", "5432"},
		{"runuser", "-u", "postgres", "--", "dropdb", "--if-exists", "centralcloud_installer_validation"},
		{"runuser", "-u", "postgres", "--", "createdb", "--owner", "centralcloud_provisioner", "centralcloud_installer_validation"},
		{"runuser", "-u", "postgres", "--", "dropdb", "--if-exists", "centralcloud_installer_validation"},
	}
	for _, command := range commands {
		if _, err := r.Run(ctx, command[0], command[1:]...); err != nil {
			return fmt.Errorf("postgresql: %w", err)
		}
	}
	return nil
}

func configureAccess() error {
	confDir := "/etc/postgresql/17/main/conf.d"
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		return err
	}
	settings := "listen_addresses = '*'\npassword_encryption = 'scram-sha-256'\n"
	if err := os.WriteFile(filepath.Join(confDir, "centralcloud.conf"), []byte(settings), 0o644); err != nil {
		return err
	}
	hbaPath := "/etc/postgresql/17/main/pg_hba.conf"
	data, err := os.ReadFile(hbaPath)
	if err != nil {
		return err
	}
	begin := "# BEGIN CENTRALCLOUD MANAGED\n"
	if strings.Contains(string(data), begin) {
		return nil
	}
	block := begin +
		"host all all 127.0.0.1/32 scram-sha-256\n" +
		"host all all ::1/128 scram-sha-256\n" +
		"host all all 172.16.0.0/12 scram-sha-256\n" +
		"host all all 0.0.0.0/0 reject\n" +
		"host all all ::/0 reject\n" +
		"# END CENTRALCLOUD MANAGED\n\n"
	backup := hbaPath + ".centralcloud-backup"
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		if err := os.WriteFile(backup, data, 0o600); err != nil {
			return err
		}
	}
	return os.WriteFile(hbaPath, append([]byte(block), data...), 0o640)
}

func ensurePassword(path string) ([]byte, error) {
	if data, err := os.ReadFile(filepath.Clean(path)); err == nil {
		if len(data) < 32 {
			return nil, fmt.Errorf("existing PostgreSQL provisioner password is too short")
		}
		return []byte(strings.TrimSpace(string(data))), nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	raw := make([]byte, 48)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	value := []byte(base64.RawURLEncoding.EncodeToString(raw))
	for index := range raw {
		raw[index] = 0
	}
	if err := os.WriteFile(path, append(append([]byte(nil), value...), '\n'), 0o600); err != nil {
		return nil, err
	}
	return value, nil
}

func quoteLiteral(value []byte) string {
	return strings.ReplaceAll(string(value), "'", "''")
}
