//go:build cgo
// +build cgo

package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"gitee.com/iscas-system/kine/pkg/drivers/generic"
	"gitee.com/iscas-system/kine/pkg/logstructured"
	"gitee.com/iscas-system/kine/pkg/logstructured/sqllog"
	"gitee.com/iscas-system/kine/pkg/server"
	"gitee.com/iscas-system/kine/pkg/util"
	"github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	// sqlite db driver
	_ "github.com/mattn/go-sqlite3"
)

var (
	schema = []string{
		`CREATE TABLE IF NOT EXISTS kine
			(
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name INTEGER,
				created INTEGER,
				deleted INTEGER,
				create_revision INTEGER,
				prev_revision INTEGER,
				lease INTEGER,
				value BLOB,
				old_value BLOB
			)`,
		`CREATE INDEX IF NOT EXISTS kine_name_index ON kine (name)`,
		`CREATE INDEX IF NOT EXISTS kine_name_id_index ON kine (name,id)`,
		`CREATE INDEX IF NOT EXISTS kine_id_deleted_index ON kine (id,deleted)`,
		`CREATE INDEX IF NOT EXISTS kine_prev_revision_index ON kine (prev_revision)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS kine_name_prev_revision_uindex ON kine (name, prev_revision)`,
		`PRAGMA wal_checkpoint(TRUNCATE)`,
	}
)

func New(ctx context.Context, dataSourceName string, connPoolConfig generic.ConnectionPoolConfig, metricsRegisterer prometheus.Registerer) (server.Backend, error) {
	backend, _, err := NewVariant(ctx, "sqlite3", dataSourceName, connPoolConfig, metricsRegisterer)
	return backend, err
}

func NewVariant(ctx context.Context, driverName, dataSourceName string, connPoolConfig generic.ConnectionPoolConfig, metricsRegisterer prometheus.Registerer) (server.Backend, *generic.Generic, error) {
	if dataSourceName == "" {
		if err := os.MkdirAll("./db", 0700); err != nil {
			return nil, nil, err
		}
		dataSourceName = "./db/state.db?_journal=WAL&cache=shared&_busy_timeout=30000"
	}

	dialect, err := generic.Open(ctx, driverName, dataSourceName, connPoolConfig, "?", false, metricsRegisterer)
	if err != nil {
		return nil, nil, err
	}

	dialect.LastInsertID = true
	dialect.GetSizeSQL = `SELECT SUM(pgsize) FROM dbstat`
	dialect.CompactSQL = `
		DELETE FROM kine AS kv
		WHERE
			kv.id IN (
				SELECT kp.prev_revision AS id
				FROM kine AS kp
				WHERE
					kp.name != 'compact_rev_key' AND
					kp.prev_revision != 0 AND
					kp.id <= ?
				UNION
				SELECT kd.id AS id
				FROM kine AS kd
				WHERE
					kd.deleted != 0 AND
					kd.id <= ?
			)`
	dialect.PostCompactSQL = `PRAGMA wal_checkpoint(FULL)`
	dialect.TranslateErr = func(err error) error {
		if err, ok := err.(sqlite3.Error); ok && err.ExtendedCode == sqlite3.ErrConstraintUnique {
			return server.ErrKeyExists
		}
		return err
	}
	dialect.ErrCode = func(err error) string {
		if err == nil {
			return ""
		}
		if err, ok := err.(sqlite3.Error); ok {
			return fmt.Sprint(err.ExtendedCode)
		}
		return err.Error()
	}

	// this is the first SQL that will be executed on a new DB conn so
	// loop on failure here because in the case of dqlite it could still be initializing
	for i := 0; i < 300; i++ {
		err = setup(dialect.DB)
		if err == nil {
			break
		}
		logrus.Errorf("failed to setup db: %v", err)
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(time.Second):
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return nil, nil, errors.Wrap(err, "setup db")
	}

	dialect.Migrate(context.Background())
	return logstructured.New(sqllog.New(dialect)), dialect, nil
}

func createResourceTable(db *sql.DB, tableName string) error {

	createTableQuery := fmt.Sprintf(`
    CREATE TABLE IF NOT EXISTS %s (
        name TEXT,
        namespace TEXT,
        apigroup TEXT,
        region TEXT,
        data TEXT,
        created_time TEXT,
        update_time TEXT,
        PRIMARY KEY (name)
    );`, tableName)

	if _, err := db.Exec(createTableQuery); err != nil {
		return err
	}

	// 创建索引
	createIndexQueries := []string{
		fmt.Sprintf(`CREATE INDEX %s_name_index ON %s (name);`, tableName, tableName),
		fmt.Sprintf(`CREATE INDEX %s_name_created_time_index ON %s (name, created_time);`, tableName, tableName),
		fmt.Sprintf(`CREATE INDEX %s_name_update_time_index ON %s (name, update_time);`, tableName, tableName),
		fmt.Sprintf(`CREATE INDEX %s_namespace_created_time_index ON %s (namespace, created_time);`, tableName, tableName),
		fmt.Sprintf(`CREATE INDEX %s_namespace_update_time_index ON %s (namespace, update_time);`, tableName, tableName),
	}

	for _, query := range createIndexQueries {
		_, err := db.Exec(query)
		if err != nil {
			return err
		}
	}
	return nil
}

func setup(db *sql.DB) error {
	logrus.Infof("Configuring database table schema and indexes, this may take a moment...")

	for _, stmt := range schema {
		logrus.Tracef("SETUP EXEC : %v", util.Stripped(stmt))
		_, err := db.Exec(stmt)
		if err != nil {
			return err
		}
	}

	// 创建特定资源的表和索引
	// 注册所有的api-resources,为他们创建表格
	resources := []string{
		"configmaps", "endpoints", "events", "limitranges", "namespaces",
		"nodes", "persistentvolumeclaims", "persistentvolumes", "pods", "podtemplates",
		"replicationcontrollers", "resourcequotas", "secrets", "serviceaccounts", "services",
		"mutatingwebhookconfigurations", "validatingadmissionpolicies", "validatingadmissionpolicybindings", "validatingwebhookconfigurations", "customresourcedefinitions",
		"apiservices", "controllerrevisions", "daemonsets", "deployments", "replicasets",
		"statefulsets", "horizontalpodautoscalers", "cronjobs", "jobs", "certificatesigningrequests",
		"leases", "endpointslices", "flowschemas", "prioritylevelconfigurations", "helmchartconfigs",
		"helmcharts", "addons", "etcdsnapshotfiles", "ingressclasses", "ingress",
		"networkpolicies", "runtimeclasses", "poddisruptionbudgets", "clusterrolebindings", "clusterroles",
		"rolebindings", "roles", "priorityclasses", "csidrivers", "csinodes",
		"csistoragecapacities", "storageclasses", "volumeattachments", "ingressroutes", "ingressroutetcps",
		"ingressrouteudps", "middlewares", "middlewaretcps", "serverstransports", "tlsoptions",
		"tlsstores", "traefikservices", "serverstransporttcps",
	}
	for _, resource := range resources {
		err := createResourceTable(db, resource)
		if err != nil {
			return err
		}
	}

	logrus.Infof("Database tables and indexes are up to date")
	return nil
}
