package generic

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	discoverybeta1 "k8s.io/api/discovery/v1beta1"
	flowcontrolv1 "k8s.io/api/flowcontrol/v1"
	networkingv1 "k8s.io/api/networking/v1"
	nodev1 "k8s.io/api/node/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitee.com/iscas-system/kine/pkg/metrics"
	"gitee.com/iscas-system/kine/pkg/server"
	"gitee.com/iscas-system/kine/pkg/util"
	"github.com/Rican7/retry/backoff"
	"github.com/Rican7/retry/strategy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/sirupsen/logrus"
)

const (
	defaultMaxIdleConns = 2 // copied from database/sql
)

// explicit interface check
var _ server.Dialect = (*Generic)(nil)

var (
	columns = "kv.id AS theid, kv.name, kv.created, kv.deleted, kv.create_revision, kv.prev_revision, kv.lease, kv.value, kv.old_value"
	revSQL  = `
		SELECT MAX(rkv.id) AS id
		FROM kine AS rkv`

	compactRevSQL = `
		SELECT MAX(crkv.prev_revision) AS prev_revision
		FROM kine AS crkv
		WHERE crkv.name = 'compact_rev_key'`

	idOfKey = `
		AND
		mkv.id <= ? AND
		mkv.id > (
			SELECT MAX(ikv.id) AS id
			FROM kine AS ikv
			WHERE
				ikv.name = ? AND
				ikv.id <= ?)`

	listSQL = fmt.Sprintf(`
		SELECT *
		FROM (
			SELECT (%s), (%s), %s
			FROM kine AS kv
			JOIN (
				SELECT MAX(mkv.id) AS id
				FROM kine AS mkv
				WHERE
					mkv.name LIKE ?
					%%s
				GROUP BY mkv.name) AS maxkv
				ON maxkv.id = kv.id
			WHERE
				kv.deleted = 0 OR
				?
		) AS lkv
		ORDER BY lkv.theid ASC
		`, revSQL, compactRevSQL, columns)

	tableName = ""

	tableMap = map[string]string{
		"/configmaps/": "configmaps", "/endpoints/": "endpoints", "/events/": "events", "/limitranges/": "limitranges", "/namespaces/": "namespaces",
		"/minions/": "nodes", "/persistentvolumeclaims/": "persistentvolumeclaims", "/persistentvolumes/": "persistentvolumes", "/pods/": "pods", "/podtemplates/": "podtemplates",
		"/controllers/": "replicationcontrollers", "/resourcequotas/": "resourcequotas", "/secrets/": "secrets", "/serviceaccounts/": "serviceaccounts", "/services/specs/": "services",
		"/mutatingwebhookconfigurations/": "mutatingwebhookconfigurations", "/validatingadmissionpolicies/": "validatingadmissionpolicies", "/validatingadmissionpolicybindings/": "validatingadmissionpolicybindings", "/validatingwebhookconfigurations/": "validatingwebhookconfigurations", "/customresourcedefinitions/": "customresourcedefinitions",
		"/apiservices/": "apiservices", "/controllerrevisions/": "controllerrevisions", "/daemonsets/": "daemonsets", "/deployments/": "deployments", "/replicasets/": "replicasets",
		"/statefulsets/": "statefulsets", "/horizontalpodautoscalers/": "horizontalpodautoscalers", "/cronjobs/": "cronjobs", "/jobs/": "jobs", "/certificatesigningrequests/": "certificatesigningrequests",
		"/leases/": "leases", "/endpointslices/": "endpointslices", "/flowschemas/": "flowschemas", "/prioritylevelconfigurations/": "prioritylevelconfigurations", "/helmchartconfigs/": "helmchartconfigs",
		"/helmcharts/": "helmcharts", "/addons/": "addons", "/etcdsnapshotfiles/": "etcdsnapshotfiles", "/ingressclasses/": "ingressclasses", "/ingress/": "ingress",
		"/networkpolicies/": "networkpolicies", "/runtimeclasses/": "runtimeclasses", "/poddisruptionbudgets/": "poddisruptionbudgets", "/clusterrolebindings/": "clusterrolebindings", "/clusterroles/": "clusterroles",
		"/rolebindings/": "rolebindings", "/roles/": "roles", "/priorityclasses/": "priorityclasses", "/csidrivers/": "csidrivers", "/csinodes/": "csinodes",
		"/csistoragecapacities/": "csistoragecapacities", "/storageclasses/": "storageclasses", "/volumeattachments/": "volumeattachments", "/traefik.containo.us/ingressroutes/": "ingressroutes", "/traefik.containo.us/ingressroutetcps/": "ingressroutetcps",
		"/traefik.containo.us/ingressrouteudps/": "ingressrouteudps", "/traefik.containo.us/middlewares/": "middlewares", "/traefik.containo.us/middlewaretcps/": "middlewaretcps", "/traefik.containo.us/serverstransports/": "serverstransports", "/traefik.containo.us/tlsoptions/": "tlsoptions",
		"/traefik.containo.us/tlsstores/": "tlsstores", "/traefik.containo.us/traefikservices/": "traefikservices", "/traefik.io/ingressroutes/": "ingressroutes", "/traefik.io/ingressroutetcps/": "ingressroutetcps", "/traefik.io/ingressrouteudps/": "ingressrouteudps",
		"/traefik.io/middlewares/": "middlewares", "/traefik.io/middlewaretcps/": "middlewaretcps", "/traefik.io/serverstransports/": "serverstransports", "/serverstransporttcps/": "serverstransporttcps", "/traefik.io/tlsoptions/": "tlsoptions",
		"/traefik.io/tlsstores/": "tlsstores", "/traefik.io/traefikservices/": "traefikservices",
	}
)

type ErrRetry func(error) bool
type TranslateErr func(error) error
type ErrCode func(error) string

type ConnectionPoolConfig struct {
	MaxIdle     int           // zero means defaultMaxIdleConns; negative means 0
	MaxOpen     int           // <= 0 means unlimited
	MaxLifetime time.Duration // maximum amount of time a connection may be reused
}

type Generic struct {
	sync.Mutex

	LockWrites            bool
	LastInsertID          bool
	DB                    *sql.DB
	GetCurrentSQL         string
	GetRevisionSQL        string
	RevisionSQL           string
	ListRevisionStartSQL  string
	GetRevisionAfterSQL   string
	CountCurrentSQL       string
	CountRevisionSQL      string
	AfterSQL              string
	DeleteSQL             string
	CompactSQL            string
	UpdateCompactSQL      string
	PostCompactSQL        string
	InsertSQL             string
	FillSQL               string
	InsertLastInsertIDSQL string
	GetSizeSQL            string
	ResourcesDeleteSQL    string
	ResourcesInsertSQL    string
	ResourcesUpdateSQL    string
	param                 string
	numbered              bool
	Retry                 ErrRetry
	InsertRetry           ErrRetry
	TranslateErr          TranslateErr
	ErrCode               ErrCode
	FillRetryDuration     time.Duration
	//protobuf解码器
	protobufSerializer runtime.Serializer
}

// 字符串匹配，用于提取JSON中的信息
func extractValue(jsonStr, key string) (string, error) {
	// 创建匹配键值对的正则表达式
	regexPattern := fmt.Sprintf(`"%s"\s*:\s*"(.*?)"`, key)
	re := regexp.MustCompile(regexPattern)

	// 查找匹配项
	matches := re.FindStringSubmatch(jsonStr)
	if len(matches) < 2 {
		return "", fmt.Errorf("key %s not found", key)
	}
	return matches[1], nil
}

// 同样是字符串匹配，目的是提取出某条resources数据对应的表名及资源名
func containsAndReturnRemainder(str1, str2 string) (bool, string) {
	//检查str1是否包含str2
	index := strings.Index(str1, str2)
	if index == -1 {
		return false, ""
	}
	//如果str1包含str2，这返回str1字符串里包含的str2之后的字符串
	remainder := str1[index+len(str2):]
	return true, remainder
}

func q(sql, param string, numbered bool) string {
	if param == "?" && !numbered {
		return sql
	}

	regex := regexp.MustCompile(`\?`)
	n := 0
	return regex.ReplaceAllStringFunc(sql, func(string) string {
		if numbered {
			n++
			return param + strconv.Itoa(n)
		}
		return param
	})
}

// 注册所有支持的resources
func addSchemes(scheme *runtime.Scheme) {
	schemes := []struct {
		name string
		add  func(*runtime.Scheme) error
	}{
		{"core/v1", corev1.AddToScheme},
		{"apps/v1", appsv1.AddToScheme},
		{"batch/v1", batchv1.AddToScheme},
		{"rbac/v1", rbacv1.AddToScheme},
		{"apiextensions/v1", apiextensionsv1.AddToScheme},
		{"apiregistration/v1", apiregistrationv1.AddToScheme},
		{"flowcontrol/v1", flowcontrolv1.AddToScheme},
		{"coordination/v1", coordinationv1.AddToScheme},
		{"discovery/v1", discoveryv1.AddToScheme},
		{"discovery/v1beta1", discoverybeta1.AddToScheme},
		{"scheduling/v1", schedulingv1.AddToScheme},
		{"storage/v1", storagev1.AddToScheme},
		{"admissionregistration/v1", admissionregistrationv1.AddToScheme},
		{"admissionregistration/v1alpha1", admissionregistrationv1alpha1.AddToScheme},
		{"admissionregistration/v1beta1", admissionregistrationv1beta1.AddToScheme},
		{"authentication/v1", authenticationv1.AddToScheme},
		{"authorization/v1", authorizationv1.AddToScheme},
		{"autoscaling/v2", autoscalingv2.AddToScheme},
		{"certificates/v1", certificatesv1.AddToScheme},
		{"networking/v1", networkingv1.AddToScheme},
		{"node/v1", nodev1.AddToScheme},
		{"policy/v1", policyv1.AddToScheme},
	}

	for _, s := range schemes {
		if err := s.add(scheme); err != nil {
			log.Fatalf("Failed to add %s types to scheme: %v", s.name, err)
		}
	}
}

func configureConnectionPooling(connPoolConfig ConnectionPoolConfig, db *sql.DB, driverName string) {
	// behavior copied from database/sql - zero means defaultMaxIdleConns; negative means 0
	if connPoolConfig.MaxIdle < 0 {
		connPoolConfig.MaxIdle = 0
	} else if connPoolConfig.MaxIdle == 0 {
		connPoolConfig.MaxIdle = defaultMaxIdleConns
	}

	logrus.Infof("Configuring %s database connection pooling: maxIdleConns=%d, maxOpenConns=%d, connMaxLifetime=%s", driverName, connPoolConfig.MaxIdle, connPoolConfig.MaxOpen, connPoolConfig.MaxLifetime)
	db.SetMaxIdleConns(connPoolConfig.MaxIdle)
	db.SetMaxOpenConns(connPoolConfig.MaxOpen)
	db.SetConnMaxLifetime(connPoolConfig.MaxLifetime)
}

func openAndTest(driverName, dataSourceName string) (*sql.DB, error) {
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 3; i++ {
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, err
		}
	}

	return db, nil
}

func Open(ctx context.Context, driverName, dataSourceName string, connPoolConfig ConnectionPoolConfig, paramCharacter string, numbered bool, metricsRegisterer prometheus.Registerer) (*Generic, error) {
	var (
		db  *sql.DB
		err error
	)

	for i := 0; i < 300; i++ {
		db, err = openAndTest(driverName, dataSourceName)
		if err == nil {
			break
		}

		logrus.Errorf("failed to ping connection: %v", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}

	configureConnectionPooling(connPoolConfig, db, driverName)

	if metricsRegisterer != nil {
		metricsRegisterer.MustRegister(collectors.NewDBStatsCollector(db, "kine"))
	}

	// 初始化解码器
	// 初始化 Scheme
	myScheme := runtime.NewScheme()

	//注册各个对象到scheme中
	addSchemes(myScheme)

	// 初始化 CodecFactory
	codecFactory := serializer.NewCodecFactory(myScheme)

	// 获取 Protobuf 序列化器
	serializerInfo, ok := runtime.SerializerInfoForMediaType(codecFactory.SupportedMediaTypes(), runtime.ContentTypeProtobuf)
	if !ok {
		log.Fatalf("No Protobuf serializer found")
	}
	protobufSerializer := serializerInfo.Serializer

	return &Generic{
		DB: db,
		//sql语句中参数的符号
		param:    paramCharacter,
		numbered: numbered,
		//protobuf序列化器
		protobufSerializer: protobufSerializer,
		GetRevisionSQL: q(fmt.Sprintf(`
			SELECT
			0, 0, %s
			FROM kine AS kv
			WHERE kv.id = ?`, columns), paramCharacter, numbered),

		GetCurrentSQL:        q(fmt.Sprintf(listSQL, ""), paramCharacter, numbered),
		ListRevisionStartSQL: q(fmt.Sprintf(listSQL, "AND mkv.id <= ?"), paramCharacter, numbered),
		GetRevisionAfterSQL:  q(fmt.Sprintf(listSQL, idOfKey), paramCharacter, numbered),

		CountCurrentSQL: q(fmt.Sprintf(`
			SELECT (%s), COUNT(c.theid)
			FROM (
				%s
			) c`, revSQL, fmt.Sprintf(listSQL, "")), paramCharacter, numbered),

		CountRevisionSQL: q(fmt.Sprintf(`
			SELECT (%s), COUNT(c.theid)
			FROM (
				%s
			) c`, revSQL, fmt.Sprintf(listSQL, "AND mkv.id <= ?")), paramCharacter, numbered),

		AfterSQL: q(fmt.Sprintf(`
			SELECT (%s), (%s), %s
			FROM kine AS kv
			WHERE
				kv.name LIKE ? AND
				kv.id > ?
			ORDER BY kv.id ASC`, revSQL, compactRevSQL, columns), paramCharacter, numbered),

		DeleteSQL: q(`
			DELETE FROM kine AS kv
			WHERE kv.id = ?`, paramCharacter, numbered),

		UpdateCompactSQL: q(`
			UPDATE kine
			SET prev_revision = ?
			WHERE name = 'compact_rev_key'`, paramCharacter, numbered),

		InsertLastInsertIDSQL: q(`INSERT INTO kine(name, created, deleted, create_revision, prev_revision, lease, value, old_value)
			values(?, ?, ?, ?, ?, ?, ?, ?)`, paramCharacter, numbered),

		InsertSQL: q(`INSERT INTO kine(name, created, deleted, create_revision, prev_revision, lease, value, old_value)
			values(?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`, paramCharacter, numbered),

		FillSQL: q(`INSERT INTO kine(id, name, created, deleted, create_revision, prev_revision, lease, value, old_value)
			values(?, ?, ?, ?, ?, ?, ?, ?, ?)`, paramCharacter, numbered),

		ResourcesDeleteSQL: `DELETE FROM %s WHERE name = ?`,

		ResourcesInsertSQL: `INSERT INTO %s (name, namespace, apigroup, region, data, created_time, update_time)
			values(?, ?, ?, ?, ?, ?, ?)`,

		ResourcesUpdateSQL: `UPDATE %s SET namespace = ?, region = ?,data = ?, update_time = ? WHERE name = ?`,
	}, err
}

func (d *Generic) Migrate(ctx context.Context) {
	var (
		count     = 0
		countKV   = d.queryRow(ctx, "SELECT COUNT(*) FROM key_value")
		countKine = d.queryRow(ctx, "SELECT COUNT(*) FROM kine")
	)

	if err := countKV.Scan(&count); err != nil || count == 0 {
		return
	}

	if err := countKine.Scan(&count); err != nil || count != 0 {
		return
	}

	logrus.Infof("Migrating content from old table")
	_, err := d.execute(ctx,
		`INSERT INTO kine(deleted, create_revision, prev_revision, name, value, created, lease)
					SELECT 0, 0, 0, kv.name, kv.value, 1, CASE WHEN kv.ttl > 0 THEN 15 ELSE 0 END
					FROM key_value kv
						WHERE kv.id IN (SELECT MAX(kvd.id) FROM key_value kvd GROUP BY kvd.name)`)
	if err != nil {
		logrus.Errorf("Migration failed: %v", err)
	}
	//迁移kine中的数据到pod、service等各个表中
	if err := d.migrateData(ctx); err != nil {
		logrus.Fatalf("Data migration failed: %v", err)
	}
}

func (d *Generic) migrateData(ctx context.Context) error {
	var jsonData []byte
	resourceName := ""
	namespace := ""
	apigroup := ""
	region := ""
	creationTime := ""

	// 查询kine表中的所有数据
	rows, err := d.DB.QueryContext(ctx, `SELECT name, value FROM kine`)
	if err != nil {
		return fmt.Errorf("query kine table failed when migrating...: %v", err)
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			fmt.Println("failed to close rows: %v", err)
		}
	}(rows)

	for rows.Next() {
		var name string
		var value []byte
		if err := rows.Scan(&name, &value); err != nil {
			return fmt.Errorf("scan row failed: %v", err)
		}
		for resource, tablename := range tableMap {
			if found, remainder := containsAndReturnRemainder(name, resource); found {
				tableName = tablename
				resourceName = remainder
				break
			}
		}
		//如果没匹配到对应的resources，则直接返回，不需要进行后续操作
		if resourceName == "" {
			continue
		}

		encodedData := value

		// 解码 Protobuf 数据
		gvk := &schema.GroupVersionKind{} // 替换为实际的 GVK
		obj, _, err := d.protobufSerializer.Decode(encodedData, gvk, nil)
		if err != nil {
			//如果报错如下，则证明数据不需要从protobuf进行解码
			if err.Error() == "provided data does not appear to be a protobuf message, expected prefix [107 56 115 0]" {
				jsonData = value
			} else {
				fmt.Println("decoding：", tableName)
				log.Fatalf("Failed to decode protobuf: %v", err)
			}
		} else {
			// 将解码后的对象转换为 JSON 格式
			jsonData, err = json.MarshalIndent(obj, "", "  ")
			if err != nil {
				log.Fatalf("Failed to marshal JSON: %v", err)
			}
		}

		apigroup, err = extractValue(string(jsonData), "apiVersion")
		if err != nil {
			namespace = "cant-find-apigroup"
		}

		namespace, err = extractValue(string(jsonData), "namespace")
		if err != nil {
			namespace = "cant-find-namespace"
		}

		region, err = extractValue(string(jsonData), "nodeName")
		if err != nil {
			region = "cant-find-region"
		}

		creationTime, err = extractValue(string(jsonData), "creationTimestamp")
		if err != nil {
			creationTime = "cant-find-creationTime"
		}

		// 执行插入
		_, err = d.execute(ctx, q(fmt.Sprintf(d.ResourcesInsertSQL, tableName), d.param, d.numbered), resourceName, namespace, apigroup, region, jsonData, creationTime, creationTime)
		if err != nil {
			fmt.Println("insert resources error")
			panic(err)
		}

	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows iteration failed: %v", err)
	}

	return nil
}

func (d *Generic) query(ctx context.Context, sql string, args ...interface{}) (result *sql.Rows, err error) {
	logrus.Tracef("QUERY %v : %s", args, util.Stripped(sql))
	startTime := time.Now()
	defer func() {
		metrics.ObserveSQL(startTime, d.ErrCode(err), util.Stripped(sql), args)
	}()
	return d.DB.QueryContext(ctx, sql, args...)
}

func (d *Generic) queryRow(ctx context.Context, sql string, args ...interface{}) (result *sql.Row) {
	logrus.Tracef("QUERY ROW %v : %s", args, util.Stripped(sql))
	startTime := time.Now()
	defer func() {
		metrics.ObserveSQL(startTime, d.ErrCode(result.Err()), util.Stripped(sql), args)
	}()
	return d.DB.QueryRowContext(ctx, sql, args...)
}

func (d *Generic) execute(ctx context.Context, sql string, args ...interface{}) (result sql.Result, err error) {
	if d.LockWrites {
		d.Lock()
		defer d.Unlock()
	}

	wait := strategy.Backoff(backoff.Linear(100 + time.Millisecond))
	for i := uint(0); i < 20; i++ {
		logrus.Tracef("EXEC (try: %d) %v : %s", i, args, util.Stripped(sql))
		startTime := time.Now()
		result, err = d.DB.ExecContext(ctx, sql, args...)
		metrics.ObserveSQL(startTime, d.ErrCode(err), util.Stripped(sql), args)
		if err != nil && d.Retry != nil && d.Retry(err) {
			wait(i)
			continue
		}
		return result, err
	}
	return
}

func (d *Generic) GetCompactRevision(ctx context.Context) (int64, error) {
	var id int64
	row := d.queryRow(ctx, compactRevSQL)
	err := row.Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

func (d *Generic) SetCompactRevision(ctx context.Context, revision int64) error {
	logrus.Tracef("SETCOMPACTREVISION %v", revision)
	_, err := d.execute(ctx, d.UpdateCompactSQL, revision)
	return err
}

func (d *Generic) Compact(ctx context.Context, revision int64) (int64, error) {
	logrus.Tracef("COMPACT %v", revision)
	res, err := d.execute(ctx, d.CompactSQL, revision, revision)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *Generic) PostCompact(ctx context.Context) error {
	logrus.Trace("POSTCOMPACT")
	if d.PostCompactSQL != "" {
		_, err := d.execute(ctx, d.PostCompactSQL)
		return err
	}
	return nil
}

func (d *Generic) GetRevision(ctx context.Context, revision int64) (*sql.Rows, error) {
	return d.query(ctx, d.GetRevisionSQL, revision)
}

func (d *Generic) DeleteRevision(ctx context.Context, revision int64) error {
	logrus.Tracef("DELETEREVISION %v", revision)
	_, err := d.execute(ctx, d.DeleteSQL, revision)
	return err
}

func (d *Generic) ListCurrent(ctx context.Context, prefix string, limit int64, includeDeleted bool) (*sql.Rows, error) {
	sql := d.GetCurrentSQL
	if limit > 0 {
		sql = fmt.Sprintf("%s LIMIT %d", sql, limit)
	}
	return d.query(ctx, sql, prefix, includeDeleted)
}

func (d *Generic) List(ctx context.Context, prefix, startKey string, limit, revision int64, includeDeleted bool) (*sql.Rows, error) {
	if startKey == "" {
		sql := d.ListRevisionStartSQL
		if limit > 0 {
			sql = fmt.Sprintf("%s LIMIT %d", sql, limit)
		}
		return d.query(ctx, sql, prefix, revision, includeDeleted)
	}

	sql := d.GetRevisionAfterSQL
	if limit > 0 {
		sql = fmt.Sprintf("%s LIMIT %d", sql, limit)
	}
	return d.query(ctx, sql, prefix, revision, startKey, revision, includeDeleted)
}

func (d *Generic) CountCurrent(ctx context.Context, prefix string) (int64, int64, error) {
	var (
		rev sql.NullInt64
		id  int64
	)

	row := d.queryRow(ctx, d.CountCurrentSQL, prefix, false)
	err := row.Scan(&rev, &id)
	return rev.Int64, id, err
}

func (d *Generic) Count(ctx context.Context, prefix string, revision int64) (int64, int64, error) {
	var (
		rev sql.NullInt64
		id  int64
	)

	row := d.queryRow(ctx, d.CountRevisionSQL, prefix, revision, false)
	err := row.Scan(&rev, &id)
	return rev.Int64, id, err
}

func (d *Generic) CurrentRevision(ctx context.Context) (int64, error) {
	var id int64
	row := d.queryRow(ctx, revSQL)
	err := row.Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

func (d *Generic) After(ctx context.Context, prefix string, rev, limit int64) (*sql.Rows, error) {
	sql := d.AfterSQL
	if limit > 0 {
		sql = fmt.Sprintf("%s LIMIT %d", sql, limit)
	}
	return d.query(ctx, sql, prefix, rev)
}

func (d *Generic) Fill(ctx context.Context, revision int64) error {
	_, err := d.execute(ctx, d.FillSQL, revision, fmt.Sprintf("gap-%d", revision), 0, 1, 0, 0, 0, nil, nil)
	return err
}

func (d *Generic) IsFill(key string) bool {
	return strings.HasPrefix(key, "gap-")
}

func (d *Generic) Insert(ctx context.Context, key string, create, delete bool, createRevision, previousRevision int64, ttl int64, value, prevValue []byte) (id int64, err error) {
	if d.TranslateErr != nil {
		defer func() {
			if err != nil {
				err = d.TranslateErr(err)
			}
		}()
	}

	cVal := 0
	dVal := 0
	if create {
		cVal = 1
	}
	if delete {
		dVal = 1
	}

	if d.LastInsertID {
		row, err := d.execute(ctx, d.InsertLastInsertIDSQL, key, cVal, dVal, createRevision, previousRevision, ttl, value, prevValue)
		if err != nil {
			return 0, err
		}
		id, err = row.LastInsertId()
		if err != nil {
			return 0, err
		}
	} else {
		// Drivers without LastInsertID support may conflict on the serial id key when inserting rows,
		// as the ID is reserved at the beginning of the implicit transaction, but does not become
		// visible until the transaction completes, at which point we may have already created a gap fill record.
		// Retry the insert if the driver indicates a retriable insert error, to avoid presenting a spurious
		// duplicate key error to the client.
		wait := strategy.Backoff(backoff.Linear(100 + time.Millisecond))
		for i := uint(0); i < 20; i++ {
			row := d.queryRow(ctx, d.InsertSQL, key, cVal, dVal, createRevision, previousRevision, ttl, value, prevValue)
			err = row.Scan(&id)
			if err != nil && d.InsertRetry != nil && d.InsertRetry(err) {
				wait(i)
				continue
			}
			break
		}
		if err != nil {
			return 0, err
		}
	}

	var jsonData []byte
	resourceName := ""
	namespace := ""
	apigroup := ""
	region := ""
	creationTime := ""

	for resource, tablename := range tableMap {
		if found, remainder := containsAndReturnRemainder(key, resource); found {
			tableName = tablename
			resourceName = remainder
			break
		}
	}

	//如果没匹配到对应的resources，则直接返回，不需要进行后续操作
	if resourceName == "" {
		return id, nil
	}

	if dVal == 1 {

		_, err = d.execute(ctx, q(fmt.Sprintf(d.ResourcesDeleteSQL, tableName), d.param, d.numbered), resourceName)
		if err != nil {
			fmt.Println("delete resources error")
			panic(err)
		}
	} else {

		encodedData := value

		// 解码 Protobuf 数据
		gvk := &schema.GroupVersionKind{} // 替换为实际的 GVK
		obj, _, err := d.protobufSerializer.Decode(encodedData, gvk, nil)
		if err != nil {
			//如果报错如下，则证明数据不需要从protobuf进行解码
			if err.Error() == "provided data does not appear to be a protobuf message, expected prefix [107 56 115 0]" {
				jsonData = value
			} else {
				fmt.Println("decoding：", tableName)
				log.Fatalf("Failed to decode protobuf: %v", err)
			}
		} else {
			// 将解码后的对象转换为 JSON 格式
			jsonData, err = json.MarshalIndent(obj, "", "  ")
			if err != nil {
				log.Fatalf("Failed to marshal JSON: %v", err)
			}
		}

		apigroup, err = extractValue(string(jsonData), "apiVersion")
		if err != nil {
			namespace = "cant-find-apigroup"
		}

		namespace, err = extractValue(string(jsonData), "namespace")
		if err != nil {
			namespace = "cant-find-namespace"
		}

		region, err = extractValue(string(jsonData), "nodeName")
		if err != nil {
			region = "cant-find-region"
		}

		creationTime, err = extractValue(string(jsonData), "creationTimestamp")
		if err != nil {
			creationTime = "cant-find-creationTime"
		}

		// 获取当前时间
		currentTime := time.Now().UTC()

		// 格式化时间
		formattedTime := currentTime.Format("2006-01-02T15:04:05Z")

		// 如果是创建操作
		if cVal == 1 {

			// 执行插入
			_, err = d.execute(ctx, q(fmt.Sprintf(d.ResourcesInsertSQL, tableName), d.param, d.numbered), resourceName, namespace, apigroup, region, jsonData, creationTime, creationTime)
			if err != nil {
				fmt.Println("insert resources error")
				panic(err)
			}

		} else {

			// 执行更新
			_, err = d.execute(ctx, q(fmt.Sprintf(d.ResourcesUpdateSQL, tableName), d.param, d.numbered), namespace, region, jsonData, formattedTime, resourceName)
			if err != nil {
				fmt.Println("update resources error")
				panic(err)
			}
		}

	}

	return id, err
}

func (d *Generic) GetSize(ctx context.Context) (int64, error) {
	if d.GetSizeSQL == "" {
		return 0, errors.New("driver does not support size reporting")
	}
	var size int64
	row := d.queryRow(ctx, d.GetSizeSQL)
	if err := row.Scan(&size); err != nil {
		return 0, err
	}
	return size, nil
}

func (d *Generic) FillRetryDelay(ctx context.Context) {
	time.Sleep(d.FillRetryDuration)
}
