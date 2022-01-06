package fuzzing

import (
	"context"
	"testing"

	"vitess.io/vitess/go/mysql"
	"vitess.io/vitess/go/mysql/fakesqldb"
	"vitess.io/vitess/go/sqltypes"
	"vitess.io/vitess/go/vt/dbconfigs"
	"vitess.io/vitess/go/vt/mysqlctl/fakemysqldaemon"
	"vitess.io/vitess/go/vt/vttablet/tabletmanager"
	"vitess.io/vitess/go/vt/vttablet/tabletservermock"
)

func FuzzTabletManager_ExecuteFetchAsDba(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := context.Background()
		cp := mysql.ConnParams{}
		db := fakesqldb.New(t)
		db.AddQueryPattern(".*", &sqltypes.Result{})
		daemon := fakemysqldaemon.NewFakeMysqlDaemon(db)

		dbName := "dbname"
		tm := &tabletmanager.TabletManager{
			MysqlDaemon:         daemon,
			DBConfigs:           dbconfigs.NewTestDBConfigs(cp, cp, dbName),
			QueryServiceControl: tabletservermock.NewController(),
		}
		_, _ = tm.ExecuteFetchAsDba(ctx, data, dbName, 10, false, false)
	})
}
