package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
)

type M20260829000001CreateAuthTables struct{}

func (r *M20260829000001CreateAuthTables) Signature() string {
	return "20260829000001_create_auth_tables"
}

func (r *M20260829000001CreateAuthTables) Up() error {
	if !facades.Schema().HasTable("users") {

		if err := facades.Schema().Create("users", func(table schema.Blueprint) {
			table.ID()
			table.String("name")
			table.Boolean("is_active").Default(true)
			table.DateTimeTz("last_seen_at").Nullable()
			table.DateTimeTz("created_at").UseCurrent()
			table.DateTimeTz("updated_at").UseCurrent()
			table.Unique("name")
		}); err != nil {
			return err
		}
	}

	if !facades.Schema().HasTable("trusted_devices") {
		if err := facades.Schema().Create("trusted_devices", func(table schema.Blueprint) {
			table.ID()
			table.UnsignedBigInteger("user_id")

			table.String("token_hash")
			table.String("label")
			table.String("user_agent")
			table.String("last_ip")

			table.String("enrolled_via")
			table.DateTimeTz("last_used_at").UseCurrent()
			table.DateTimeTz("absolute_expires_at")
			table.DateTimeTz("quarantine_until").Nullable()
			table.DateTimeTz("revoked_at").Nullable()
			table.String("revoked_by").Nullable()
			table.DateTimeTz("created_at").UseCurrent()
			table.Unique("token_hash")
			table.Index("user_id")
		}); err != nil {
			return err
		}
	}

	if !facades.Schema().HasTable("enroll_codes") {
		if err := facades.Schema().Create("enroll_codes", func(table schema.Blueprint) {
			table.ID()

			table.String("code_hash")
			table.UnsignedBigInteger("user_id")

			table.String("issued_via")
			table.UnsignedBigInteger("issued_by_device_id").Nullable()
			table.DateTimeTz("expires_at")
			table.DateTimeTz("used_at").Nullable()
			table.String("used_by_ip").Nullable()
			table.DateTimeTz("created_at").UseCurrent()
			table.Unique("code_hash")
		}); err != nil {
			return err
		}
	}

	if !facades.Schema().HasTable("auth_events") {

		if err := facades.Schema().Create("auth_events", func(table schema.Blueprint) {
			table.ID()
			table.String("event")
			table.UnsignedBigInteger("user_id").Nullable()
			table.UnsignedBigInteger("device_id").Nullable()
			table.String("ip")
			table.String("details")
			table.DateTimeTz("occurred_at").UseCurrent()
			table.Index("occurred_at")
		}); err != nil {
			return err
		}
	}

	if !facades.Schema().HasTable("settings") {
		if err := facades.Schema().Create("settings", func(table schema.Blueprint) {
			table.String("key")
			table.String("value")
			table.DateTimeTz("updated_at").UseCurrent()
			table.Primary("key")
		}); err != nil {
			return err
		}
	}

	return nil
}

func (r *M20260829000001CreateAuthTables) Down() error {
	for _, t := range []string{"settings", "auth_events", "enroll_codes", "trusted_devices", "users"} {
		if err := facades.Schema().DropIfExists(t); err != nil {
			return err
		}
	}
	return nil
}
