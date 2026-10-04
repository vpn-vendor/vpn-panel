package migrations

import (
	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

type M20260927000001ForgetProductIfaces struct{}

func (r *M20260927000001ForgetProductIfaces) Signature() string {
	return "20260927000001_forget_product_ifaces"
}

func (r *M20260927000001ForgetProductIfaces) Up() error {

	names := []any{"wg-vpn0", "ovpn-vpn0", "ifb-vpn0", "ifb-vpn1", "ppp0"}
	_, err := facades.Orm().Query().WhereIn("name", names).Delete(&models.Interface{})
	return err
}

func (r *M20260927000001ForgetProductIfaces) Down() error { return nil }
