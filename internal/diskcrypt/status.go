package diskcrypt

type Status struct {
	Encrypted bool   `json:"encrypted"`
	Cipher    string `json:"cipher"`
	KeyBits   int    `json:"key_bits"`
	Slots     int    `json:"slots"`
	Discards  bool   `json:"discards"`
	AESNI     bool   `json:"aes_ni"`

	FirstBootPending bool `json:"first_boot_pending"`

	ChangeRequested bool `json:"change_requested"`

	LastChange   string `json:"last_change"`
	LastChangeAt string `json:"last_change_at"`

	UnlockKeymap string `json:"unlock_keymap"`
}
