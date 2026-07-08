package handlers

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authSessionResponse struct {
	Username        string `json:"username"`
	Role            string `json:"role"`
	ReadOnly        bool   `json:"read_only"`
	CanMutate       bool   `json:"can_mutate"`
	CanViewSettings bool   `json:"can_view_settings"`
	GuestMessage    string `json:"guest_message,omitempty"`
}

type guestAccessStatusResponse struct {
	Username string `json:"username"`
	Exists   bool   `json:"exists"`
	Enabled  bool   `json:"enabled"`
}

type guestAccessRequest struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Password string `json:"password,omitempty"`
}
