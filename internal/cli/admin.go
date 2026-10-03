package cli

import (
	"errors"
	"os"
	"strconv"

	"github.com/oheco/oheco-broker/sdk/go/remote"
	"github.com/spf13/cobra"
)

func adminCommands(o *rootOptions) *cobra.Command {
	admin := &cobra.Command{Use: "admin", Short: "Administrator-only account and relay management"}
	var tokenFile string
	admin.PersistentFlags().StringVar(&tokenFile, "token-file", "", "Private admin bearer file (otherwise OHECO_BROKER_ADMIN_TOKEN)")
	request := func(cmd *cobra.Command, method, path string, body any) error {
		token := os.Getenv("OHECO_BROKER_ADMIN_TOKEN")
		var err error
		if tokenFile != "" {
			token, err = tokenFromFile(tokenFile)
			if err != nil {
				return err
			}
		}
		if len(token) < 16 {
			return errors.New("administrator token is required")
		}
		client, err := remote.New(remote.Options{URL: o.endpoint(config{}), CAFile: o.ca})
		if err != nil {
			return err
		}
		defer client.Close()
		raw, err := client.Request(method, path, &token, body)
		if err != nil {
			return err
		}
		return printJSON(cmd, raw)
	}
	tenant := &cobra.Command{Use: "tenant", Short: "Tenant administration"}
	var status string
	var tenantLimit, tenantOffset int
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if tenantLimit < 1 || tenantLimit > 1000 || tenantOffset < 0 || tenantOffset > 1000000000 {
			return errors.New("limit must be1..1000 and offset0..1000000000")
		}
		path := "/v1/admin/tenants?limit=" + strconv.Itoa(tenantLimit) + "&offset=" + strconv.Itoa(tenantOffset)
		if status != "" {
			if status != "active" && status != "pending" && status != "disabled" {
				return errors.New("status must be active,pending or disabled")
			}
			path += "&status=" + status
		}
		return request(cmd, "GET", path, nil)
	}}
	list.Flags().StringVar(&status, "status", "", "Optional active/pending/disabled filter")
	list.Flags().IntVar(&tenantLimit, "limit", 100, "Page size1..1000")
	list.Flags().IntVar(&tenantOffset, "offset", 0, "Pagination offset; follow next_offset in response")
	tenant.AddCommand(list)
	tenant.AddCommand(&cobra.Command{Use: "show tenant-id", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return request(cmd, "GET", "/v1/admin/tenants/"+args[0], nil)
	}})
	for _, action := range []string{"approve", "enable", "disable"} {
		action := action
		tenant.AddCommand(&cobra.Command{Use: action + " tenant-id", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			return request(cmd, "POST", "/v1/admin/tenants/"+args[0]+"/"+action, map[string]any{})
		}})
	}
	relay := &cobra.Command{Use: "relay", Short: "Enable or disable a tenant's paid relay capability"}
	for _, action := range []string{"enable", "disable"} {
		action := action
		relay.AddCommand(&cobra.Command{Use: action + " tenant-id", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			return request(cmd, "POST", "/v1/admin/tenants/"+args[0]+"/relay", map[string]any{"enabled": action == "enable"})
		}})
	}
	tenant.AddCommand(relay)
	var password string
	var passwordStdin bool
	reset := &cobra.Command{Use: "reset-password tenant-id", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		pw, err := readPassword(cmd, password, passwordStdin, "Replacement account password")
		if err != nil {
			return err
		}
		return request(cmd, "POST", "/v1/admin/tenants/"+args[0]+"/reset-password", map[string]any{"password": pw})
	}}
	reset.Flags().StringVar(&password, "password", "", "Replacement password (prefer stdin)")
	reset.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read replacement password from stdin")
	tenant.AddCommand(reset)
	var name, email string
	update := &cobra.Command{Use: "update tenant-id", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{}
		if cmd.Flags().Changed("name") {
			body["name"] = name
		}
		if cmd.Flags().Changed("email") {
			body["email"] = email
		}
		if len(body) == 0 {
			return errors.New("choose --name and/or --email")
		}
		return request(cmd, "PATCH", "/v1/admin/tenants/"+args[0], body)
	}}
	update.Flags().StringVar(&name, "name", "", "New tenant name")
	update.Flags().StringVar(&email, "email", "", "New contact email")
	tenant.AddCommand(update)
	admin.AddCommand(tenant)
	registration := &cobra.Command{Use: "registration", Short: "Registration policy"}
	registration.AddCommand(&cobra.Command{Use: "show", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return request(cmd, "GET", "/v1/admin/settings", nil) }})
	registration.AddCommand(&cobra.Command{Use: "set open|approval|closed", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] != "open" && args[0] != "approval" && args[0] != "closed" {
			return errors.New("registration policy must be open, approval or closed")
		}
		return request(cmd, "PATCH", "/v1/admin/settings", map[string]any{"registration_policy": args[0]})
	}})
	registration.AddCommand(&cobra.Command{Use: "relay-default enable|disable", Short: "Set TURN eligibility for newly registered tenants", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] != "enable" && args[0] != "disable" {
			return errors.New("relay default must be enable or disable")
		}
		return request(cmd, "PATCH", "/v1/admin/settings", map[string]any{"registration_relay_enabled": args[0] == "enable"})
	}})
	admin.AddCommand(registration)
	brokers := &cobra.Command{Use: "broker", Short: "Inspect all tenants' brokers"}
	var owner string
	var brokerLimit, brokerOffset int
	brokerList := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if brokerLimit < 1 || brokerLimit > 1000 || brokerOffset < 0 || brokerOffset > 1000000000 {
			return errors.New("limit must be1..1000 and offset0..1000000000")
		}
		path := "/v1/admin/brokers?limit=" + strconv.Itoa(brokerLimit) + "&offset=" + strconv.Itoa(brokerOffset)
		if owner != "" {
			path += "&tenant_id=" + owner
		}
		return request(cmd, "GET", path, nil)
	}}
	brokerList.Flags().StringVar(&owner, "tenant", "", "Tenant UUID filter")
	brokerList.Flags().IntVar(&brokerLimit, "limit", 100, "Page size1..1000")
	brokerList.Flags().IntVar(&brokerOffset, "offset", 0, "Pagination offset; follow next_offset in response")
	brokers.AddCommand(brokerList, &cobra.Command{Use: "show broker-id", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return request(cmd, "GET", "/v1/admin/brokers/"+args[0], nil)
	}})
	admin.AddCommand(brokers)
	var usageTenant, usageBroker string
	usage := &cobra.Command{Use: "usage", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		path := "/v1/admin/usage"
		if usageBroker != "" {
			path += "?broker_id=" + usageBroker
		} else if usageTenant != "" {
			path += "?tenant_id=" + usageTenant
		}
		return request(cmd, "GET", path, nil)
	}}
	usage.Flags().StringVar(&usageTenant, "tenant", "", "Tenant UUID")
	usage.Flags().StringVar(&usageBroker, "broker", "", "Broker UUID")
	admin.AddCommand(usage)
	admin.AddCommand(&cobra.Command{Use: "info", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return request(cmd, "GET", "/v1/admin/info", nil) }})
	return admin
}
