package cmd

import (
	"fmt"
	"strings"

	api "cmit/paas/warp/api"

	"github.com/spf13/cobra"
)

func serviceShow() error {
	fmt.Println("Services\n============================================================")
	resp, err := client.GetService(ctx, &api.Empty{})
	if err != nil {
		return err
	}
	for _, s := range resp.Services {
		fmt.Printf("P[%s]: V[%s:%d]\tL[%s]\n\tR[%s:%d]\n------------------------------------------------------------\n",
			s.Key.Protocol.String(), s.Key.Ip, s.Key.Port, s.Val.LocalIp,
			strings.Join(s.Val.RealServerIps, ","), s.Val.RealPort)
	}
	return nil
}

func newServiceCmd() *cobra.Command {
	serviceCmd := &cobra.Command{
		Use: "service",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	showCmd := &cobra.Command{
		Use: "show",
		Run: func(cmd *cobra.Command, args []string) {
			if err := serviceShow(); err != nil {
				exitWithError(err)
			}
		},
	}

	serviceCmd.AddCommand(showCmd)
	return serviceCmd
}
