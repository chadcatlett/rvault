package cmd

import (
	"fmt"
	"rvault/internal/pkg/api"
	"rvault/internal/pkg/kv"
	"strings"

	"k8s.io/klog"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// listCmd represents the listSecrets command
var grepCmd = &cobra.Command{
	Use:   "grep <term> <engine>",
	Short: "Recursively search secrets for a given path",
	Long:  `Recursively search secrets for a given path`,
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag("grep.term", cmd.Flags().Lookup("term"))
		_ = viper.BindPFlag("grep.path", cmd.Flags().Lookup("path"))
		_ = viper.BindPFlag("global.kv_version", cmd.Flags().Lookup("kv-version"))
	},
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		c, err := api.NewClient()
		if err != nil {
			klog.Fatalf("%v", err)
		}
		searchTerm := args[0]
		engine := args[1]
		path := viper.GetString("grep.path")
		concurrency := viper.GetUint32("global.concurrency")
		includePaths := viper.GetStringSlice("global.include_paths")
		excludePaths := viper.GetStringSlice("global.exclude_paths")
		// fmt.Println("searchTerm: ", searchTerm)
		// fmt.Println("engine: ", engine)
		// fmt.Println("path: ", path)
		secrets, err := kv.RGrep(c, engine, path, includePaths, excludePaths, concurrency, searchTerm)
		if err != nil {
			klog.Fatalf("%v", err)
		}
		// meh, err := json.MarshalIndent(secrets, "", " ")
		if err != nil {
			klog.Fatalf("%v", err)
		}
		//fmt.Printf(string(meh))
		// fmt.Printf("Debug: %v\n", secrets)
		// func makePath(a,b string) string {
		// 	newA :=strings.TrimPrefix("/", a)
		// 	newA = strings.TrimSuffix(newA,"/")
		// }

		for k, _ := range secrets {

			fmt.Printf("Found '%s' in %s/%s\n", searchTerm, strings.TrimSuffix(engine, "/"),
				strings.TrimPrefix(k, "/"))
		}

	},
}

func init() {
	grepCmd.Flags().StringP("path", "p", "/", "Path to look for secrets")
	grepCmd.Flags().StringP("kv-version", "k", "", "KV Version")
	rootCmd.AddCommand(grepCmd)
}
